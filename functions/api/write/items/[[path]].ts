import { notFound, parseBucketPath } from "@/utils/bucket";
import { get_auth_status, checkPathPermission, isInternalPath, isThumbnailKey, isSafeKey } from "@/utils/auth";
import { deleteUnreferencedThumbnails } from "@/utils/thumbnails";
import { deleteSharesForKeys, rebindSharesEtag } from "@/utils/shares";
import { rawEtagOf } from "@/utils/etag";
import { pickContentType } from "@/utils/response";
import {isCrossOriginRequest, crossOriginRejectedResponse} from "@/utils/csrf";

function unauthorizedResponse() {
  // 不设置 WWW-Authenticate 头：一是避免弹出浏览器原生登录框，
  // 二是避免浏览器缓存 Basic 凭据后被跨站请求利用（见 utils/csrf.ts 的说明）
  return new Response("没有操作权限", {
    status: 401,
    headers: { "Content-Type": "text/plain" },
  });
}

// L10：路径解码失败（BadPathError，status 400）转成 400 响应；其他错误原样抛出
async function withBadPath(fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (e: any) {
    if (e?.status === 400) return new Response("路径无效", { status: 400 });
    throw e;
  }
}

export async function onRequestPostCreateMultipart(context) {
  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return notFound();

  const request: Request = context.request;

  // N6：分片上传的冲突以前只在 complete 时才查（传完整文件才发现撞名）；
  // 建分片的 POST 本来就带 If-None-Match: *（客户端 multipartUpload 把
  // 调用方传的 headers 原样带上），这里先 head 一下，撞了直接 412，
  // 省得传完所有分片才失败。complete 处的检查保留（create 与 complete
  // 之间仍有竞态窗口，complete 是最后一道关）。
  if ((request.headers.get("if-none-match") || "").trim() === "*") {
    const existing = await bucket.head(path);
    if (existing) {
      return new Response(JSON.stringify({ error: "目标文件已存在" }), {
        status: 412,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  const customMetadata: Record<string, string> = {};
  const thumbnailHeader = request.headers.get("fd-thumbnail");
  if (thumbnailHeader && /^[0-9a-f]{40}$/.test(thumbnailHeader))
    customMetadata.thumbnail = thumbnailHeader;

  const multipartUpload = await bucket.createMultipartUpload(path, {
    httpMetadata: {
      contentType: pickContentType(request.headers.get("content-type"), path),
    },
    customMetadata,
  });

  return new Response(
    JSON.stringify({
      key: multipartUpload.key,
      uploadId: multipartUpload.uploadId,
    })
  );
}

export async function onRequestPostCompleteMultipart(context) {
  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return notFound();

  const request: Request = context.request;
  const url = new URL(request.url);
  const uploadId = new URLSearchParams(url.search).get("uploadId");
  const multipartUpload = await bucket.resumeMultipartUpload(path, uploadId);

  const completeBody: { parts: Array<any> } = await request.json();

  // F3：分片完成没有条件写入（R2 的 complete 不支持 onlyIf）。客户端发
  // If-None-Match: * 时，先查目标是否已存在；已存在则中止分片上传并返回
  // 412，拒绝覆盖（best effort，仍有 head 与 complete 之间的竞态窗口，
  // 但比直接覆盖好；单 PUT 走 onlyIf，是严格的）。
  if ((request.headers.get("if-none-match") || "").trim() === "*") {
    const existing = await bucket.head(path);
    if (existing) {
      try {
        await multipartUpload.abort();
      } catch {
        // 中止失败不影响本次 412（孤儿分片由 R2 侧清理）
      }
      return new Response(JSON.stringify({ error: "目标文件已存在" }), {
        status: 412,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  try {
    const object = await multipartUpload.complete(completeBody.parts);
    return new Response(null, {
      headers: { etag: object.httpEtag },
    });
  } catch (error: any) {
    return new Response(error.message, { status: 400 });
  }
}

export async function onRequestPostFixMetadata(context) {
  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return notFound();

  const existing = await bucket.get(path);
  if (!existing) {
    return new Response(JSON.stringify({ error: "文件不存在" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  const body: { thumbnail?: string; contentType?: string } = await context.request
    .json()
    .catch(() => ({}));

  const customMetadata: Record<string, string> = { ...(existing.customMetadata || {}) };
  if (typeof body.thumbnail === "string" && /^[0-9a-f]{40}$/.test(body.thumbnail))
    customMetadata.thumbnail = body.thumbnail;

  const contentType = body.contentType || existing.httpMetadata?.contentType;

  // 这是一次 R2 内部的读回写操作（get 之后立刻 put 回同一个 key），
  // 文件本体完全不经过发起请求的浏览器，不需要客户端重新上传整份文件——
  // 对于修复大视频文件缺失的 content-type / 重新生成缩略图这种场景，
  // 比让前端把整份原始视频再上传一遍要高效得多。
  //
  // R3-4：put 带条件 onlyIf: { etagMatches: <get 到的原始 etag> }——get 与 put
  // 之间文件被别人重新上传时 put 返回 null、不写入，不会拿旧内容覆盖新上传
  // （丢失更新）。这里必须用 existing.etag（原始值），不是 httpEtag：R2 条件
  // 参数不认带引号的写法，会直接抛异常（见 utils/etag.ts）。
  const oldEtag = rawEtagOf(existing);
  const obj = await bucket.put(path, existing.body, {
    customMetadata,
    httpMetadata: contentType ? { contentType } : undefined,
    onlyIf: { etagMatches: oldEtag },
  });
  if (!obj) {
    return new Response(JSON.stringify({ error: "文件在处理期间被修改，请重试" }), {
      status: 412,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 重写后 etag 可能换了格式（分片上传的 >100 MB 文件是 <md5>-<N>，单 PUT 重写后
  // 是 <md5>），而分享绑定的是 etag——不改绑的话，这个文件上所有分享都会变成
  // "分享的文件已被替换"。内容没变（条件写入已保证写的就是刚读到的那份），
  // 把绑定旧 etag 的分享改绑到新 etag。改绑失败不影响本次请求（文件已写好），
  // 但会在返回里标出来。
  let sharesRebound = 0;
  let sharesRebindFailed = 0;
  try {
    const r = await rebindSharesEtag(bucket, path, oldEtag, rawEtagOf(obj));
    sharesRebound = r.rebound;
    sharesRebindFailed = r.failed;
  } catch (error) {
    sharesRebindFailed = 1;
    console.error("[shares] 改绑分享 etag 失败：", error);
  }

  const { key, size, uploaded } = obj;
  return new Response(JSON.stringify({ key, size, uploaded, customMetadata, sharesRebound, sharesRebindFailed }), {
    headers: { "Content-Type": "application/json" },
  });
}

export async function onRequestPost(context) {
  // 修复：此前 POST（创建分片上传 / 完成分片上传）完全没有做权限校验，
  // 任何人都可以不登录直接写入任意路径（配合 PUT 分片上传即可绕过认证）。
  if (isCrossOriginRequest(context)) return crossOriginRejectedResponse();
  if (!(await get_auth_status(context))) return unauthorizedResponse();

  const url = new URL(context.request.url);
  const searchParams = new URLSearchParams(url.search);

  if (searchParams.has("uploads")) {
    return withBadPath(() => onRequestPostCreateMultipart(context));
  }

  if (searchParams.has("uploadId")) {
    return withBadPath(() => onRequestPostCompleteMultipart(context));
  }

  if (searchParams.has("fixMetadata")) {
    return withBadPath(() => onRequestPostFixMetadata(context));
  }

  return new Response("Method not allowed", { status: 405 });
}

export async function onRequestPutMultipart(context) {
  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return notFound();

  const request: Request = context.request;
  const url = new URL(request.url);

  const uploadId = new URLSearchParams(url.search).get("uploadId");
  const multipartUpload = await bucket.resumeMultipartUpload(path, uploadId);

  const partNumber = parseInt(
    new URLSearchParams(url.search).get("partNumber")
  );
  const uploadedPart = await multipartUpload.uploadPart(
    partNumber,
    request.body
  );

  return new Response(null, {
    headers: {
      "Content-Type": "application/json",
      etag: uploadedPart.etag,
    },
  });
}

export async function onRequestPut(context) {
  if (isCrossOriginRequest(context)) return crossOriginRejectedResponse();
  if(!(await get_auth_status(context))){
    return unauthorizedResponse();
   }
  const url = new URL(context.request.url);

  if (new URLSearchParams(url.search).has("uploadId")) {
    return withBadPath(() => onRequestPutMultipart(context));
  }

  let bucket, path: string;
  try {
    [bucket, path] = parseBucketPath(context);
  } catch (e: any) {
    // L10：路径解码失败返回 400，而不是 500
    if (e?.status === 400) return new Response("路径无效", { status: 400 });
    throw e;
  }
  if (!bucket) return notFound();

  const request: Request = context.request;

  let content = request.body;
  const customMetadata: Record<string, string> = {};
  // 之前这里完全没有设置 httpMetadata，导致所有走普通 PUT（非分片）上传的文件
  // 在 R2 里都没有存储 content-type——只有超过分片阈值、走 multipart 上传的
  // 大文件才会被正确设置。列表接口读到 httpMetadata.contentType 为 undefined 时
  // 前端只能把文件当成通用的 'application/octet-stream'，导致缩略图/预览图标
  // 完全无法显示，即使 customMetadata.thumbnail 本身是有效的。
  let contentType: string | undefined = pickContentType(request.headers.get("content-type"), path);

  if (request.headers.has("x-amz-copy-source")) {
    let sourceName: string;
    try {
      sourceName = decodeURIComponent(request.headers.get("x-amz-copy-source"));
    } catch {
      return new Response("无效的复制源", { status: 400 });
    }
    // 修复：此前复制源完全不做权限检查，只要对目标目录有写权限，
    // 就能把任意路径（其他用户的目录、内部文件）的内容复制到自己目录里读出来。
    const sourceReadable =
      isSafeKey(sourceName) &&
      (isInternalPath(sourceName)
        ? isThumbnailKey(sourceName)
        : await checkPathPermission(context, sourceName, false));
    if (!sourceReadable) return unauthorizedResponse();

    const source = await bucket.get(sourceName);
    if (!source) return new Response("复制源不存在", { status: 404 });
    content = source.body;
    if (source.customMetadata?.thumbnail)
      customMetadata.thumbnail = source.customMetadata.thumbnail;
    // 复制/移动场景下，前端发出的 Content-Type 请求头固定是占位值
    // "application/octet-stream"，并不代表源文件的真实类型；这里改为沿用
    // 源对象已经存储的 content-type，避免复制/移动后类型被错误覆盖成占位值。
    contentType = source.httpMetadata?.contentType || contentType;
  }

  const thumbnailHeader = request.headers.get("fd-thumbnail");
  if (thumbnailHeader && /^[0-9a-f]{40}$/.test(thumbnailHeader))
    customMetadata.thumbnail = thumbnailHeader;

  // F3：服务端撞名保护。客户端发 If-None-Match: * 时，只有目标不存在才写入；
  // 已存在则 bucket.put 返回 null，这里返回 412，拒绝静默覆盖。
  // （不发该头时保持原来的覆盖行为，向后兼容；复制/粘贴也走这条 PUT。）
  const putOptions: Record<string, any> = {
    customMetadata,
    httpMetadata: contentType ? { contentType } : undefined,
  };
  if ((request.headers.get("if-none-match") || "").trim() === "*") {
    putOptions.onlyIf = { etagDoesNotMatch: "*" };
  }
  const obj = await bucket.put(path, content, putOptions);
  if (!obj) {
    return new Response(JSON.stringify({ error: "目标文件已存在" }), {
      status: 412,
      headers: { "Content-Type": "application/json" },
    });
  }
  const { key, size, uploaded } = obj;
  return new Response(JSON.stringify({ key, size, uploaded }), {
    headers: { "Content-Type": "application/json" },
  });
}

export async function onRequestHead(context) {
  // HEAD请求用于检查写入权限，不实际执行操作
  if(!(await get_auth_status(context))){
    // 不设置WWW-Authenticate头，避免弹出浏览器登录框
    return new Response("没有操作权限", {
        status: 403, // 使用403而不是401，避免触发浏览器认证
        headers: {
          "Content-Type": "text/plain"
        },
    });
   }

  // 如果有权限，返回200状态码
  return new Response(null, { status: 200 });
}

export async function onRequestDelete(context) {
  if (isCrossOriginRequest(context)) return crossOriginRejectedResponse();
  if(!(await get_auth_status(context))){
    return unauthorizedResponse();
   }
  let bucket, path: string;
  try {
    [bucket, path] = parseBucketPath(context);
  } catch (e: any) {
    // L10：路径解码失败返回 400，而不是 500
    if (e?.status === 400) return new Response("路径无效", { status: 400 });
    throw e;
  }
  if (!bucket) return notFound();

  // N1：先读原文件的缩略图摘要（删完就读不到了）。删缩略图是尽力而为：
  // 摘要被其他文件（重命名/复制/重复上传）共享时不删，清理失败也不
  // 影响本次删除的 204。
  let digest: string | null = null;
  try {
    const obj = await bucket.head(path);
    digest = obj?.customMetadata?.thumbnail ?? null;
  } catch {
    // 没有元数据就按无缩略图处理。
  }

  await bucket.delete(path);
  if (digest) await deleteUnreferencedThumbnails(bucket, [digest], [path]);
  // N8：删文件时撤销指向它的分享（孤儿记录不留；链接本身已因 etag 比对失效）。
  await deleteSharesForKeys(bucket, [path]);
  return new Response(null, { status: 204 });
}
