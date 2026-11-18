// D2：文件夹打包成 ZIP 下载（GET /api/zip?dir=<目录>&token=<可选目录令牌>）。
//
//   - 只给站主自己用：登录 + 对目录有读权限；或持目录级签名令牌（和 /raw/
//     一样，文件列表接口签发的令牌）；GUEST 目录匿名也可下载（和读权限一致）。
//   - 流式生成（utils/zip.ts，STORE 不压缩），不把 ZIP 放内存里。
//   - 上限：100 个文件 / 200 MB（可用环境变量 ZIP_MAX_FILES / ZIP_MAX_BYTES 调整）。
//     超限返回 413 并说明原因，不返回半截 ZIP。
//   - 这不是文件夹分享：不生成可分享的链接，也不接受 /api/sign 那种
//     针对单个文件的令牌——目录令牌或登录二选一。

import { getBucket } from "@/utils/bucket";
import { getRequestUser, userCanRead, isInternalPath, isSafeKey, FOLDER_MARKER } from "@/utils/auth";
import { verifyToken } from "@/utils/signing";
import { createZipStream } from "@/utils/zip";

const DEFAULT_MAX_FILES = 100;
const DEFAULT_MAX_BYTES = 200 * 1024 * 1024;

function maxFiles(env): number {
  const n = parseInt(env["ZIP_MAX_FILES"] || "", 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_FILES;
}

function maxBytes(env): number {
  const n = parseInt(env["ZIP_MAX_BYTES"] || "", 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_BYTES;
}

export async function onRequestGet(context) {
  return handleZip(context);
}

async function handleZip(context) {
  const request: Request = context.request;
  const url = new URL(request.url);
  const dir = url.searchParams.get("dir") || "";
  const prefix = dir ? (dir.endsWith("/") ? dir : dir + "/") : "";

  if (prefix && (!isSafeKey(prefix) || isInternalPath(prefix))) {
    return new Response("目录无效", { status: 400 });
  }

  const bucket = getBucket(context);
  if (!bucket) return new Response("存储桶未配置", { status: 500 });

  // 认证：目录令牌（文件列表签发的）或登录后的读权限；GUEST 目录匿名可读。
  let allowed = false;
  const token = url.searchParams.get("token") || "";
  if (token && prefix && (await verifyToken(context.env, bucket, token, prefix))) {
    allowed = true;
  }
  if (!allowed) {
    const user = await getRequestUser(context);
    if (userCanRead(user, context.env, prefix)) allowed = true;
  }
  if (!allowed) return new Response("没有访问权限", { status: 401 });

  const limitFiles = maxFiles(context.env);
  const limitBytes = maxBytes(context.env);

  // 递归枚举：超过上限就拒绝，不返回半截 ZIP
  const keys: { key: string; size: number }[] = [];
  let totalBytes = 0;
  let cursor: string | undefined = undefined;
  let overCount = false;
  let overSize = false;
  let complete = false;
  for (let page = 0; page < 20; page++) {
    const list = await bucket.list({ prefix, cursor });
    for (const o of list.objects || []) {
      if (o.key.endsWith("/" + FOLDER_MARKER) || isInternalPath(o.key)) continue;
      keys.push({ key: o.key, size: o.size });
      totalBytes += o.size;
      if (keys.length > limitFiles) {
        overCount = true;
        break;
      }
      if (totalBytes > limitBytes) {
        overSize = true;
        break;
      }
    }
    if (overCount || overSize) break;
    if (!list.truncated) {
      complete = true;
      break;
    }
    cursor = list.cursor;
  }
  if (overCount) {
    return new Response(`文件夹文件过多（超过 ${limitFiles} 个），请分批下载`, { status: 413 });
  }
  if (overSize) {
    return new Response(`文件夹总大小超过 ${Math.round(limitBytes / 1024 / 1024)} MB，请分批下载`, { status: 413 });
  }
  if (!complete) {
    return new Response(`文件夹文件过多（超过 ${limitFiles} 个），请分批下载`, { status: 413 });
  }
  if (keys.length === 0) {
    return new Response("文件夹为空，没有可下载的文件", { status: 400 });
  }

  // 流式生成：逐个取 R2 对象体。对象在 R2 里不可变，列表时的 size 是可信的。
  const stream = createZipStream(
    keys.map(({ key, size }) => ({
      name: prefix ? key.slice(prefix.length) : key,
      size,
      openBody: async () => {
        const object = await bucket.get(key);
        if (!object || !object.body) throw new Error("文件读取失败: " + key);
        return object.body as ReadableStream<Uint8Array>;
      },
    }))
  );

  const folderName = prefix ? prefix.replace(/\/$/, "").split("/").pop() || "folder" : "files";
  const ascii = folderName.replace(/[^\x20-\x7e]/g, "_");
  return new Response(stream, {
    status: 200,
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": `attachment; filename="${ascii}.zip"; filename*=UTF-8''${encodeURIComponent(folderName)}.zip`,
      "Cache-Control": "no-store",
    },
  });
}
