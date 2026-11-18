import { notFound, parseBucketPath } from "@/utils/bucket";
import { getRequestUser, userCanRead, isInternalPath, isThumbnailKey, isSafeKey } from "@/utils/auth";
import { verifyToken } from "@/utils/signing";
import { applyObjectSecurityHeaders, formatContentRange } from "@/utils/response";

// 读取权限（满足任意一条即可）：
//   1. 路径在 GUEST 目录下 —— 公开文件，直链即可访问；
//   2. URL 带有效的签名令牌 ?token=...（分享链接、应用内的缩略图/预览/全景图）；
//   3. 请求带 Authorization: Basic 且账户对该路径有读权限（curl、脚本）。
// _$flaredrive$/ 下除缩略图外的内容永远不可读。
async function canRead(context, bucket, path: string): Promise<boolean> {
  // L1：路径本身必须安全（拒绝 ".."、"."、空段等），否则 "a/../b" 会让
  // startsWith 前缀判断和用户看到的目录结构对不上。
  if (!isSafeKey(path)) return false;
  const internal = isInternalPath(path);
  if (internal && !isThumbnailKey(path)) return false;

  if (!internal && userCanRead(null, context.env, path)) return true;

  const token = new URL(context.request.url).searchParams.get("token");
  if (token && (await verifyToken(context.env, bucket, token, path))) return true;

  const user = await getRequestUser(context);
  if (!user) return false;
  // 缩略图按内容摘要命名，任何已登录用户都可以读
  return internal ? true : userCanRead(user, context.env, path);
}

async function handle(context, headOnly: boolean) {
  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return notFound();

  if (!(await canRead(context, bucket, path))) {
    // 统一返回 404，不区分"没有权限"和"文件不存在"，避免被用来探测文件名。
    // 不带 WWW-Authenticate，避免浏览器弹出原生登录框并缓存凭据。
    return notFound();
  }

  const request: Request = context.request;

  const object = headOnly
    ? await bucket.head(path)
    : await bucket.get(path, { range: request.headers, onlyIf: request.headers });
  if (!object) return notFound();

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Last-Modified", new Date(object.uploaded).toUTCString());

  // 带签名的 URL 等同于凭据，只允许浏览器自己缓存，不让中间缓存保存
  if (isThumbnailKey(path)) headers.set("Cache-Control", "private, max-age=31536000, immutable");
  else headers.set("Cache-Control", "private, no-cache");

  applyObjectSecurityHeaders(headers, path);

  if (headOnly) {
    headers.set("Content-Length", String(object.size));
    return new Response(null, { status: 200, headers });
  }

  // onlyIf 条件未通过（例如 If-None-Match 命中）时 R2 返回没有 body 的对象
  if (!("body" in object) || !object.body) {
    return new Response(null, { status: 304, headers });
  }

  if (request.headers.get("range") && object.range) {
    headers.set("Content-Range", formatContentRange(object.range, object.size));
    return new Response(object.body, { headers, status: 206 });
  }

  return new Response(object.body, { headers, status: 200 });
}

export async function onRequestGet(context) {
  return handle(context, false);
}

export async function onRequestHead(context) {
  return handle(context, true);
}
