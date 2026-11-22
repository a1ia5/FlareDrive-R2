// D1：公开分享页 /share/{id}。
//
//   GET  /share/{id}             分享页（文件名、大小、有效期、缩略图、下载按钮）
//   GET  /share/{id}?thumb=1    缩略图 PNG（有缩略图的文件才有；不计下载次数）
//   GET  /share/{id}?download=1 下载（计一次下载次数，Content-Disposition: attachment）
//   POST /share/{id}             提交访问密码（表单 POST，密码不进 URL）
//
// v22：分享页不再放原文件预览，?preview=1 已删除——它直接暴露文件字节，
// 且媒体预览不计下载次数，等于绕过 maxDownloads；有缩略图只放缩略图，
// 没有缩略图的什么都不放。
//
// 所有检查（存在 / 过期 / 次数 / 密码）都集中在 utils/shares 的
// checkShareAccess() 里，这里不重复写。密码验证通过后发一个 1 小时
// 有效的 HMAC 令牌 Cookie（复用签名密钥），Cookie 本身不含密码。

import { getBucket } from "@/utils/bucket";
import { applyObjectSecurityHeaders } from "@/utils/response";
import { getClientIP, claimSharePasswordAttempt, clearSharePasswordLimit } from "@/utils/login-limit";
import {
  shareKeyForId,
  checkShareAccess,
  loadShare,
  verifySharePassword,
  issueSharePasswordToken,
  sharePasswordCookieName,
  recordShareDownload,
} from "@/utils/shares";
import { thumbnailKeyForDigest } from "@/utils/thumbnails";

function htmlEscape(s: string): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatSize(size: number): string {
  if (!isFinite(size) || size < 0) return "";
  if (size < 1024) return size + " B";
  if (size < 1024 * 1024) return (size / 1024).toFixed(1) + " KB";
  if (size < 1024 * 1024 * 1024) return (size / (1024 * 1024)).toFixed(1) + " MB";
  return (size / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

function page(title: string, body: string, status = 200): Response {
  const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${htmlEscape(title)} - FlareDrive 分享</title><style>body{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#222}h1{font-size:20px;word-break:break-all}.meta{color:#666;font-size:14px;line-height:1.8}.btn{display:inline-block;margin-top:16px;padding:10px 24px;background:#007bff;color:#fff;text-decoration:none;border-radius:6px}.preview{max-width:100%;margin-top:16px}input{padding:8px;width:100%;box-sizing:border-box;margin:8px 0}button{padding:10px 24px;background:#007bff;color:#fff;border:none;border-radius:6px;cursor:pointer}.error{color:#dc3545}</style></head><body>${body}<p style="margin-top:32px;color:#999;font-size:13px">FlareDrive 分享 · 下载次数按下载请求计数</p></body></html>`;
  return new Response(html, { status, headers: {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    // N7：分享页是 Function 响应，_headers 不适用，这里直接加。
    // X-Frame-Options: DENY——下载按钮不能被套进别人的页面里点；
    // Referrer-Policy: no-referrer——URL 本身就是密钥，不通过 Referer 泄露；
    // CSP：页面只有内联样式、同源图片（缩略图）和同源表单（密码），其它一律不加载。
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'",
  } });
}

function notFoundPage(message: string, status = 404): Response {
  return page("分享不可用", `<h1>分享不可用</h1><p class="meta">${htmlEscape(message)}</p>`, status);
}

function passwordForm(id: string, error = ""): Response {
  return page(
    "请输入访问密码",
    `<h1>该分享需要访问密码</h1>
     ${error ? `<p class="error">${htmlEscape(error)}</p>` : ""}
     <form method="post" action="/share/${htmlEscape(id)}">
       <input type="password" name="password" placeholder="访问密码" autofocus required>
       <button type="submit">查看分享</button>
     </form>`
  );
}

// 流式返回文件字节（复用 /raw/ 的 Range/条件请求处理）
async function streamFile(context, key: string, download: boolean) {
  const request: Request = context.request;
  const bucket = getBucket(context);
  const object = await bucket.get(key, { range: request.headers, onlyIf: request.headers });
  if (!object) return notFoundPage("分享的文件已被删除");

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Last-Modified", new Date(object.uploaded).toUTCString());
  headers.set("Cache-Control", "private, no-cache");
  const filename = key.split("/").pop() || "file";
  const ascii = filename.replace(/[^\x20-\x7e]/g, "_");
  headers.set(
    "Content-Disposition",
    `${download ? "attachment" : "inline"}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`
  );
  // F1：分享流也要加对象安全头（与 /raw/、WebDAV 一致）。危险类型
  // （html/svg/xml/js）会被这里强制改成 attachment 下载，不会在本站
  // 域名下以内联方式执行脚本、读取 localStorage 里的登录凭据。
  // 调用点在 Content-Disposition 之后，所以强制下载能覆盖上面的 inline。
  applyObjectSecurityHeaders(headers, key);
  if (!("body" in object) || !object.body) return new Response(null, { status: 304, headers });
  if (request.headers.get("range") && object.range) {
    const range = object.range;
    headers.set("Content-Range", `bytes ${range.offset}-${range.offset + range.length - 1}/${object.size}`);
    return new Response(object.body, { status: 206, headers });
  }
  return new Response(object.body, { status: 200, headers });
}

export async function onRequestGet(context) {
  const id = ((context.params?.path || []) as string[])[0] || "";
  if (!shareKeyForId(id)) return notFoundPage("分享不存在或已被撤销");

  const bucket = getBucket(context);
  if (!bucket) return notFoundPage("存储桶未配置", 500);

  const check = await checkShareAccess(context.env, bucket, id, context.request);
  if (!check.ok) {
    if (check.status === 401) return passwordForm(id);
    return notFoundPage(check.message, check.status);
  }
  const share = check.share;
  const url = new URL(context.request.url);

  if (url.searchParams.has("download")) {
    await recordShareDownload(bucket, share);
    return streamFile(context, share.key, true);
  }

  // v22：分享页不再放原文件预览。?preview=1 已删除（它直接暴露文件字节，
  // 且媒体预览不计下载次数，等于绕过 maxDownloads）；旧的 ?preview=1
  // 请求会落到下面的落地页渲染，只返回 HTML，不返回文件字节、不计下载。
  const obj = await bucket.head(share.key);
  if (!obj) return notFoundPage("分享的文件已被删除");
  // 缩略图摘要存在文件的 customMetadata.thumbnail 里；没有摘要或摘要
  // 非法时 thumbKey 为 null，落地页什么都不放。
  const thumbKey = thumbnailKeyForDigest(obj.customMetadata?.thumbnail ?? "");

  if (url.searchParams.has("thumb")) {
    if (!thumbKey) return notFoundPage("该文件没有缩略图");
    // 缩略图不计下载次数（它只是 144×144 的预览图，不是文件本身）。
    return streamFile(context, thumbKey, false);
  }

  const type = obj.httpMetadata?.contentType || "application/octet-stream";
  const size = obj.size;

  // 只有有缩略图的文件才放一张缩略图；没有缩略图的什么都不放。
  const preview = thumbKey
    ? `<img class="preview" src="/share/${htmlEscape(id)}?thumb=1" alt="">`
    : "";

  // 分享页是服务端渲染：Worker 的默认时区是 UTC，而管理页在浏览器里按
  // 访客本地时区渲染（站主在东八区），不指定时区会差 8 小时。
  // 固定用 Asia/Shanghai，与管理页显示的时间一致。
  const expiresText = share.expiresAt === null ? "长期有效" : "有效期至 " + new Date(share.expiresAt * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" });
  const limitText = share.maxDownloads === null ? "" : ` · 最多下载 ${share.maxDownloads} 次`;

  return page(
    share.name,
    `<h1>${htmlEscape(share.name)}</h1>
     <p class="meta">${formatSize(size)} · ${htmlEscape(type)}<br>${htmlEscape(expiresText)} · 已下载 ${share.downloads} 次${htmlEscape(limitText)}</p>
     ${preview}
     <p><a class="btn" href="/share/${htmlEscape(id)}?download=1">下载</a></p>`
  );
}

export async function onRequestPost(context) {
  const id = ((context.params?.path || []) as string[])[0] || "";
  if (!shareKeyForId(id)) return notFoundPage("分享不存在或已被撤销");

  const bucket = getBucket(context);
  if (!bucket) return notFoundPage("存储桶未配置", 500);

  const share = await loadShare(bucket, id);
  if (!share) return notFoundPage("分享不存在或已被撤销");
  if (!share.password) {
    return new Response(null, { status: 303, headers: { Location: "/share/" + id } });
  }

  let password = "";
  try {
    const form = await context.request.formData();
    password = String(form.get("password") || "");
  } catch {
    return passwordForm(id, "提交失败，请重试");
  }
  // F6：分享密码也限流（与登录限流同一套 R2 存储和阈值，键 share_limit:<id>:<IP>）。
  // 拿到链接的人不能无限试密码；被封禁时不再校验密码（也不透露密码是否正确）。
  // v28（R3-2）：先原子认领一次尝试，失败不用再另记（已记过）；通过后要清零。
  const clientIP = getClientIP(context.request);
  const limit = await claimSharePasswordAttempt(bucket, id, clientIP);
  if (!limit.allowed) {
    return passwordForm(id, `密码尝试次数过多，请在 ${Math.ceil((limit.remainingBanTime || 0) / 60)} 分钟后重试`);
  }
  if (!(await verifySharePassword(share, password))) {
    // remainingAttempts === 0 说明这次就是第 5 次，封禁已生效。
    if (limit.remainingAttempts === 0) {
      return passwordForm(id, `密码尝试次数过多，请在 ${Math.ceil((limit.remainingBanTime || 0) / 60)} 分钟后重试`);
    }
    return passwordForm(id, "密码错误");
  }

  await clearSharePasswordLimit(bucket, id, clientIP);
  const token = await issueSharePasswordToken(context.env, bucket, id);
  const secure = new URL(context.request.url).protocol === "https:";
  const cookie =
    `${sharePasswordCookieName(id)}=${encodeURIComponent(token)}; HttpOnly; Path=/share/${id}; Max-Age=3600; SameSite=Lax` +
    (secure ? "; Secure" : "");
  return new Response(null, {
    status: 303,
    headers: { Location: "/share/" + id, "Set-Cookie": cookie },
  });
}
