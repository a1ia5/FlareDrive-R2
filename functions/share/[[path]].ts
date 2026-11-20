// D1：公开分享页 /share/{id}。
//
//   GET  /share/{id}             分享页（文件名、大小、有效期、预览、下载按钮）
//   GET  /share/{id}?preview=1  预览用的文件字节流（不计下载次数）
//   GET  /share/{id}?download=1 下载（计一次下载次数，Content-Disposition: attachment）
//   POST /share/{id}             提交访问密码（表单 POST，密码不进 URL）
//
// 所有检查（存在 / 过期 / 次数 / 密码）都集中在 utils/shares 的
// checkShareAccess() 里，这里不重复写。密码验证通过后发一个 1 小时
// 有效的 HMAC 令牌 Cookie（复用签名密钥），Cookie 本身不含密码。

import { getBucket } from "@/utils/bucket";
import { applyObjectSecurityHeaders } from "@/utils/response";
import {
  shareKeyForId,
  checkShareAccess,
  loadShare,
  verifySharePassword,
  issueSharePasswordToken,
  sharePasswordCookieName,
  recordShareDownload,
} from "@/utils/shares";

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
  const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${htmlEscape(title)} - FlareDrive 分享</title><style>body{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#222}h1{font-size:20px;word-break:break-all}.meta{color:#666;font-size:14px;line-height:1.8}.btn{display:inline-block;margin-top:16px;padding:10px 24px;background:#007bff;color:#fff;text-decoration:none;border-radius:6px}.preview{max-width:100%;margin-top:16px}input{padding:8px;width:100%;box-sizing:border-box;margin:8px 0}button{padding:10px 24px;background:#007bff;color:#fff;border:none;border-radius:6px;cursor:pointer}.error{color:#dc3545}</style></head><body>${body}<p style="margin-top:32px;color:#999;font-size:13px">FlareDrive 分享 · 下载次数按下载请求计数，预览不计入</p></body></html>`;
  return new Response(html, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
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
  if (url.searchParams.has("preview")) {
    return streamFile(context, share.key, false);
  }

  const obj = await bucket.head(share.key);
  if (!obj) return notFoundPage("分享的文件已被删除");
  const type = obj.httpMetadata?.contentType || "application/octet-stream";
  const size = obj.size;

  let preview = "";
  if (type.startsWith("image/")) {
    preview = `<img class="preview" src="/share/${htmlEscape(id)}?preview=1" alt="">`;
  } else if (type.startsWith("video/")) {
    preview = `<video class="preview" src="/share/${htmlEscape(id)}?preview=1" controls preload="metadata"></video>`;
  } else if (type.startsWith("audio/")) {
    preview = `<audio class="preview" src="/share/${htmlEscape(id)}?preview=1" controls preload="metadata"></audio>`;
  }

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
  if (!(await verifySharePassword(share, password))) {
    return passwordForm(id, "密码错误");
  }

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
