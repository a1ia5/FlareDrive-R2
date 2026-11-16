// WebDAV 接口：/dav/<path>
//
// 沿用网盘本身的约定：
//   - 目录用空对象 "<目录>/_$folder$" 标记（没有标记但下面有对象的前缀也算目录）；
//   - 权限和网页端完全一致（utils/auth.ts），必须用账户登录，不提供匿名访问；
//   - _$flaredrive$/ 内部目录和 _$folder$ 标记对客户端不可见。
//
// R2 没有原生的移动/重命名，MOVE/COPY 是"逐个复制，全部成功后再删除源"，
// 不是原子操作；单个请求能处理的对象数受 Workers 子请求数限制。

import { getBucket, parseBucketPath } from "@/utils/bucket";
import {
  getRequestUser,
  userCanRead,
  userCanWrite,
  userCanTraverse,
  isSafeKey,
  isInternalPath,
  FOLDER_MARKER,
  UserInfo,
} from "@/utils/auth";
import { isCrossOriginRequest, crossOriginRejectedResponse } from "@/utils/csrf";
import { applyObjectSecurityHeaders, formatContentRange, pickContentType } from "@/utils/response";
import { encodeKeyForUrl } from "@/utils/signing";

const DAV_BASE = "/dav/";
const ALLOW = "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK";
const WRITE_METHODS = new Set(["PUT", "DELETE", "MKCOL", "COPY", "MOVE", "PROPPATCH", "LOCK", "UNLOCK"]);
const MAX_BUFFERED_UPLOAD = 64 * 1024 * 1024;

type Resource =
  | { kind: "none" }
  | { kind: "file"; object: any }
  | { kind: "dir" };

function davHeaders(extra: Record<string, string> = {}): Headers {
  return new Headers({ DAV: "1, 2", "MS-Author-Via": "DAV", ...extra });
}

function text(status: number, body = "", extra: Record<string, string> = {}): Response {
  return new Response(body || null, { status, headers: davHeaders(extra) });
}

function unauthorized(): Response {
  // WebDAV 客户端必须收到 Basic 质询才会发送凭据。质询只出现在 /dav/ 下，
  // 写操作另有 Origin 校验（utils/csrf.ts），浏览器缓存凭据后也无法被跨站利用。
  return text(401, "需要登录", { "WWW-Authenticate": 'Basic realm="FlareDrive WebDAV", charset="UTF-8"' });
}

function xmlEscape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function hrefFor(path: string, isDir: boolean): string {
  if (!path) return DAV_BASE;
  return DAV_BASE + encodeKeyForUrl(path) + (isDir ? "/" : "");
}

function hasMarkerSegment(path: string): boolean {
  return path.split("/").includes(FOLDER_MARKER);
}

async function resolve(bucket, path: string, wantDir: boolean): Promise<Resource> {
  if (!path) return { kind: "dir" };
  if (!wantDir) {
    const object = await bucket.head(path);
    if (object) return { kind: "file", object };
  }
  const list = await bucket.list({ prefix: path + "/", limit: 1 });
  if (list.objects.length > 0 || (list.delimitedPrefixes || []).length > 0) return { kind: "dir" };
  return { kind: "none" };
}

async function listAllKeys(bucket, prefix: string): Promise<string[]> {
  const keys: string[] = [];
  let cursor: string | undefined = undefined;
  for (;;) {
    const list = await bucket.list({ prefix, cursor });
    for (const o of list.objects) keys.push(o.key);
    if (!list.truncated) break;
    cursor = list.cursor;
  }
  return keys;
}

async function deleteKeys(bucket, keys: string[]): Promise<void> {
  for (let i = 0; i < keys.length; i += 1000) {
    await bucket.delete(keys.slice(i, i + 1000));
  }
}

async function copyObject(bucket, from: string, to: string): Promise<boolean> {
  const source = await bucket.get(from);
  if (!source) return false;
  await bucket.put(to, source.body, {
    httpMetadata: source.httpMetadata,
    customMetadata: source.customMetadata,
  });
  return true;
}

// ---------------------------------------------------------------------------
// PROPFIND
// ---------------------------------------------------------------------------

function propResponse(href: string, props: string): string {
  return `<D:response><D:href>${xmlEscape(href)}</D:href><D:propstat><D:prop>${props}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`;
}

function dirProps(path: string): string {
  const name = path.split("/").pop() || "";
  return (
    `<D:displayname>${xmlEscape(name)}</D:displayname>` +
    `<D:resourcetype><D:collection/></D:resourcetype>` +
    `<D:getlastmodified>${new Date().toUTCString()}</D:getlastmodified>`
  );
}

function fileProps(object: any): string {
  const name = object.key.split("/").pop() || "";
  const type = object.httpMetadata?.contentType || "application/octet-stream";
  const uploaded = new Date(object.uploaded);
  return (
    `<D:displayname>${xmlEscape(name)}</D:displayname>` +
    `<D:resourcetype/>` +
    `<D:getcontentlength>${object.size}</D:getcontentlength>` +
    `<D:getlastmodified>${uploaded.toUTCString()}</D:getlastmodified>` +
    `<D:creationdate>${uploaded.toISOString()}</D:creationdate>` +
    `<D:getetag>${xmlEscape(object.httpEtag)}</D:getetag>` +
    `<D:getcontenttype>${xmlEscape(type)}</D:getcontenttype>`
  );
}

async function propfind(context, bucket, user: UserInfo, path: string, wantDir: boolean): Promise<Response> {
  const env = context.env;
  const res = await resolve(bucket, path, wantDir);
  if (res.kind === "none") return text(404, "Not found");

  const parts: string[] = [];

  if (res.kind === "file") {
    if (!userCanRead(user, env, path)) return text(403, "没有访问权限");
    parts.push(propResponse(hrefFor(path, false), fileProps(res.object)));
  } else {
    const prefix = path ? path + "/" : "";
    if (prefix && !userCanTraverse(user, env, prefix)) return text(403, "没有访问权限");
    parts.push(propResponse(hrefFor(path, true), dirProps(path)));

    const depth = context.request.headers.get("Depth");
    if (depth !== "0") {
      // Depth: infinity 也按 1 处理
      let cursor: string | undefined = undefined;
      for (;;) {
        const list = await bucket.list({ prefix, delimiter: "/", cursor, include: ["httpMetadata"] });
        for (const folder of list.delimitedPrefixes || []) {
          if (isInternalPath(folder) || !userCanTraverse(user, env, folder)) continue;
          const p = folder.replace(/\/$/, "");
          parts.push(propResponse(hrefFor(p, true), dirProps(p)));
        }
        for (const object of list.objects) {
          const name = object.key.slice(prefix.length);
          if (name === FOLDER_MARKER || !name) continue;
          if (!userCanRead(user, env, object.key)) continue;
          parts.push(propResponse(hrefFor(object.key, false), fileProps(object)));
        }
        if (!list.truncated) break;
        cursor = list.cursor;
      }
    }
  }

  const xml = `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">${parts.join("")}</D:multistatus>`;
  return new Response(xml, {
    status: 207,
    headers: davHeaders({ "Content-Type": 'application/xml; charset="utf-8"' }),
  });
}

// ---------------------------------------------------------------------------
// GET / HEAD / PUT / DELETE / MKCOL
// ---------------------------------------------------------------------------

async function getFile(context, bucket, user: UserInfo, path: string, headOnly: boolean): Promise<Response> {
  if (!path) return text(headOnly ? 200 : 405, "", { Allow: ALLOW });
  if (!userCanRead(user, context.env, path)) {
    // 可能是一个允许"路过"的目录
    return text(userCanTraverse(user, context.env, path + "/") ? 405 : 403, "", { Allow: ALLOW });
  }

  const request: Request = context.request;
  const object = headOnly
    ? await bucket.head(path)
    : await bucket.get(path, { range: request.headers, onlyIf: request.headers });
  if (!object) {
    const res = await resolve(bucket, path, true);
    return res.kind === "dir" ? text(405, "", { Allow: ALLOW }) : text(404, "Not found");
  }

  const headers = davHeaders();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Last-Modified", new Date(object.uploaded).toUTCString());
  headers.set("Cache-Control", "private, no-cache");
  applyObjectSecurityHeaders(headers, path);

  if (headOnly) {
    headers.set("Content-Length", String(object.size));
    return new Response(null, { status: 200, headers });
  }
  if (!("body" in object) || !object.body) return new Response(null, { status: 304, headers });
  if (request.headers.get("range") && object.range) {
    headers.set("Content-Range", formatContentRange(object.range, object.size));
    return new Response(object.body, { status: 206, headers });
  }
  return new Response(object.body, { status: 200, headers });
}

async function putFile(context, bucket, user: UserInfo, path: string, wantDir: boolean): Promise<Response> {
  if (!path || wantDir) return text(405, "不能对目录执行 PUT", { Allow: ALLOW });
  if (!userCanWrite(user, context.env, path)) return text(403, "没有写入权限");

  const dir = await bucket.list({ prefix: path + "/", limit: 1 });
  if (dir.objects.length > 0) return text(405, "同名目录已存在");

  const request: Request = context.request;
  const existed = !!(await bucket.head(path));

  // R2 的流式写入需要事先知道长度；没有 Content-Length（分块传输）时只能先读进内存
  let body: any = request.body;
  const length = request.headers.get("Content-Length");
  if (length === null) {
    const buffered = await request.arrayBuffer();
    if (buffered.byteLength > MAX_BUFFERED_UPLOAD) return text(413, "文件过大，请使用带 Content-Length 的上传");
    body = buffered;
  } else if (length === "0" || !body) {
    body = new Uint8Array(0);
  }

  const contentType = pickContentType(request.headers.get("Content-Type"), path);
  await bucket.put(path, body, { httpMetadata: contentType ? { contentType } : undefined });
  return text(existed ? 204 : 201);
}

async function deleteResource(context, bucket, user: UserInfo, path: string, wantDir: boolean): Promise<Response> {
  if (!path) return text(403, "不能删除根目录");
  const res = await resolve(bucket, path, wantDir);
  if (res.kind === "none") return text(404, "Not found");

  if (res.kind === "file") {
    if (!userCanWrite(user, context.env, path)) return text(403, "没有写入权限");
    await bucket.delete(path);
    return text(204);
  }

  const prefix = path + "/";
  if (!userCanWrite(user, context.env, prefix)) return text(403, "没有写入权限");
  await deleteKeys(bucket, await listAllKeys(bucket, prefix));
  return text(204);
}

async function mkcol(context, bucket, user: UserInfo, path: string): Promise<Response> {
  if (!path) return text(405, "根目录已存在", { Allow: ALLOW });
  const request: Request = context.request;
  if (request.body && (await request.arrayBuffer()).byteLength > 0) return text(415, "MKCOL 不支持请求体");

  const marker = `${path}/${FOLDER_MARKER}`;
  if (!userCanWrite(user, context.env, marker)) return text(403, "没有写入权限");

  const existing = await resolve(bucket, path, false);
  if (existing.kind !== "none") return text(405, "同名文件或目录已存在", { Allow: ALLOW });

  const parent = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
  if (parent && (await resolve(bucket, parent, true)).kind !== "dir") return text(409, "上级目录不存在");

  await bucket.put(marker, new Uint8Array(0));
  return text(201);
}

// ---------------------------------------------------------------------------
// COPY / MOVE
// ---------------------------------------------------------------------------

function parseDestination(context): { path: string; wantDir: boolean } | null {
  const header = context.request.headers.get("Destination");
  if (!header) return null;
  const reqUrl = new URL(context.request.url);
  let url: URL;
  try {
    url = new URL(header, reqUrl);
  } catch {
    return null;
  }
  if (url.host !== reqUrl.host) return null;
  if (!url.pathname.startsWith(DAV_BASE)) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(url.pathname.slice(DAV_BASE.length));
  } catch {
    return null;
  }
  const wantDir = decoded.endsWith("/");
  const path = decoded.replace(/\/+$/, "");
  if (!path || !isSafeKey(path) || isInternalPath(path) || hasMarkerSegment(path)) return null;
  return { path, wantDir };
}

async function copyOrMove(context, bucket, user: UserInfo, path: string, wantDir: boolean, move: boolean): Promise<Response> {
  const env = context.env;
  if (!path) return text(403, "不能复制或移动根目录");

  const dest = parseDestination(context);
  if (!dest) return text(400, "Destination 无效");
  const to = dest.path;
  if (to === path) return text(403, "源和目标相同");

  const src = await resolve(bucket, path, wantDir);
  if (src.kind === "none") return text(404, "Not found");
  const isDir = src.kind === "dir";
  const srcPrefix = path + "/";
  const dstPrefix = to + "/";

  if (isDir && (dstPrefix.startsWith(srcPrefix) || srcPrefix.startsWith(dstPrefix))) {
    return text(403, "不能把目录复制或移动到它自己的上级或下级目录");
  }

  // 权限：COPY 需要源的读权限，MOVE 需要源的写权限；目标都需要写权限
  const srcCheck = isDir ? srcPrefix : path;
  const srcOk = move ? userCanWrite(user, env, srcCheck) : userCanRead(user, env, srcCheck);
  const dstOk = userCanWrite(user, env, isDir ? dstPrefix : to);
  if (!srcOk || !dstOk) return text(403, "没有权限");

  // 目标已存在：Overwrite: F → 412；否则先整个删除目标再写入（替换，而不是合并）
  const existing = await resolve(bucket, to, false);
  const overwrite = (context.request.headers.get("Overwrite") || "T").toUpperCase() !== "F";
  if (existing.kind !== "none") {
    if (!overwrite) return text(412, "目标已存在");
    if (existing.kind === "dir") {
      if (!userCanWrite(user, env, dstPrefix)) return text(403, "没有权限");
      await deleteKeys(bucket, await listAllKeys(bucket, dstPrefix));
    } else {
      await bucket.delete(to);
    }
  }

  const copied: string[] = [];
  try {
    if (!isDir) {
      if (!(await copyObject(bucket, path, to))) return text(404, "Not found");
      copied.push(to);
      if (move) await bucket.delete(path);
    } else {
      const keys = await listAllKeys(bucket, srcPrefix);
      for (const key of keys) {
        const target = dstPrefix + key.slice(srcPrefix.length);
        if (await copyObject(bucket, key, target)) copied.push(target);
      }
      // 源目录没有显式标记时，给目标补一个，保证空目录也能显示
      if (!keys.includes(srcPrefix + FOLDER_MARKER)) {
        await bucket.put(dstPrefix + FOLDER_MARKER, new Uint8Array(0));
        copied.push(dstPrefix + FOLDER_MARKER);
      }
      // 全部复制成功之后才删除源
      if (move) await deleteKeys(bucket, keys);
    }
  } catch (e) {
    console.error("dav copy/move failed:", e);
    // 复制中途失败：源还完整保留着，把已经写到目标的部分清理掉
    try {
      await deleteKeys(bucket, copied);
    } catch {}
    return text(507, "复制过程中出错，操作已取消");
  }

  return text(existing.kind === "none" ? 201 : 204);
}

// ---------------------------------------------------------------------------
// LOCK / UNLOCK / PROPPATCH（最小实现，满足 Windows / macOS 客户端的写入流程）
// ---------------------------------------------------------------------------

function lock(context, path: string): Response {
  const token = "opaquelocktoken:" + crypto.randomUUID();
  const xml =
    `<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>` +
    `<D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope>` +
    `<D:depth>infinity</D:depth><D:timeout>Second-3600</D:timeout>` +
    `<D:locktoken><D:href>${token}</D:href></D:locktoken>` +
    `<D:lockroot><D:href>${xmlEscape(hrefFor(path, false))}</D:href></D:lockroot>` +
    `</D:activelock></D:lockdiscovery></D:prop>`;
  return new Response(xml, {
    status: 200,
    headers: davHeaders({ "Content-Type": 'application/xml; charset="utf-8"', "Lock-Token": `<${token}>` }),
  });
}

function proppatch(path: string, isDir: boolean): Response {
  const xml =
    `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:"><D:response>` +
    `<D:href>${xmlEscape(hrefFor(path, isDir))}</D:href>` +
    `<D:propstat><D:prop/><D:status>HTTP/1.1 200 OK</D:status></D:propstat>` +
    `</D:response></D:multistatus>`;
  return new Response(xml, {
    status: 207,
    headers: davHeaders({ "Content-Type": 'application/xml; charset="utf-8"' }),
  });
}

// ---------------------------------------------------------------------------

export async function onRequest(context) {
  const request: Request = context.request;
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, { status: 200, headers: davHeaders({ Allow: ALLOW, "Content-Length": "0" }) });
  }

  if (WRITE_METHODS.has(method) && isCrossOriginRequest(context)) return crossOriginRejectedResponse();

  const user = await getRequestUser(context);
  if (!user) return unauthorized();

  const bucket = getBucket(context);
  if (!bucket) return text(500, "存储桶未配置");

  let decoded: string;
  try {
    decoded = parseBucketPath(context)[1];
  } catch {
    return text(400, "路径无效");
  }
  const wantDir = decoded === "" || new URL(request.url).pathname.endsWith("/");
  const path = decoded.replace(/\/+$/, "");

  if (path) {
    if (!isSafeKey(path)) return text(400, "路径无效");
    if (isInternalPath(path) || hasMarkerSegment(path)) return text(404, "Not found");
  }

  try {
    switch (method) {
      case "PROPFIND":
        return await propfind(context, bucket, user, path, wantDir);
      case "GET":
        return await getFile(context, bucket, user, path, false);
      case "HEAD":
        return await getFile(context, bucket, user, path, true);
      case "PUT":
        return await putFile(context, bucket, user, path, wantDir);
      case "DELETE":
        return await deleteResource(context, bucket, user, path, wantDir);
      case "MKCOL":
        return await mkcol(context, bucket, user, path);
      case "COPY":
        return await copyOrMove(context, bucket, user, path, wantDir, false);
      case "MOVE":
        return await copyOrMove(context, bucket, user, path, wantDir, true);
      case "LOCK":
      case "UNLOCK":
      case "PROPPATCH": {
        const target = path ? (wantDir ? path + "/" : path) : "";
        if (!path || !userCanWrite(user, context.env, target)) return text(403, "没有写入权限");
        if (method === "LOCK") return lock(context, path);
        if (method === "UNLOCK") return text(204);
        return proppatch(path, wantDir);
      }
      default:
        return text(405, "Method not allowed", { Allow: ALLOW });
    }
  } catch (e) {
    console.error("dav error:", method, e);
    return text(500, "服务器内部错误");
  }
}
