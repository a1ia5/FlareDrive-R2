// WebDAV 接口：/dav/<path>
//
// 沿用网盘本身的约定：
//   - 目录用空对象 "<目录>/_$folder$" 标记（没有标记但下面有对象的前缀也算目录）；
//   - 权限和网页端完全一致（utils/auth.ts），必须用账户登录，不提供匿名访问；
//   - _$flaredrive$/ 内部目录和 _$folder$ 标记对客户端不可见。
//
// R2 没有原生的移动/重命名，MOVE/COPY 是"先暂存、再提交，全部成功后再删除源"，
// 不是原子操作；单个请求能处理的对象数受 Workers 子请求数限制（暂存让每个文件
// 多花一倍子请求，大目录可能触及上限而返回 507，但源和目标都保持原样）。
// 覆盖目标时也一样：旧目标只有在新内容完整提交之后才会被清理，绝不在复制开始
// 前删除。唯一无法完全避免的残留风险：R2 没有目录级原子替换，提交阶段中途失败
// 时目标可能已被部分更新（暂存阶段失败则目标完全不受影响）。

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

  // 目标已存在：Overwrite: F → 412。注意这里不再像以前那样先删除目标
  // （H3/M5）：旧目标只有在新内容完整提交之后才会被清理。
  const existing = await resolve(bucket, to, false);
  const overwrite = (context.request.headers.get("Overwrite") || "T").toUpperCase() !== "F";
  if (existing.kind !== "none") {
    if (!overwrite) return text(412, "目标已存在");
    if (existing.kind === "dir" && !userCanWrite(user, env, dstPrefix)) return text(403, "没有权限");
  }
  const dstExisted = existing.kind !== "none";
  // 覆盖时需要知道旧目标里有哪些 key：提交完成后删掉不在新内容里的旧文件
  // （替换而不是合并；文件/目录类型互换时，旧目标的整个 key 也在这里面）。
  const oldDstKeys: string[] =
    existing.kind === "dir"
      ? await listAllKeys(bucket, dstPrefix)
      : existing.kind === "file"
        ? [to]
        : [];

  // H3/M5：两阶段复制。阶段一先把全部内容写到目标下的临时目录（源和原目标
  // 都原封不动）；阶段二逐个提交到最终位置，提交完再删暂存副本；全部成功后
  // 才删源（MOVE）并清理旧目标里多余的文件。任何一步失败都保留源；
  // 目标在暂存阶段失败时完全不受影响。
  const staging = ".flaredrive-staging-" + crypto.randomUUID();
  const staged: string[] = []; // 已写入暂存区、尚未提交的 key
  const committed: string[] = []; // 已提交到最终位置的 key
  let committedAll = false; // 全部提交完成之后，失败也不再回滚已提交的文件
  const abort = async (msg: string): Promise<Response> => {
    try {
      await deleteKeys(bucket, staged);
    } catch {}
    // 只有目标本来不存在、且尚未全部提交时，删掉已提交的新文件才是安全的回滚；
    // 覆盖场景下已提交的文件无法恢复成旧内容，留着比删掉好。
    if (!dstExisted && !committedAll) {
      try {
        await deleteKeys(bucket, committed);
      } catch {}
    }
    return text(507, msg);
  };
  try {
    if (!isDir) {
      if (dstExisted) {
        // 覆盖单个文件：先写到临时 key 再提交（R2 的 PUT 本身是原子的，
        // 提交失败时旧文件仍在）。
        const tmp = to + ".flaredrive-tmp-" + crypto.randomUUID();
        if (!(await copyObject(bucket, path, tmp))) return await abort("复制失败，目标未改动");
        staged.push(tmp);
        if (!(await copyObject(bucket, tmp, to))) return await abort("复制失败，目标未改动");
        committed.push(to);
        await bucket.delete(tmp);
        staged.splice(staged.indexOf(tmp), 1);
      } else {
        if (!(await copyObject(bucket, path, to))) return await abort("复制失败，目标未改动");
        committed.push(to);
      }
      committedAll = true;
      if (move) await bucket.delete(path);
    } else {
      const keys = await listAllKeys(bucket, srcPrefix);
      const stagePrefix = dstPrefix + staging + "/";
      // 阶段一：暂存全部源文件（源和目标都原封不动）
      for (const key of keys) {
        const stagedKey = stagePrefix + key.slice(srcPrefix.length);
        if (!(await copyObject(bucket, key, stagedKey))) {
          return await abort("复制失败，源和目标均未改动");
        }
        staged.push(stagedKey);
      }
      // 源目录没有显式标记时，给目标补一个，保证空目录也能显示
      if (!keys.includes(srcPrefix + FOLDER_MARKER)) {
        await bucket.put(stagePrefix + FOLDER_MARKER, new Uint8Array(0));
        staged.push(stagePrefix + FOLDER_MARKER);
      }
      // 阶段二：逐个提交到最终位置（提交完成后删除暂存副本）
      for (const stagedKey of [...staged]) {
        const target = dstPrefix + stagedKey.slice(stagePrefix.length);
        if (!(await copyObject(bucket, stagedKey, target))) {
          return await abort(dstExisted ? "复制失败，目标可能已被部分更新" : "复制失败，操作已取消");
        }
        committed.push(target);
        await bucket.delete(stagedKey);
        staged.splice(staged.indexOf(stagedKey), 1);
      }
      // 全部提交成功后，删掉旧目标里不在新内容里的文件（替换而不是合并）
      const stale = oldDstKeys.filter((k) => !committed.includes(k));
      if (stale.length > 0) await deleteKeys(bucket, stale);
      committedAll = true;
      // 全部复制成功之后才删除源
      if (move) await deleteKeys(bucket, keys);
    }
  } catch (e) {
    console.error("dav copy/move failed:", e);
    return await abort("复制过程中出错，操作已取消");
  }

  return text(dstExisted ? 204 : 201);
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
