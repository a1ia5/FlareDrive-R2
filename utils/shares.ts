// D1：有状态的短分享链接（替代无状态 HMAC 签名链接）。
//
//   - 分享记录是 JSON，存在内部前缀 _$flaredrive$/shares/{id}.json，
//     公开 URL 是 /share/{id}（短随机 ID，不暴露文件路径）。
//   - 一条记录：目标文件、过期时间（null = 长期有效）、可选的访问密码
//     （PBKDF2 哈希）、可选的下载次数上限、已下载次数、创建者。
//   - 删除记录即撤销链接，立即生效。/api/sign 的 HMAC 链接保持可用
//     （向后兼容），目录级令牌只用于应用内预览。
//   - 下载计数按"成功返回文件"的请求计（200/206；失败、304 不计），预览请求不计入。
//   - 密码绝不出现在 URL 里：通过 POST 表单提交，验证通过后发一个
//     1 小时有效的 HMAC 令牌 Cookie（复用 utils/signing 的 signToken）。
//   - 所有认证/过期/次数/密码检查集中在 checkShareAccess() 里，
//     /share/* 的各个入口都走它，不要各自再写一份。

import { INTERNAL_PREFIX, isSafeKey } from "./auth";
import { signToken, verifyToken, clampShareTtl } from "./signing";
import { normalizeEtag, rawEtagOf, sameEtag } from "./etag";

export const SHARE_PREFIX = INTERNAL_PREFIX + "shares/";

const ID_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const ID_LENGTH = 10;
const ID_RE = /^[A-Za-z0-9]{10}$/;
const PASSWORD_ITERATIONS = 10000;
const PASSWORD_MAX_LENGTH = 128;
const MAX_DOWNLOADS_LIMIT = 10000;
// R3-5：每个用户最多持有的分享记录数（软上限：并发创建时可能略超）。
export const MAX_SHARES_PER_USER = 200;
// R2 自定义元数据总大小上限 2048 字节（键+值）；留余量，超了就不写元数据，
// 清理时退回读记录本体（R2 对象名本身上限 1024 字节，正常情况下总是放得下，这里是防御）。
const META_BUDGET = 1900;

export interface ShareRecord {
  id: string;
  key: string;
  name: string;
  createdAt: number; // unix 秒
  expiresAt: number | null; // null = 长期有效
  password: { salt: string; hash: string } | null;
  maxDownloads: number | null;
  downloads: number;
  createdBy: string;
  // N8：创建时目标文件的 etag。新记录存**原始** etag（obj.etag，不带引号）；
  // v25–v28 的记录存的是带引号的 httpEtag，比较时统一过 normalizeEtag()。
  // 老记录（v25 之前）没有，跳过比对。
  etag: string | null;
}

export function createShareId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(ID_LENGTH));
  let id = "";
  for (const b of bytes) id += ID_ALPHABET[b % ID_ALPHABET.length];
  return id;
}

export function shareKeyForId(id: string): string | null {
  if (typeof id !== "string" || !ID_RE.test(id)) return null;
  return SHARE_PREFIX + id + ".json";
}

export function shareUrlForId(origin: string, id: string): string {
  return origin.replace(/\/+$/, "") + "/share/" + id;
}

// days: 0 = 长期有效；1/7/30 天按 SHARE_LINK_MAX_TTL 上限 clamp。
export function shareExpiryForDays(env, days: number): number | null {
  if (!days || days <= 0) return null;
  const ttl = clampShareTtl(env, Math.floor(days) * 86400);
  return Math.floor(Date.now() / 1000) + ttl;
}

function b64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function pbkdf2Hex(password: string, saltB64: string): Promise<string> {
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PASSWORD_ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  return hex(new Uint8Array(bits));
}

export async function hashSharePassword(password: string): Promise<{ salt: string; hash: string }> {
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await pbkdf2Hex(password, salt);
  return { salt, hash };
}

export async function verifySharePassword(record: ShareRecord, password: string): Promise<boolean> {
  if (!record.password) return false;
  if (typeof password !== "string" || password.length === 0 || password.length > PASSWORD_MAX_LENGTH) return false;
  const hash = await pbkdf2Hex(password, record.password.salt);
  // 定长比较，避免时序泄露
  const a = record.password.hash;
  if (a.length !== hash.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ hash.charCodeAt(i);
  return diff === 0;
}

export function validateShareInput(input: any): { key: string; days: number; password: string | null; maxDownloads: number | null } | { error: string } {
  const key = typeof input?.key === "string" ? input.key : "";
  if (!key || !isSafeKey(key) || key.endsWith("/")) return { error: "分享目标无效" };
  let days = 7;
  if (input?.days !== undefined) {
    const d = Number(input.days);
    if (![0, 1, 7, 30].includes(d)) return { error: "有效期只能是 0（长期有效）、1、7 或 30 天" };
    days = d;
  }
  let password: string | null = null;
  if (typeof input?.password === "string" && input.password.length > 0) {
    if (input.password.length > PASSWORD_MAX_LENGTH) return { error: "密码过长" };
    password = input.password;
  }
  let maxDownloads: number | null = null;
  if (input?.maxDownloads !== undefined && input?.maxDownloads !== null && input?.maxDownloads !== "") {
    const n = Number(input.maxDownloads);
    if (!Number.isInteger(n) || n < 1 || n > MAX_DOWNLOADS_LIMIT) return { error: "下载次数上限须在 1–10000 之间" };
    maxDownloads = n;
  }
  return { key, days, password, maxDownloads };
}

function parseShare(text: string, id: string): ShareRecord | null {
  try {
    const record = JSON.parse(text);
    if (!record || record.id !== id || typeof record.key !== "string" || !isSafeKey(record.key)) return null;
    return {
      id: record.id,
      key: record.key,
      name: typeof record.name === "string" ? record.name : record.key.split("/").pop() || record.key,
      createdAt: typeof record.createdAt === "number" ? record.createdAt : 0,
      expiresAt: typeof record.expiresAt === "number" ? record.expiresAt : null,
      password: record.password && typeof record.password.salt === "string" && typeof record.password.hash === "string" ? record.password : null,
      maxDownloads: typeof record.maxDownloads === "number" ? record.maxDownloads : null,
      downloads: typeof record.downloads === "number" ? record.downloads : 0,
      createdBy: typeof record.createdBy === "string" ? record.createdBy : "",
      etag: typeof record.etag === "string" ? record.etag : null,
    };
  } catch {
    return null;
  }
}

export async function loadShare(bucket: any, id: string): Promise<ShareRecord | null> {
  const key = shareKeyForId(id);
  if (!key) return null;
  const obj = await bucket.get(key);
  if (!obj) return null;
  return parseShare(await obj.text(), id);
}

// R3-5：把"目标 key + 创建者"同时写进记录对象的 customMetadata——
// bucket.list({ include: ["customMetadata"] }) 一次列表就能拿到，不用逐条读记录。
// 元数据只是索引，记录本体（JSON）仍是唯一的事实来源。
function metaForShare(record: ShareRecord): Record<string, string> {
  const enc = new TextEncoder();
  const meta: Record<string, string> = { u: record.createdBy || "" };
  const size = enc.encode("k").length + enc.encode(record.key).length + enc.encode("u").length + enc.encode(meta.u).length;
  if (size <= META_BUDGET) meta.k = record.key; // 超长（多字节路径）时省略，清理时退回读本体
  return meta;
}

export async function saveShare(bucket: any, record: ShareRecord): Promise<void> {
  await bucket.put(SHARE_PREFIX + record.id + ".json", JSON.stringify(record), {
    httpMetadata: { contentType: "application/json" },
    customMetadata: metaForShare(record),
  });
}

// 读-改-写一条分享记录，用 R2 条件写入（onlyIf.etagMatches，**原始** etag）
// 做乐观并发：期间记录被别人改过就重读重试，不会把别人的改动（下载次数、
// 重新绑定的 etag）覆盖回旧值；记录已被撤销（读不到）时不会把它写回来。
// mutate 返回 null 表示无需修改。返回 true = 已写入或无需修改，false = 记录不存在或重试用尽。
export async function updateShare(
  bucket: any,
  id: string,
  mutate: (s: ShareRecord) => ShareRecord | null,
  attempts = 12
): Promise<boolean> {
  const key = shareKeyForId(id);
  if (!key) return false;
  for (let i = 0; i < attempts; i++) {
    // 冲突后带随机退避重试：并发写同一条记录时，每轮至少有一个成功，退避让其余的错开。
    if (i > 0) await new Promise((r) => setTimeout(r, Math.random() * 15 * i));
    const obj = await bucket.get(key);
    if (!obj) return false;
    const current = parseShare(await obj.text(), id);
    if (!current) return false;
    const next = mutate(current);
    if (!next) return true;
    const written = await bucket.put(key, JSON.stringify(next), {
      httpMetadata: { contentType: "application/json" },
      customMetadata: metaForShare(next),
      onlyIf: { etagMatches: rawEtagOf(obj) },
    });
    if (written) return true;
  }
  return false;
}

export async function deleteShare(bucket: any, id: string): Promise<void> {
  const key = shareKeyForId(id);
  if (key) await bucket.delete(key);
}

// R3-5：只列"记录索引"（id、目标 key、创建者），不读记录本体。
// 新记录的 key/创建者在 customMetadata 里，一次 list 返回，所以每页 1 次 R2 调用；
// 没有元数据的记录（v28 及更早创建的，或多字节路径超长的）退回读本体——数量
// 只会随老记录过期/撤销而减少，重新创建分享即可迁移。
export interface ShareIndexEntry {
  id: string;
  key: string;
  createdBy: string;
}

export async function scanShares(bucket: any): Promise<{ entries: ShareIndexEntry[]; truncated: boolean }> {
  const entries: ShareIndexEntry[] = [];
  let cursor: string | undefined = undefined;
  let truncated = false;
  for (let page = 0; page < 20; page++) {
    const list = await bucket.list({ prefix: SHARE_PREFIX, cursor, include: ["customMetadata"] });
    for (const o of list.objects || []) {
      const id = o.key.slice(SHARE_PREFIX.length).replace(/\.json$/, "");
      const meta = o.customMetadata;
      if (meta && typeof meta.k === "string" && meta.k && typeof meta.u === "string") {
        entries.push({ id, key: meta.k, createdBy: meta.u });
        continue;
      }
      const record = await loadShare(bucket, id);
      if (record) entries.push({ id, key: record.key, createdBy: record.createdBy });
    }
    truncated = !!list.truncated;
    if (!truncated) break;
    cursor = list.cursor;
  }
  return { entries, truncated };
}

// N8：删文件时顺带撤销指向它的分享——否则删完重建同名文件，旧链接
// 虽然因 etag 比对打不开了，管理页里还挂着一条孤儿记录。尽力而为：
// 列分享失败不影响删除本身。
export async function deleteSharesForKeys(bucket: any, keys: string[]): Promise<void> {
  if (keys.length === 0) return;
  try {
    const wanted = new Set(keys);
    const { entries, truncated } = await scanShares(bucket);
    if (truncated) console.warn("[shares] 分享记录超过扫描上限（20 页），部分分享可能没有被清理");
    for (const e of entries) {
      if (wanted.has(e.key)) await deleteShare(bucket, e.id);
    }
  } catch (error) {
    // 分享清理失败不影响删除本身，但要留日志——之前这里静默吞掉，清理失效没人知道。
    console.error("[shares] 删除文件后清理分享失败：", error);
  }
}

// R3-4：文件被"原样重写"（重新生成缩略图 / 修复 content-type）后 etag 会变
// （分片上传的 <md5>-<N> 重写成单 PUT 的 <md5>），把绑定旧 etag 的分享
// 改绑到新 etag。只改"当前绑定的正是旧 etag"的记录：调用方是在对旧 etag 做了
// 条件写入成功之后才调用的，内容没变，这些分享指向的就是同一份内容。
// 返回 { rebound, failed }：failed > 0 表示有分享没改绑成功（日志里也会有）。
export async function rebindSharesEtag(
  bucket: any,
  key: string,
  oldEtag: string,
  newEtag: string
): Promise<{ rebound: number; failed: number }> {
  const next = normalizeEtag(newEtag);
  let rebound = 0;
  let failed = 0;
  if (!next || sameEtag(oldEtag, next)) return { rebound, failed };
  const { entries } = await scanShares(bucket);
  for (const e of entries) {
    if (e.key !== key) continue;
    try {
      let changed = false;
      const ok = await updateShare(bucket, e.id, (s) => {
        if (!s.etag || !sameEtag(s.etag, oldEtag)) return null;
        changed = true;
        return { ...s, etag: next };
      });
      if (!ok) failed++;
      else if (changed) rebound++;
    } catch (error) {
      failed++;
      console.error("[shares] 改绑分享 etag 失败：", e.id, error);
    }
  }
  return { rebound, failed };
}

export async function listShares(bucket: any): Promise<ShareRecord[]> {
  const records: ShareRecord[] = [];
  let cursor: string | undefined = undefined;
  for (let page = 0; page < 20; page++) {
    const list = await bucket.list({ prefix: SHARE_PREFIX, cursor });
    for (const o of list.objects || []) {
      const id = o.key.slice(SHARE_PREFIX.length).replace(/\.json$/, "");
      const record = await loadShare(bucket, id);
      if (record) records.push(record);
    }
    if (!list.truncated) break;
    cursor = list.cursor;
  }
  return records;
}

// 密码验证通过后发的 Cookie 令牌：复用 HMAC 签名，payload.f = "share:<id>"，
// 有效期 1 小时。Cookie 本身不含密码，撤销分享（删记录）后令牌自然失效。
export function sharePasswordCookieName(id: string): string {
  return "share_" + id;
}

export async function issueSharePasswordToken(env, bucket: any, id: string): Promise<string> {
  return signToken(env, bucket, { e: Math.floor(Date.now() / 1000) + 3600, f: "share:" + id });
}

export async function hasValidSharePasswordToken(env, bucket: any, request: Request, id: string): Promise<boolean> {
  const cookie = request.headers.get("Cookie") || "";
  const name = sharePasswordCookieName(id) + "=";
  const part = cookie.split(";").map((c) => c.trim()).find((c) => c.startsWith(name));
  if (!part) return false;
  const token = decodeURIComponent(part.slice(name.length));
  return verifyToken(env, bucket, token, "share:" + id);
}

// 集中检查：不存在 / 过期 / 次数用完 / 需要密码。调用方按返回的状态处理，
// 不要在各入口重复写这些判断。
export type ShareCheck =
  | { ok: true; share: ShareRecord }
  | { ok: false; status: 404 | 410; message: string }
  | { ok: false; status: 401; needsPassword: true };

export async function checkShareAccess(env, bucket: any, id: string, request: Request): Promise<ShareCheck> {
  const share = await loadShare(bucket, id);
  if (!share) return { ok: false, status: 404, message: "分享不存在或已被撤销" };
  const now = Math.floor(Date.now() / 1000);
  if (share.expiresAt !== null && share.expiresAt <= now) return { ok: false, status: 410, message: "分享链接已过期" };
  if (share.maxDownloads !== null && share.downloads >= share.maxDownloads) {
    return { ok: false, status: 410, message: "分享链接的下载次数已用完" };
  }
  if (share.password && !(await hasValidSharePasswordToken(env, bucket, request, id))) {
    return { ok: false, status: 401, needsPassword: true };
  }
  // N8：分享绑定的是创建时那个文件，不只是 key——文件被删掉又在同名位置
  // 建了个新文件，旧链接不能接着用。创建时把对象的 etag 存进记录，
  // 这里比对；老分享（没存 etag）跳过检查，照常可用。
  // 比较的是规范化后的原始 etag（见 utils/etag.ts）：v25–v28 的记录存的是带引号
  // 的 httpEtag，规范化后照样匹配。
  if (share.etag) {
    const obj = await bucket.head(share.key);
    if (!obj) return { ok: false, status: 404, message: "分享的文件已被删除" };
    const current = rawEtagOf(obj);
    if (current && !sameEtag(current, share.etag)) {
      return { ok: false, status: 404, message: "分享的文件已被替换，请重新分享" };
    }
  }
  return { ok: true, share };
}

// 下载计数：只在文件真正开始返回（200/206）之后才调用，失败的下载
// （404/500/304、etag 不符）不占 maxDownloads。用 updateShare 的条件写入累加：
// 并发下载不会互相覆盖计数，也不会把刚改绑的 etag 写回旧值，已撤销的分享
// 不会被写回。尽力而为：写回失败不影响本次下载。
export async function recordShareDownload(bucket: any, share: ShareRecord): Promise<void> {
  try {
    await updateShare(bucket, share.id, (s) => ({ ...s, downloads: s.downloads + 1 }));
  } catch {
    // 计数失败不影响下载本身
  }
}
