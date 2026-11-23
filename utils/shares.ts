// D1：有状态的短分享链接（替代无状态 HMAC 签名链接）。
//
//   - 分享记录是 JSON，存在内部前缀 _$flaredrive$/shares/{id}.json，
//     公开 URL 是 /share/{id}（短随机 ID，不暴露文件路径）。
//   - 一条记录：目标文件、过期时间（null = 长期有效）、可选的访问密码
//     （PBKDF2 哈希）、可选的下载次数上限、已下载次数、创建者。
//   - 删除记录即撤销链接，立即生效。/api/sign 的 HMAC 链接保持可用
//     （向后兼容），目录级令牌只用于应用内预览。
//   - 下载计数按请求计（不是按完成下载计），预览请求不计入。
//   - 密码绝不出现在 URL 里：通过 POST 表单提交，验证通过后发一个
//     1 小时有效的 HMAC 令牌 Cookie（复用 utils/signing 的 signToken）。
//   - 所有认证/过期/次数/密码检查集中在 checkShareAccess() 里，
//     /share/* 的各个入口都走它，不要各自再写一份。

import { INTERNAL_PREFIX, isSafeKey } from "./auth";
import { signToken, verifyToken, clampShareTtl } from "./signing";

export const SHARE_PREFIX = INTERNAL_PREFIX + "shares/";

const ID_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const ID_LENGTH = 10;
const ID_RE = /^[A-Za-z0-9]{10}$/;
const PASSWORD_ITERATIONS = 10000;
const PASSWORD_MAX_LENGTH = 128;
const MAX_DOWNLOADS_LIMIT = 10000;

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
  etag: string | null; // N8：创建时目标文件的 httpEtag；老记录没有，跳过比对
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

export async function loadShare(bucket: any, id: string): Promise<ShareRecord | null> {
  const key = shareKeyForId(id);
  if (!key) return null;
  const obj = await bucket.get(key);
  if (!obj) return null;
  try {
    const record = JSON.parse(await obj.text());
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

export async function saveShare(bucket: any, record: ShareRecord): Promise<void> {
  await bucket.put(SHARE_PREFIX + record.id + ".json", JSON.stringify(record), {
    httpMetadata: { contentType: "application/json" },
  });
}

export async function deleteShare(bucket: any, id: string): Promise<void> {
  const key = shareKeyForId(id);
  if (key) await bucket.delete(key);
}

// N8：删文件时顺带撤销指向它的分享——否则删完重建同名文件，旧链接
// 虽然因 etag 比对打不开了，管理页里还挂着一条孤儿记录。尽力而为：
// 列分享失败不影响删除本身。
export async function deleteSharesForKeys(bucket: any, keys: string[]): Promise<void> {
  if (keys.length === 0) return;
  try {
    const wanted = new Set(keys);
    const all = await listShares(bucket);
    for (const s of all) {
      if (wanted.has(s.key)) await deleteShare(bucket, s.id);
    }
  } catch {
    // 分享清理失败不影响删除本身
  }
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
  if (share.etag) {
    const obj = await bucket.head(share.key);
    if (!obj) return { ok: false, status: 404, message: "分享的文件已被删除" };
    if (obj.httpEtag && obj.httpEtag !== share.etag) {
      return { ok: false, status: 404, message: "分享的文件已被替换，请重新分享" };
    }
  }
  return { ok: true, share };
}

// 下载计数按请求计（不是按完成下载计）。尽力而为：写回失败不影响本次下载。
export async function recordShareDownload(bucket: any, share: ShareRecord): Promise<void> {
  try {
    await saveShare(bucket, { ...share, downloads: share.downloads + 1 });
  } catch {
    // 计数失败不影响下载本身
  }
}
