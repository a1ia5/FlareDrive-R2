// /raw/ 读取用的带过期时间的 HMAC 签名 URL。
//
// 令牌格式：  <base64url(payload JSON)>.<base64url(HMAC-SHA256(payload))>
// payload：   { e: 过期时间(Unix 秒), f?: 精确文件 key, p?: 允许的目录前缀[] }
//
//   - 分享链接：f = 文件 key，只对这一个文件有效；
//   - 应用内显示（缩略图、预览、全景图、下载）：p = [当前目录, 缩略图目录]，
//     由文件列表接口签发，12~24 小时后失效。
//
// 密钥来源：环境变量 SIGNING_SECRET；没有配置时自动生成一个随机密钥保存在
// R2 的 _$flaredrive$/signing-secret（该路径任何接口都读不到）。
// 更换/删除密钥会让所有已签发的链接立即失效。

import { INTERNAL_PREFIX } from "./auth";

const SECRET_KEY_PATH = INTERNAL_PREFIX + "signing-secret";

export interface TokenPayload {
  e: number;
  f?: string;
  p?: string[];
}

// 按"密钥来源"缓存已导入的 CryptoKey：环境变量按值缓存；
// R2 里的密钥按存储桶对象缓存（多存储桶部署时每个桶各有自己的密钥）。
let envKeyCache: { secret: string; key: CryptoKey } | null = null;
const bucketKeyCache = new WeakMap<object, CryptoKey>();

function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function importKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function getSigningKey(env, bucket): Promise<CryptoKey> {
  const envSecret = env["SIGNING_SECRET"];
  if (typeof envSecret === "string" && envSecret.length > 0) {
    if (envKeyCache?.secret !== envSecret) {
      envKeyCache = { secret: envSecret, key: await importKey(envSecret) };
    }
    return envKeyCache.key;
  }

  const cached = bucketKeyCache.get(bucket);
  if (cached) return cached;

  let secret: string | null = null;
  const existing = await bucket.get(SECRET_KEY_PATH);
  if (existing) secret = (await existing.text()).trim();

  if (!secret) {
    const generated = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    // onlyIf etagDoesNotMatch "*"：只有对象还不存在时才写入，
    // 避免两个并发请求各自生成不同的密钥、互相覆盖。
    const put = await bucket.put(SECRET_KEY_PATH, generated, {
      onlyIf: { etagDoesNotMatch: "*" },
    });
    if (put) {
      secret = generated;
    } else {
      const again = await bucket.get(SECRET_KEY_PATH);
      if (!again) throw new Error("无法读取签名密钥");
      secret = (await again.text()).trim();
    }
  }

  const key = await importKey(secret);
  bucketKeyCache.set(bucket, key);
  return key;
}

export async function signToken(env, bucket, payload: TokenPayload): Promise<string> {
  const key = await getSigningKey(env, bucket);
  const body = b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return body + "." + b64urlEncode(new Uint8Array(sig));
}

// 校验令牌是否有效、未过期，并且覆盖 path。
export async function verifyToken(env, bucket, token: string, path: string): Promise<boolean> {
  if (!token || token.length > 4096) return false;
  const dot = token.indexOf(".");
  if (dot <= 0 || dot !== token.lastIndexOf(".")) return false;
  const body = token.slice(0, dot);

  let sig: Uint8Array;
  let payload: TokenPayload;
  try {
    sig = b64urlDecode(token.slice(dot + 1));
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
  } catch {
    return false;
  }

  const key = await getSigningKey(env, bucket);
  // crypto.subtle.verify 内部是定长比较
  const ok = await crypto.subtle.verify("HMAC", key, sig, new TextEncoder().encode(body));
  if (!ok) return false;

  if (typeof payload?.e !== "number" || payload.e < Math.floor(Date.now() / 1000)) return false;
  if (typeof payload.f === "string" && payload.f === path) return true;
  if (Array.isArray(payload.p)) {
    for (const prefix of payload.p) {
      if (typeof prefix === "string" && path.startsWith(prefix)) return true;
    }
  }
  return false;
}

// 应用内令牌的过期时间：对齐到 12 小时的整点边界再加 12 小时，
// 这样同一时间段内签出的 URL 完全相同，浏览器缓存（尤其是缩略图）仍然有效。
export function sessionTokenExpiry(nowMs = Date.now()): number {
  const bucketSec = 12 * 3600;
  const now = Math.floor(nowMs / 1000);
  return (Math.floor(now / bucketSec) + 2) * bucketSec;
}

export function clampShareTtl(env, requested: unknown): number {
  const max = Math.max(60, parseInt(env["SHARE_LINK_MAX_TTL"] || "", 10) || 30 * 86400);
  const def = Math.min(max, 7 * 86400);
  const n = typeof requested === "number" && isFinite(requested) ? Math.floor(requested) : def;
  return Math.min(max, Math.max(60, n));
}

export function encodeKeyForUrl(key: string): string {
  return key.split("/").map(encodeURIComponent).join("/");
}
