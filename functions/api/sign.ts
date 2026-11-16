import { getRequestUser, userCanRead, getGuestDirs, isInternalPath, isSafeKey } from "@/utils/auth";
import { getBucket } from "@/utils/bucket";
import { signToken, clampShareTtl, encodeKeyForUrl } from "@/utils/signing";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

// POST /api/sign   { key: "dir/file.ext", expiresIn?: 秒 }
// 为一个文件生成带过期时间的分享链接。调用者必须对该文件有读权限。
export async function onRequestPost(context) {
  let body: { key?: string; expiresIn?: number } = {};
  try {
    body = await context.request.json();
  } catch {
    return json({ error: "请求格式错误" }, 400);
  }

  const key = typeof body.key === "string" ? body.key : "";
  if (!key || key.endsWith("/") || !isSafeKey(key) || isInternalPath(key)) {
    return json({ error: "无效的文件路径" }, 400);
  }

  const env = context.env;
  const origin = new URL(context.request.url).origin;
  const base = `${origin}/raw/${encodeKeyForUrl(key)}`;

  // GUEST 目录下的文件本来就是公开的，直链即可，不需要签名
  if (userCanRead(null, env, key) && getGuestDirs(env).length > 0) {
    return json({ url: base, expires: null, public: true });
  }

  const user = await getRequestUser(context);
  if (!user) return json({ error: "需要登录" }, 401);
  if (!userCanRead(user, env, key)) return json({ error: "没有该文件的访问权限" }, 403);

  const bucket = getBucket(context);
  if (!bucket) return json({ error: "存储桶未配置" }, 500);

  const ttl = clampShareTtl(env, body.expiresIn);
  const expires = Math.floor(Date.now() / 1000) + ttl;
  const token = await signToken(env, bucket, { e: expires, f: key });

  return json({ url: `${base}?token=${token}`, expires, public: false });
}
