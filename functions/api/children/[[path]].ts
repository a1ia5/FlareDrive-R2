import { notFound, parseBucketPath } from "@/utils/bucket";
import {
  get_list_auth_status,
  userCanRead,
  userCanTraverse,
  isSafeKey,
  INTERNAL_PREFIX,
  THUMBNAIL_PREFIX,
  FOLDER_MARKER,
} from "@/utils/auth";
import { signToken, sessionTokenExpiry } from "@/utils/signing";

const MAX_PAGES = 20; // 每页最多 1000 个对象

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function onRequestGet(context) {
  try {
    const [bucket, rawPath] = parseBucketPath(context);
    if (!bucket) return notFound();

    const path = rawPath.replace(/\/+$/, "");
    const prefix = path && `${path}/`;
    if (prefix.startsWith(INTERNAL_PREFIX)) return notFound();
    if (prefix && !isSafeKey(prefix)) return notFound();

    const authResult = await get_list_auth_status(context, path);
    if (!authResult.hasAccess) {
      // 200 + needLogin：不带 WWW-Authenticate，避免弹出浏览器原生登录框
      return json({ needLogin: true, message: "需要登录才能查看文件列表" });
    }
    const user = authResult.user;
    const env = context.env;

    // 此前只取第一页（最多 1000 个对象），超出的文件既看不到，
    // 递归删除/移动文件夹时也会被漏掉。
    const objects: any[] = [];
    const folderSet = new Set<string>();
    let cursor: string | undefined = undefined;
    let truncated = false;
    for (let page = 0; page < MAX_PAGES; page++) {
      const list = await bucket.list({
        prefix,
        delimiter: "/",
        cursor,
        include: ["httpMetadata", "customMetadata"],
      });
      objects.push(...list.objects);
      for (const p of list.delimitedPrefixes) folderSet.add(p);
      truncated = !!list.truncated;
      if (!list.truncated) break;
      cursor = list.cursor;
    }

    const value = objects
      .filter((obj) => !obj.key.endsWith("/" + FOLDER_MARKER) && obj.key !== FOLDER_MARKER)
      .filter((obj) => userCanRead(user, env, obj.key))
      .map(({ key, size, uploaded, httpMetadata, customMetadata }) => ({
        key,
        size,
        uploaded,
        httpMetadata,
        customMetadata,
      }));

    const folders = [...folderSet]
      .filter((folder) => !folder.startsWith(INTERNAL_PREFIX))
      .filter((folder) => userCanTraverse(user, env, folder));

    // 应用内读取 /raw/ 用的签名令牌：覆盖缩略图目录；
    // 如果当前账户对这个目录本身有读权限，再加上这个目录。
    const scopes = [THUMBNAIL_PREFIX];
    if (user && userCanRead(user, env, prefix)) scopes.push(prefix);
    const expires = sessionTokenExpiry();
    const rawToken = await signToken(env, bucket, { e: expires, p: scopes });

    return json({
      value,
      folders,
      isGuest: authResult.isGuest,
      truncated,
      rawToken,
      rawTokenPrefix: scopes.length > 1 ? prefix : null,
      rawTokenExpires: expires,
    });
  } catch (e) {
    console.error("children error:", e);
    return new Response("服务器内部错误", { status: 500 });
  }
}
