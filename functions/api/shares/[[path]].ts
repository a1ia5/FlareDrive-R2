// D1：有状态分享链接的管理接口。
//
//   POST   /api/shares        创建分享（登录 + 对文件有读权限）
//   GET    /api/shares        列出分享（本人创建的；管理员看全部）
//   DELETE /api/shares/{id}   撤销分享（创建者或管理员）
//
// 公开下载入口在 functions/share/[[path]].ts（/share/{id}），不在这里。
// /api/sign 的 HMAC 链接保持可用（向后兼容）。

import { getBucket } from "@/utils/bucket";
import { getRequestUser, userCanRead, isInternalPath, isThumbnailKey, getGuestDirs } from "@/utils/auth";
import { isCrossOriginRequest, crossOriginRejectedResponse } from "@/utils/csrf";
import {
  createShareId,
  validateShareInput,
  hashSharePassword,
  shareExpiryForDays,
  saveShare,
  loadShare,
  deleteShare,
  listShares,
  shareUrlForId,
} from "@/utils/shares";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function onRequest(context) {
  const request: Request = context.request;
  const method = request.method.toUpperCase();
  const segments: string[] = (context.params?.path || []) as string[];
  const origin = new URL(request.url).origin;

  if ((method === "POST" || method === "DELETE") && isCrossOriginRequest(context)) {
    return crossOriginRejectedResponse();
  }

  const user = await getRequestUser(context);
  if (!user) {
    return json({ error: "需要登录" }, 401);
  }
  // 只读用户禁止创建、查看和管理分享链接：分享会把文件以链接形式
  // 对外暴露，属于写操作；仅置灰按钮不够，必须在服务端直接拒绝。
  if (user.isReadOnly) {
    return json({ error: "只读用户无法创建或管理分享链接" }, 403);
  }

  const bucket = getBucket(context);
  if (!bucket) return json({ error: "存储桶未配置" }, 500);

  // ---- 创建分享 ----
  if (method === "POST" && segments.length === 0) {
    let input: any = {};
    try {
      input = await request.json();
    } catch {
      return json({ error: "请求体无效" }, 400);
    }
    const validated = validateShareInput(input);
    if ("error" in validated) return json({ error: validated.error }, 400);
    const { key, days, password, maxDownloads } = validated;

    if (isInternalPath(key) && !isThumbnailKey(key)) return json({ error: "不能分享内部文件" }, 400);
    if (!userCanRead(user, context.env, key)) return json({ error: "没有该文件的访问权限" }, 403);
    const obj = await bucket.head(key);
    if (!obj) return json({ error: "文件不存在" }, 404);

    const id = createShareId();
    const record = {
      id,
      key,
      name: key.split("/").pop() || key,
      createdAt: Math.floor(Date.now() / 1000),
      expiresAt: shareExpiryForDays(context.env, days),
      password: password ? await hashSharePassword(password) : null,
      maxDownloads,
      downloads: 0,
      createdBy: user.username,
    };
    await saveShare(bucket, record);
    // replaceId：分享对话框改选项重新生成时，删掉上一条自己创建的记录，
    // 避免每次改有效期/密码都在管理页留一条孤儿分享。
    const replaceId = typeof input?.replaceId === "string" ? input.replaceId : "";
    if (replaceId && replaceId !== id) {
      const old = await loadShare(bucket, replaceId);
      if (old && (user.isAdmin || old.createdBy === user.username)) {
        await deleteShare(bucket, replaceId);
      }
    }
    const guestDirs = getGuestDirs(context.env);
    return json({
      id,
      url: shareUrlForId(origin, id),
      key: record.key,
      name: record.name,
      expiresAt: record.expiresAt,
      expires: record.expiresAt,
      downloads: 0,
      maxDownloads: record.maxDownloads,
      hasPassword: !!record.password,
      public: guestDirs.some((d) => key.startsWith(d)),
    });
  }

  // ---- 列出分享 ----
  if (method === "GET" && segments.length === 0) {
    const all = await listShares(bucket);
    const visible = user.isAdmin ? all : all.filter((s) => s.createdBy === user.username);
    visible.sort((a, b) => b.createdAt - a.createdAt);
    return json({
      shares: visible.map((s) => ({
        id: s.id,
        key: s.key,
        name: s.name,
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
        downloads: s.downloads,
        maxDownloads: s.maxDownloads,
        hasPassword: !!s.password,
        createdBy: s.createdBy,
        url: shareUrlForId(origin, s.id),
      })),
    });
  }

  // ---- 撤销分享 ----
  if (method === "DELETE" && segments.length === 1) {
    const share = await loadShare(bucket, segments[0]);
    if (!share) return json({ error: "分享不存在" }, 404);
    if (!user.isAdmin && share.createdBy !== user.username) {
      return json({ error: "只能撤销自己创建的分享" }, 403);
    }
    await deleteShare(bucket, segments[0]);
    return json({ success: true });
  }

  return json({ error: "Method not allowed" }, 405);
}
