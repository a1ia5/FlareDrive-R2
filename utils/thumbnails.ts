// 删除文件时顺带清理缩略图。
//
// 缩略图对象以内容摘要命名：_$flaredrive$/thumbnails/<sha1(缩略图字节)>.png，
// 文件的 customMetadata.thumbnail 存的就是这 40 位摘要。
//
// 同一个摘要可能被多个文件引用：同一张图重复上传、复制/移动/重命名都会
// 继承同一份 customMetadata.thumbnail（复制时服务端会原样沿用，见
// functions/api/write/items/[[path]].ts 的复制分支）。所以删文件时
// 不能无条件删缩略图，必须先确认没有别的活文件还在引用它。
// R2 没有原生的文件夹重命名/移动，改名、移动本质上都是 COPY + DELETE，
// 这个检查是必需的，不是可选优化。
//
// 清理是尽力而为的：扫描不到完整列表、或删缩略图本身失败时，宁可留下
// 孤儿缩略图，也绝不能影响文件删除本身，更不能误删仍被引用的缩略图。

import { THUMBNAIL_PREFIX } from "./auth";

const DIGEST_RE = /^[0-9a-f]{40}$/;
// 与 children 列表保持一致：每页 1000 个对象，上限 20000 个。
const MAX_SCAN_PAGES = 20;

export function thumbnailKeyForDigest(digest: string): string | null {
  if (typeof digest !== "string" || !DIGEST_RE.test(digest)) return null;
  return THUMBNAIL_PREFIX + digest + ".png";
}

function digestOf(obj: any): string | null {
  const d = obj?.customMetadata?.thumbnail;
  return typeof d === "string" && DIGEST_RE.test(d) ? d : null;
}

// 删掉 digests 里那些已无任何引用者（排除 deletedKeys）的缩略图对象。
// 引用检查靠一次全桶列表扫描（带 customMetadata）；扫描不完整（超过
// 上限仍 truncated）时无法证明无引用，全部跳过。
// 永远不抛异常。
export async function deleteUnreferencedThumbnails(
  bucket: any,
  digests: string[],
  deletedKeys: string[]
): Promise<void> {
  const targets = [...new Set((digests || []).filter((d) => DIGEST_RE.test(d || "")))];
  if (!targets.length) return;
  try {
    const deleted = new Set(deletedKeys || []);
    const referenced = new Set<string>();
    let cursor: string | undefined = undefined;
    let complete = false;
    for (let page = 0; page < MAX_SCAN_PAGES; page++) {
      const list: any = await bucket.list({ include: ["customMetadata"], cursor });
      for (const obj of list.objects || []) {
        if (deleted.has(obj.key)) continue;
        const d = digestOf(obj);
        if (d) referenced.add(d);
      }
      if (!list.truncated) {
        complete = true;
        break;
      }
      cursor = list.cursor;
    }
    if (!complete) return;
    for (const digest of targets) {
      if (referenced.has(digest)) continue;
      const key = thumbnailKeyForDigest(digest);
      if (key) await bucket.delete(key);
    }
  } catch {
    // 尽力而为：缩略图清理失败不影响文件删除。
  }
}
