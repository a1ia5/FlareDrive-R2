// R2 的 etag 有两种写法，混用就是 v27/v28 出事故的原因：
//
//   obj.etag      原始值，不带引号，例如  5d41402abc4b2a76b9719d911017c592
//                 （分片上传的对象是  <md5>-<分片数>）
//   obj.httpEtag  同一个值加了双引号，只用来放进 HTTP 响应头 ETag
//
// R2 的条件参数（put/get 的 onlyIf: { etagMatches / etagDoesNotMatch }）只认
// **原始值**：传带引号的值，workerd 直接抛 "Conditional ETag should not be
// wrapped in quotes"，线上表现为 Worker 未捕获异常（error code: 1101）。
//
// 所以：存进记录、拿去比较、传给 onlyIf 的一律是原始值；httpEtag 只用于响应头。
// v25–v28 创建的分享记录里存的是带引号的 httpEtag，比较时统一过 normalizeEtag()，
// 老记录不用迁移。

// 去掉两端空白、弱校验前缀 W/、成对的双引号。null/非字符串返回 ""。
export function normalizeEtag(value: unknown): string {
  if (typeof value !== "string") return "";
  let s = value.trim();
  if (s.startsWith("W/")) s = s.slice(2);
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) s = s.slice(1, -1);
  return s;
}

// 取一个 R2 对象的原始 etag（优先 obj.etag，没有时才从 httpEtag 去引号）。
export function rawEtagOf(obj: any): string {
  if (!obj) return "";
  return normalizeEtag(obj.etag) || normalizeEtag(obj.httpEtag);
}

// 两个 etag 是否是同一个值（忽略引号写法）；任何一边为空都不算相同。
export function sameEtag(a: unknown, b: unknown): boolean {
  const x = normalizeEtag(a);
  return x !== "" && x === normalizeEtag(b);
}
