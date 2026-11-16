// R2 里的对象完全来自用户上传，不能信任。所有把对象内容返回给浏览器的接口
// （/raw/、/dav/）都要经过这里加上同一组响应头。

const DANGEROUS_CONTENT_TYPES = [
  "text/html",
  "application/xhtml+xml",
  "image/svg+xml",
  "application/xml",
  "text/xml",
  "application/javascript",
  "text/javascript",
];

const DANGEROUS_EXTENSIONS = /\.(x?html?|svgz?|xml|xsl|xslt|mht|mhtml|js|mjs)$/i;

export function isDangerousContent(contentType: string | null, key = ""): boolean {
  if (DANGEROUS_EXTENSIONS.test(key)) return true;
  if (!contentType) return false;
  const base = contentType.split(";")[0].trim().toLowerCase();
  return DANGEROUS_CONTENT_TYPES.includes(base);
}

export function applyObjectSecurityHeaders(headers: Headers, key: string): void {
  // 1) 禁止内容嗅探
  headers.set("X-Content-Type-Options", "nosniff");
  // 2) CSP sandbox：即使被直接在标签页里打开，也是一个没有脚本、没有同源身份的文档，
  //    读不到本站的 localStorage（登录凭据保存在那里），也调不了 /api/*
  headers.set("Content-Security-Policy", "sandbox");
  // 3) html / svg / xml / js 直接打开时一律强制下载（<img> 内联显示 svg 不受影响）
  if (isDangerousContent(headers.get("Content-Type"), key)) {
    const name = key.split("/").pop() || "download";
    headers.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(name)}`);
  }
  // 4) 签名在 URL 里，不要通过 Referer 泄露给第三方
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Frame-Options", "SAMEORIGIN");
}

// R2Range（{offset,length} | {suffix}）→ "bytes start-end/size"
export function formatContentRange(range: any, size: number): string {
  let start: number;
  let end: number;
  if (typeof range?.suffix === "number") {
    start = Math.max(0, size - range.suffix);
    end = size - 1;
  } else {
    start = typeof range?.offset === "number" ? range.offset : 0;
    end = typeof range?.length === "number" ? start + range.length - 1 : size - 1;
  }
  return `bytes ${start}-${end}/${size}`;
}

const EXT_MIME: Record<string, string> = {
  jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", gif: "image/gif", webp: "image/webp",
  bmp: "image/bmp", ico: "image/x-icon", avif: "image/avif", heic: "image/heic",
  mp4: "video/mp4", m4v: "video/mp4", webm: "video/webm", mov: "video/quicktime", mkv: "video/x-matroska",
  avi: "video/x-msvideo", ogv: "video/ogg", wmv: "video/x-ms-wmv",
  mp3: "audio/mpeg", m4a: "audio/mp4", wav: "audio/wav", flac: "audio/flac", ogg: "audio/ogg",
  pdf: "application/pdf", txt: "text/plain", md: "text/markdown", csv: "text/csv", json: "application/json",
  zip: "application/zip", gz: "application/gzip", tar: "application/x-tar", "7z": "application/x-7z-compressed",
  doc: "application/msword", docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xls: "application/vnd.ms-excel", xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ppt: "application/vnd.ms-powerpoint", pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
};

export function guessContentType(key: string): string | undefined {
  const ext = (key.split("/").pop() || "").split(".").pop()?.toLowerCase() || "";
  return EXT_MIME[ext];
}

// 客户端给的 Content-Type 缺失或是占位值时，按后缀猜一个
export function pickContentType(headerValue: string | null, key: string): string | undefined {
  const v = (headerValue || "").split(";")[0].trim().toLowerCase();
  if (v && v !== "application/octet-stream" && v !== "application/x-www-form-urlencoded") {
    return headerValue as string;
  }
  return guessContentType(key) || (v ? (headerValue as string) : undefined);
}
