// 离线下载：POST /api/write/fetch  { url, dir, filename? }
// 由服务端抓取一个外部 URL，保存到指定目录。调用者必须对目标目录有写权限。

import { getBucket } from "@/utils/bucket";
import { checkPathPermission, isSafeKey, isInternalPath, FOLDER_MARKER } from "@/utils/auth";
import { isCrossOriginRequest, crossOriginRejectedResponse } from "@/utils/csrf";
import { pickContentType, guessContentType } from "@/utils/response";

const MAX_REDIRECTS = 5;
// D3：默认上限从 1 GiB 降到 256 MiB——1 GiB 的文件走 Worker 流式下载很容易
// 超时，用户的实际文件都不大；需要更大时用 FETCH_MAX_SIZE 环境变量调高。
const DEFAULT_MAX_BYTES = 256 * 1024 * 1024; // 256 MiB
const MAX_BUFFERED_BYTES = 64 * 1024 * 1024; // 响应没有 Content-Length 时只能读进内存

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

// SSRF 防护：只允许 http/https、默认端口之外不限制，但拒绝本机、内网、
// 链路本地地址和本站自身（否则可以借服务端身份访问本站接口）。
// M1 注：Workers 无法做 DNS 查询（fetch 时才解析），所以这里只能检查 URL
// 字符串——这是上限，不是完整防护：一个解析到内网地址的域名是拦不住的。
// 另外拦掉已知的本站来源（*.pages.dev 和本站注册域名的全部子域名）。
export function checkTargetUrl(raw: string, selfHost: string): { ok: true; url: URL } | { ok: false; reason: string } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "URL 格式不正确" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return { ok: false, reason: "只支持 http/https 链接" };
  if (url.username || url.password) return { ok: false, reason: "不支持带账户密码的链接" };

  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!host) return { ok: false, reason: "URL 格式不正确" };
  if (host === selfHost.toLowerCase()) return { ok: false, reason: "不能下载本站地址" };
  // 本站的 Pages 默认域名和注册域名下的全部子域名都不能下
  if (host.endsWith(".pages.dev")) return { ok: false, reason: "不能下载本站地址" };
  const registrable = registrableDomain(selfHost);
  if (registrable && (host === registrable || host.endsWith("." + registrable))) {
    return { ok: false, reason: "不能下载本站地址" };
  }
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    return { ok: false, reason: "不允许访问内部地址" };
  }

  // IPv4 字面量（URL 解析后十进制/十六进制写法都已规范成点分十进制）
  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [parseInt(v4[1], 10), parseInt(v4[2], 10)];
    const blocked =
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19));
    if (blocked) return { ok: false, reason: "不允许访问内部地址" };
  }

  // IPv6 字面量：回环、未指定、ULA、链路本地、IPv4 映射一律拒绝
  if (host.includes(":")) {
    if (
      host === "::" || host === "::1" ||
      /^f[cd]/.test(host) || /^fe[89ab]/.test(host) ||
      host.startsWith("::ffff:") || host.startsWith("64:ff9b:")
    ) {
      return { ok: false, reason: "不允许访问内部地址" };
    }
  }

  return { ok: true, url };
}

// 取注册域名（最后两段，如 flaredrive.liuyc.uk -> liuyc.uk）。IP、localhost
// 和单段主机名返回 null。注意：co.uk 这类多级公共后缀会被误判（把
// "example.co.uk" 当成注册域名是准的，但本站域名本身若是 "x.co.uk"，
// 这里会拦掉整个 co.uk——对本站来说只是过度拦截，不影响安全）。
function registrableDomain(host: string): string | null {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (!h || h === "localhost" || h.includes(":") || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return null;
  const parts = h.split(".");
  if (parts.length < 2) return null;
  return parts.slice(-2).join(".");
}

export function sanitizeFilename(name: string): string {
  let n = (name || "").replace(/[\u0000-\u001f\u007f]/g, "").replace(/[\\/]/g, "_").trim();
  n = n.replace(/^\.+/, "");
  if (n.length > 200) {
    const dot = n.lastIndexOf(".");
    const ext = dot > 0 && n.length - dot <= 12 ? n.slice(dot) : "";
    n = n.slice(0, 200 - ext.length) + ext;
  }
  return n;
}

export function filenameFromResponse(url: URL, contentDisposition: string | null): string {
  if (contentDisposition) {
    const star = contentDisposition.match(/filename\*\s*=\s*(?:UTF-8|utf-8)''([^;]+)/);
    if (star) {
      try {
        const n = sanitizeFilename(decodeURIComponent(star[1].trim()));
        if (n) return n;
      } catch {}
    }
    const plain = contentDisposition.match(/filename\s*=\s*("([^"]*)"|[^;]+)/);
    if (plain) {
      const n = sanitizeFilename((plain[2] !== undefined ? plain[2] : plain[1]).trim());
      if (n) return n;
    }
  }
  const last = url.pathname.split("/").filter(Boolean).pop() || "";
  let decoded = last;
  try {
    decoded = decodeURIComponent(last);
  } catch {}
  return sanitizeFilename(decoded) || "download";
}

async function fetchFollowingRedirects(start: URL, selfHost: string): Promise<{ res: Response; finalUrl: URL } | { error: string }> {
  let current = start;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const res = await fetch(current.toString(), {
      method: "GET",
      redirect: "manual", // 每一跳都要重新过一遍地址检查
      headers: { "User-Agent": "FlareDrive-R2 fetcher", Accept: "*/*" },
    });
    if (res.status >= 300 && res.status < 400 && res.headers.get("Location")) {
      let next: URL;
      try {
        next = new URL(res.headers.get("Location"), current);
      } catch {
        return { error: "重定向地址无效" };
      }
      const check = checkTargetUrl(next.toString(), selfHost);
      if (check.ok === false) return { error: "重定向目标被拒绝：" + check.reason };
      current = check.url;
      continue;
    }
    return { res, finalUrl: current };
  }
  return { error: "重定向次数过多" };
}

export async function onRequestPost(context) {
  if (isCrossOriginRequest(context)) return crossOriginRejectedResponse();

  let body: { url?: string; dir?: string; filename?: string } = {};
  try {
    body = await context.request.json();
  } catch {
    return json({ error: "请求格式错误" }, 400);
  }

  let dir = typeof body.dir === "string" ? body.dir : "";
  if (dir && !dir.endsWith("/")) dir += "/";
  if (dir && (!isSafeKey(dir) || isInternalPath(dir))) return json({ error: "目标目录无效" }, 400);

  // 先校验权限，再发起任何外部请求
  if (!(await checkPathPermission(context, dir + "probe", true))) {
    return json({ error: "没有该目录的写入权限" }, 401);
  }

  const selfHost = new URL(context.request.url).hostname;
  const check = checkTargetUrl(typeof body.url === "string" ? body.url.trim() : "", selfHost);
  if (check.ok === false) return json({ error: check.reason }, 400);

  const bucket = getBucket(context);
  if (!bucket) return json({ error: "存储桶未配置" }, 500);

  // F10d：free-name 循环是先 head 再 put，中间有竞态窗口——两个离线下载
  // 同时下同一个 URL 时，后到的 put 会静默覆盖先到的文件。put 加 onlyIf
  //（目标已存在时返回 null 不覆盖），撞了就换下一个名字重下（最多 3 次；
  // 流只能读一次，所以每次重试都重新抓一次 URL）。
  const maxBytes = Math.max(1, parseInt(context.env["FETCH_MAX_SIZE"] || "", 10) || DEFAULT_MAX_BYTES);
  let nameIndex = 0; // 0 = 原名，1 = "name (1).ext"，……
  for (let attempt = 0; attempt < 3; attempt++) {
    let res: Response;
    let finalUrl: URL;
    try {
      const fetched = await fetchFollowingRedirects(check.url, selfHost);
      if ("error" in fetched) return json({ error: fetched.error }, 400);
      res = fetched.res;
      finalUrl = fetched.finalUrl;
    } catch (e) {
      return json({ error: "无法连接到目标地址" }, 502);
    }
    if (!res.ok || !res.body) {
      return json({ error: `目标地址返回了 HTTP ${res.status}` }, 502);
    }

    const requested = typeof body.filename === "string" ? sanitizeFilename(body.filename) : "";
    const filename = requested || filenameFromResponse(finalUrl, res.headers.get("Content-Disposition"));
    if (!isSafeKey(dir + filename) || filename === FOLDER_MARKER) return json({ error: "文件名无效" }, 400);

    // 同名文件已存在时不覆盖，改名为 "name (1).ext"（从上次撞过的位置接着找）
    const keyForIndex = (i: number): string => {
      if (i === 0) return dir + filename;
      const dot = filename.lastIndexOf(".");
      return dot > 0
        ? `${dir}${filename.slice(0, dot)} (${i})${filename.slice(dot)}`
        : `${dir}${filename} (${i})`;
    };
    let idx = nameIndex;
    let key = keyForIndex(idx);
    while (idx <= 50 && (await bucket.head(key))) {
      idx++;
      key = keyForIndex(idx);
    }
    if (idx > 50) return json({ error: "同名文件过多，请先清理目录" }, 409);
    if (!(await checkPathPermission(context, key, true))) return json({ error: "没有该目录的写入权限" }, 401);

    const lengthHeader = res.headers.get("Content-Length");
    const length = lengthHeader !== null && /^\d+$/.test(lengthHeader) ? parseInt(lengthHeader, 10) : null;
    const encoded = !!res.headers.get("Content-Encoding"); // 压缩过的响应，Content-Length 不是解压后的长度

    if (length !== null && length > maxBytes) {
      return json({ error: `文件过大（${length} 字节），上限为 ${maxBytes} 字节` }, 413);
    }

    // 下载站返回的 Content-Type 经常不准（例如把视频标成 text/plain），
    // 后缀能识别时以后缀为准，预览和缩略图都依赖这个类型。
    const contentType = guessContentType(key) || pickContentType(res.headers.get("Content-Type"), key);
    // F10d：onlyIf 让 put 变成原子"不存在才写"；撞了返回 null，不覆盖。
    const options = {
      httpMetadata: contentType ? { contentType } : undefined,
      onlyIf: { etagDoesNotMatch: "*" },
    };

    try {
      let object = null;
      if (length !== null && !encoded) {
        // 已知长度：边下边写，不占内存。M2：流也要逐字节计数——只靠声明的
        // Content-Length 拦不住谎报长度的服务端（声明小、实际多发）。
        let sizeExceeded = false;
        let total = 0;
        const counted = res.body.pipeThrough(
          new TransformStream({
            transform(chunk, controller) {
              total += chunk.byteLength;
              if (total > maxBytes) {
                sizeExceeded = true;
                controller.error(new Error("size"));
              } else {
                controller.enqueue(chunk);
              }
            },
          })
        );
        try {
          // F10c：R2 的流式 put 要求事先知道长度——pipeThrough 出来的流没有
          // 长度，线上直接 502（已实测：带 Content-Length 的离线下载两次
          // 502，不带 Content-Length 的走内存缓冲，能成功）。包一层
          // FixedLengthStream(length) 把长度告诉 R2；服务端谎报长度时
          //（多发/少发）这里会直接报错，下载失败而不是存一个错文件。
          // FixedLengthStream 是 Workers 运行时自带的；Node 测试环境没有，
          // 那里直接用 counted（mock R2 不校验流长度）。
          const stream = typeof FixedLengthStream !== "undefined"
            ? counted.pipeThrough(new FixedLengthStream(length))
            : counted;
          object = await bucket.put(key, stream, options);
        } catch (e) {
          if (sizeExceeded) return json({ error: `文件过大，上限为 ${maxBytes} 字节` }, 413);
          throw e;
        }
      } else {
        // 未知长度：R2 的流式写入要求事先知道长度，只能先读进内存，所以上限小得多
        const limit = Math.min(maxBytes, MAX_BUFFERED_BYTES);
        const reader = res.body.getReader();
        const chunks: Uint8Array[] = [];
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > limit) {
            await reader.cancel();
            return json({ error: `目标地址没有提供文件大小，这种情况下最多只能下载 ${limit} 字节` }, 413);
          }
          chunks.push(value);
        }
        const buffer = new Uint8Array(total);
        let offset = 0;
        for (const c of chunks) {
          buffer.set(c, offset);
          offset += c.byteLength;
        }
        object = await bucket.put(key, buffer, options);
      }
      if (object) return json({ key: object.key, size: object.size, contentType: contentType || null });
      // put 返回 null：head 与 put 之间有人抢先建了同名文件，换下一个名字重下。
      nameIndex = idx + 1;
    } catch (e) {
      console.error("fetch-url save failed:", e);
      return json({ error: "保存文件失败，下载可能中途中断" }, 502);
    }
  }
  return json({ error: "目标文件已存在，请稍后重试" }, 409);
}
