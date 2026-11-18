const THUMBNAIL_SIZE = 144;

// L6：按"覆盖"（cover）方式把源画面画进 144×144 的方形缩略图：等比放大到
// 填满整个方块，超出部分裁掉（居中裁剪），不再把宽屏/竖屏画面压扁成方形。
function drawCover(ctx, source, sw, sh) {
  const size = THUMBNAIL_SIZE;
  const scale = Math.max(size / sw, size / sh);
  const dw = sw * scale;
  const dh = sh * scale;
  ctx.drawImage(source, (size - dw) / 2, (size - dh) / 2, dw, dh);
}

async function captureImageFrame(ctx, srcUrl) {
  const image = await new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("图片加载失败"));
    img.src = srcUrl;
  });
  drawCover(ctx, image, image.naturalWidth, image.naturalHeight);
}

// 画面平均亮度（0~255）。每隔几个像素取样一次就够了。
function frameBrightness(imageData) {
  const data = imageData.data;
  let sum = 0;
  let count = 0;
  for (let i = 0; i < data.length; i += 16) {
    sum += 0.2126 * data[i] + 0.7152 * data[i + 1] + 0.0722 * data[i + 2];
    count++;
  }
  return count ? sum / count : 0;
}

// 亮度达到这个值就认为"已经是一张正常的画面"，不再继续取后面的帧，
// 避免对开头本来就正常的大视频多做几次远程 seek。
const BRIGHT_ENOUGH = 90;
const SEEK_TIMEOUT_MS = 8000;

function loadVideo(srcUrl, timeoutMs) {
  return new Promise((resolve, reject) => {
    const videoEl = document.createElement("video");
    videoEl.muted = true;
    videoEl.playsInline = true; // 避免部分移动端浏览器把视频拉到全屏播放
    videoEl.preload = "auto";

    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("视频加载超时"));
    }, timeoutMs);

    function cleanup() {
      clearTimeout(timer);
      videoEl.removeEventListener("loadeddata", onLoaded);
      videoEl.removeEventListener("error", onError);
    }
    function onLoaded() {
      cleanup();
      resolve(videoEl);
    }
    function onError() {
      // 后缀是 .mp4/.mov 不代表浏览器能解码里面的编码（例如部分 HEVC/H.265），
      // 这种情况纯前端没有办法生成缩略图。
      cleanup();
      reject(new Error("视频加载失败：" + (videoEl.error ? videoEl.error.message : "未知错误")));
    }

    videoEl.addEventListener("loadeddata", onLoaded);
    videoEl.addEventListener("error", onError);
    videoEl.src = srcUrl;
  });
}

// seek 是异步的，必须等 "seeked" 事件之后画面才是目标时间点的那一帧
function seekTo(videoEl, time) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("视频跳转超时"));
    }, SEEK_TIMEOUT_MS);
    function cleanup() {
      clearTimeout(timer);
      videoEl.removeEventListener("seeked", onSeeked);
      videoEl.removeEventListener("error", onError);
    }
    function onSeeked() {
      cleanup();
      resolve();
    }
    function onError() {
      cleanup();
      reject(new Error("视频跳转失败"));
    }
    videoEl.addEventListener("seeked", onSeeked);
    videoEl.addEventListener("error", onError);
    videoEl.currentTime = time;
  });
}

// 候选时间点：开头 0.1 秒，以及时长的 10% / 25% / 50% / 75%
export function thumbnailCandidateTimes(duration) {
  if (!isFinite(duration) || duration <= 0) return [0.1];
  const raw = [Math.min(0.1, duration / 2), duration * 0.1, duration * 0.25, duration * 0.5, duration * 0.75];
  const times = [];
  for (const t of raw) {
    const clamped = Math.max(0, Math.min(t, Math.max(0, duration - 0.05)));
    if (!times.some((x) => Math.abs(x - clamped) < 0.05)) times.push(clamped);
  }
  return times;
}

// 很多视频开头是黑屏或渐入，固定取 0.1 秒那一帧会得到一张全黑的缩略图。
// 现在按顺序取几个时间点的帧，选其中最亮的一张。
async function captureVideoFrame(ctx, srcUrl, timeoutMs) {
  const video = await loadVideo(srcUrl, timeoutMs);
  const size = THUMBNAIL_SIZE;
  let best = null;

  try {
    for (const time of thumbnailCandidateTimes(video.duration)) {
      try {
        await seekTo(video, time);
      } catch (seekError) {
        if (best) break; // 已经有可用的帧，后面的取不到就算了
        continue; // L5：第一个时间点 seek 失败就跳过，试下一个，不要直接报错
      }
      drawCover(ctx, video, video.videoWidth, video.videoHeight);
      const imageData = ctx.getImageData(0, 0, size, size);
      const brightness = frameBrightness(imageData);
      if (!best || brightness > best.brightness) best = { brightness, imageData };
      if (brightness >= BRIGHT_ENOUGH) break;
    }
  } finally {
    // 释放解码器和网络连接
    video.removeAttribute("src");
    video.load();
  }

  if (!best) throw new Error("未能从视频中取到画面");
  ctx.putImageData(best.imageData, 0, 0);
}

/**
 * @param {File} file
 */
export async function generateThumbnail(file) {
  const canvas = document.createElement("canvas");
  canvas.width = THUMBNAIL_SIZE;
  canvas.height = THUMBNAIL_SIZE;
  const ctx = canvas.getContext("2d");

  const objectUrl = URL.createObjectURL(file);
  try {
    if (file.type.startsWith("image/")) {
      await captureImageFrame(ctx, objectUrl);
    } else if (file.type.startsWith("video/")) {
      // 本地 Blob 已经完整存在于内存/磁盘里，这里的耗时主要来自浏览器解码器
      // 定位首帧所需的时间，文件越大通常越久，所以超时随文件大小适当放宽。
      const timeoutMs = Math.min(20000, Math.max(5000, (file.size / (1024 * 1024)) * 300));
      await captureVideoFrame(ctx, objectUrl, timeoutMs);
    }
  } finally {
    URL.revokeObjectURL(objectUrl);
  }

  /** @type Blob */
  const thumbnailBlob = await new Promise((resolve) =>
    canvas.toBlob((blob) => resolve(blob))
  );

  return thumbnailBlob;
}

/**
 * 直接基于一个支持 Range 请求的网络地址生成缩略图，不需要先把整个文件下载到
 * 内存里再解码。用于"重新生成缩略图"这种针对已存在文件的场景——<video> 标签
 * 本身就支持按需分段（Range）请求，只要 srcUrl 指向的接口正确转发 Range 头
 * （本项目的 /raw/ 接口是这样的），浏览器就只会拉取定位到某一帧所需的那部分
 * 数据，而不是整份文件，这对大视频文件明显更快、也更省内存。
 * @param {string} srcUrl
 * @param {string} type MIME 类型，例如 "video/mp4"、"image/png"
 * @param {number} [timeoutMs]
 */
export async function generateThumbnailFromUrl(srcUrl, type, timeoutMs = 15000) {
  if (!type || (!type.startsWith("image/") && !type.startsWith("video/"))) {
    return null;
  }

  const canvas = document.createElement("canvas");
  canvas.width = THUMBNAIL_SIZE;
  canvas.height = THUMBNAIL_SIZE;
  const ctx = canvas.getContext("2d");

  if (type.startsWith("image/")) {
    await captureImageFrame(ctx, srcUrl);
  } else {
    await captureVideoFrame(ctx, srcUrl, timeoutMs);
  }

  return await new Promise((resolve) => canvas.toBlob((blob) => resolve(blob)));
}

/**
 * @param {Blob} blob
 */
export async function blobDigest(blob) {
  const digest = await crypto.subtle.digest("SHA-1", await blob.arrayBuffer());
  const digestArray = Array.from(new Uint8Array(digest));
  const digestHex = digestArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return digestHex;
}

export const SIZE_LIMIT = 100 * 1000 * 1000; // 100MB

// 把 R2 key 逐段 URL 编码后拼成 API 路径（M7）：文件名里的 # ? % 等字符
// 不编码会被浏览器当成 URL 结构解析（# 变锚点、? 变查询串、% 触发解码错误），
// 服务端收到的就是错误的 key。读路径（rawUrl）本来就逐段编码，写路径也要一样。
export function apiPath(key) {
  return key.split("/").map(encodeURIComponent).join("/");
}

/**
 * @param {string} key
 * @param {File} file
 * @param {Record<string, any>} options
 */
export async function multipartUpload(key, file, options) {
  const headers = options?.headers || {};
  headers["content-type"] = file.type;

  const uploadId = await axios
    .post(`/api/write/items/${apiPath(key)}?uploads`, "", { headers })
    .then((res) => res.data.uploadId);
  const totalChunks = Math.ceil(file.size / SIZE_LIMIT);

  const promiseGenerator = function* () {
    for (let i = 1; i <= totalChunks; i++) {
      const chunk = file.slice((i - 1) * SIZE_LIMIT, i * SIZE_LIMIT);
      const searchParams = new URLSearchParams({ partNumber: i, uploadId });
      yield axios
        .put(`/api/write/items/${apiPath(key)}?${searchParams}`, chunk, {
          onUploadProgress(progressEvent) {
            if (typeof options?.onUploadProgress !== "function") return;
            options.onUploadProgress({
              loaded: (i - 1) * SIZE_LIMIT + progressEvent.loaded,
              total: file.size,
            });
          },
        })
        .then((res) => ({
          partNumber: i,
          etag: res.headers.etag,
        }));
    }
  };

  const uploadedParts = [];
  for (const part of promiseGenerator()) {
    const { partNumber, etag } = await part;
    uploadedParts[partNumber - 1] = { partNumber, etag };
  }
  const completeParams = new URLSearchParams({ uploadId });
  await axios.post(`/api/write/items/${apiPath(key)}?${completeParams}`, {
    parts: uploadedParts,
  });
}
