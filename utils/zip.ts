// D2：流式生成 ZIP（文件夹打包下载）。
//
//   - STORE（不压缩）：不需要压缩流，Worker 边读 R2 边写响应，整个 ZIP
//     不进内存；解压时任何工具都支持。
//   - 每个文件用 data descriptor（通用标志第 3 位）：流式写入时 CRC32
//     和大小要到数据写完才知道，先写 0 再补描述符；中央目录在最后，
//     需要每个文件的偏移/CRC/大小（写入过程中记录）。
//   - 只支持 ZIP32（不写 ZIP64）：单个文件和总大小都有 200 MB 上限，
//     远不到 4 GB 边界。
//   - 文件名按 UTF-8 编码（标志第 11 位）。

const CRC_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32Update(crc: number, chunk: Uint8Array): number {
  let c = (crc ^ 0xffffffff) >>> 0;
  for (let i = 0; i < chunk.length; i++) {
    c = CRC_TABLE[(c ^ chunk[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function u16(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff]);
}

function u32(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// DOS 时间（本地时间，秒按 2 秒取整）
function dosDateTime(d: Date): [number, number] {
  const time = ((d.getHours() & 0x1f) << 11) | ((d.getMinutes() & 0x3f) << 5) | ((Math.floor(d.getSeconds() / 2)) & 0x1f);
  const date = (((d.getFullYear() - 1980) & 0x7f) << 9) | (((d.getMonth() + 1) & 0x0f) << 5) | (d.getDate() & 0x1f);
  return [time, date];
}

export interface ZipEntry {
  name: string; // ZIP 内的相对路径
  size: number; // R2 里记录的大小（流式读取后还会再核对）
  // 惰性取体：调用时才打开 R2 对象流（避免一次打开 100 个流）
  openBody: () => Promise<ReadableStream<Uint8Array>>;
}

// 用 TransformStream 实现流式输出：旧版 Workers 运行时（以及本仓库
// wrangler 2.6.2 自带的 miniflare）没有开 streams_enable_constructors，
// new ReadableStream() 会直接抛错；TransformStream 不受此限。
// writer.write() 自带背压：消费者慢时写入会挂起，不会把整个 ZIP
// 缓冲在内存里。
//
// 注意：中央目录的偏移/大小不在流式写入过程中用累加器现算——
// R2 对象不可变，列表给出的大小就是最终大小，所以每个文件的本地头
// 偏移、中央目录偏移和大小都可以事先算好（30 + 文件名长度 + 文件
// 大小 + 16 字节描述符；中央目录每条 46 + 文件名长度）。流式读取
// 后会核对实际字节数和列表大小是否一致，不一致就中止整个响应。
export function createZipStream(entries: ZipEntry[]): ReadableStream<Uint8Array> {
  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
  const writer = writable.getWriter();

  // 事先算好所有偏移（见上）
  const nameBytes = entries.map((e) => new TextEncoder().encode(e.name));
  const headerOffsets: number[] = [];
  {
    let off = 0;
    for (let i = 0; i < entries.length; i++) {
      headerOffsets.push(off);
      off += 30 + nameBytes[i].length + entries[i].size + 16;
    }
  }
  const cdOffset = entries.reduce((s, e, i) => s + 30 + nameBytes[i].length + e.size + 16, 0);
  const cdSize = entries.reduce((s, _e, i) => s + 46 + nameBytes[i].length, 0);
  // CRC32 在流式读取时算出，中央目录在最后才写，需要先存起来
  const entryCrc: number[] = [];

  (async () => {
    try {
      const now = new Date();
      const [dosTime, dosDate] = dosDateTime(now);
      for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        const name = nameBytes[i];
        // 本地文件头（CRC/大小先写 0，见 data descriptor）
        const header = concat(
          u32(0x04034b50),
          u16(20), // 需要版本 2.0
          u16(0x0808), // 标志：第 3 位 data descriptor + 第 11 位 UTF-8 文件名
          u16(0), // 方法 STORE
          u16(dosTime),
          u16(dosDate),
          u32(0), // CRC（未知）
          u32(0), // 压缩后大小（未知）
          u32(0), // 未压缩大小（未知）
          u16(name.length),
          u16(0), // extra 长度
          name
        );
        await writer.write(header);

        let crc = 0;
        let size = 0;
        const body = await entry.openBody();
        const reader = body.getReader();
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            const chunk = value as Uint8Array;
            crc = crc32Update(crc, chunk);
            size += chunk.length;
            await writer.write(chunk);
          }
        } finally {
          reader.releaseLock();
        }
        // 实际字节数必须和列表大小一致（R2 对象不可变，正常不会变）
        if (size !== entry.size) throw new Error(`文件大小变化: ${entry.name}`);
        entryCrc.push(crc);

        // data descriptor（带签名）
        await writer.write(concat(u32(0x08074b50), u32(crc), u32(size), u32(size)));
      }

      for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        const name = nameBytes[i];
        await writer.write(
          concat(
            u32(0x02014b50),
            u16(20), // 制作版本
            u16(20), // 需要版本
            u16(0x0808),
            u16(0),
            u16(dosTime),
            u16(dosDate),
            u32(entryCrc[i]),
            u32(entry.size),
            u32(entry.size),
            u16(name.length),
            u16(0),
            u16(0),
            u16(0), // 磁盘号
            u16(0), // 内部属性
            u32(0), // 外部属性
            u32(headerOffsets[i]),
            name
          )
        );
      }

      await writer.write(
        concat(
          u32(0x06054b50),
          u16(0),
          u16(0),
          u16(entries.length),
          u16(entries.length),
          u32(cdSize),
          u32(cdOffset),
          u16(0)
        )
      );
      await writer.close();
    } catch (e) {
      await writer.abort(e);
    }
  })();

  return readable;
}
