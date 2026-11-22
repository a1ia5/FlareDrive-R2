// 登录 / Basic 认证的失败计数限流。
//
// v28（R3-2）：计数从 KV 搬到了 R2。KV 只有 read-modify-write，没有原子
// 操作——30 个并行请求读到的都是旧计数，全放行。R2 的 put 支持 onlyIf
// 条件写（etagMatches / etagDoesNotMatch "*"，v19 已在用），读→算→
// 条件写 + 冲突重试就是一段 CAS，计数不会丢，并行 burst 里第 6 个请求
// 读到的就是已封禁的状态。
//
// 关键流程（原来是"先查、后校验、失败再记数"，现在是"先原子认领、再校验"）：
//   - 认领（claimAuthAttempt / claimSharePasswordAttempt）：把"这次尝试"
//     原子地记一次数，并返回 verdict。已经封禁的直接返回不通过，不做
//     PBKDF2；这次就是第 5 次的，返回 remainingAttempts = 0，调用方据
//     此决定失败时返回 401 还是 429。
//   - 成功后清零（clearAuthLimit / clearSharePasswordLimit）：认领已经
//     把这次记了一次，成功必须清掉，否则成功请求也会把计数顶满然后把
//     自己封掉。
//   - 失败时不用再另记一次数（已经在认领时记过了）。
//
// 计数对象存在内部前缀 _$flaredrive$/login-limits/ 下（isInternalPath
// 挡住所有读路径，见 utils/auth.ts）；键是逻辑键的 encodeURIComponent
// （防 "/" 等字符坏 key）。记录沿用原来 KV 的 JSON 形状
// { attempts, firstAttempt, lastAttempt, bannedUntil? }，ban-status 的
// 解析不用改。
//
// 代价：每次认证都要先认领（一次 get + 一次条件 put），成功后再清掉
// （一次 delete）。个人站点的量完全吃得下；换来的是并行 burst 也会被
// 挡在 5 次。R2 出错或重试耗尽时 fail-open（只记一次日志），不阻塞认证。
//
// LOGIN_ATTEMPTS KV 不再使用（部署时若已绑，可以删掉；留着也无害）。
// 注意：切换后 KV 里残留的封禁记录会被丢弃（封禁本来就只有 30 分钟）。

export const LOGIN_LIMIT_CONFIG = {
  MAX_ATTEMPTS: 5, // 最大尝试次数
  BAN_DURATION: 30 * 60, // 封禁时长（秒），30分钟
  ATTEMPT_WINDOW: 60 * 60, // 尝试次数重置窗口（秒），1小时
};

// R2 条件写冲突时最多重试次数。每次重试都会重新读，burst 里每一轮
// 至少有一个请求能写成功；8 次足够收敛（实测 30 并行也用不满）。
const MAX_CAS_RETRIES = 8;

const LIMIT_PREFIX = "_$flaredrive$/login-limits/";

function limitObjectKey(logicalKey: string): string {
  return LIMIT_PREFIX + encodeURIComponent(logicalKey) + ".json";
}

// 获取客户端IP地址
export function getClientIP(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For") ||
    request.headers.get("X-Real-IP") ||
    "unknown"
  );
}

// R2 本身出错 / 存储桶未绑定时限流 fail-open——在日志里大声报一次
// （每个 isolate 只报一次，避免刷屏），不阻塞认证（与原来 N10 的
// 处理一致：一次存储失败不能把所有认证请求都变成 500）。
let warnedR2Error = false;
function warnR2Error(error) {
  if (warnedR2Error) return;
  warnedR2Error = true;
  console.error("[SECURITY] 登录限流存储出错，限流已临时关闭（fail-open）：", error);
}

// CAS 重试耗尽（持续冲突）时 fail-open，同样只报一次。
let warnedCasExhausted = false;
function warnCasExhausted() {
  if (warnedCasExhausted) return;
  warnedCasExhausted = true;
  console.error("[SECURITY] 登录限流 CAS 重试耗尽，限流已临时关闭（fail-open）：并行冲突过多");
}

function failOpen() {
  return { allowed: true, remainingAttempts: LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS };
}

function bannedResponse(remainingBanTime: number) {
  return {
    allowed: false,
    banned: true,
    remainingBanTime,
    message: `账户已被临时锁定，请在 ${Math.ceil(remainingBanTime / 60)} 分钟后重试`,
  };
}

function lockedMessage() {
  return `登录尝试次数过多，账户已被锁定 ${LOGIN_LIMIT_CONFIG.BAN_DURATION / 60} 分钟`;
}

// 条件写一次：obj 存在时按它的 etag 写，不存在时按"不存在"写。
// 返回 { ok }；ok=false 且 error 为空表示条件没满足（别人先写了），
// 调用方重读重试；error 非空表示 R2 本身出错，调用方 fail-open。
async function casPut(bucket, r2key: string, next: any, obj: any) {
  try {
    const putOptions: any = { httpMetadata: { contentType: "application/json" } };
    if (obj) {
      if (!obj.httpEtag) return { ok: false, error: new Error("missing etag on limit record") };
      putOptions.onlyIf = { etagMatches: obj.httpEtag };
    } else {
      putOptions.onlyIf = { etagDoesNotMatch: "*" };
    }
    const written = await bucket.put(r2key, JSON.stringify(next), putOptions);
    return { ok: written !== null && written !== undefined };
  } catch (error) {
    return { ok: false, error };
  }
}

// 核心：原子认领一次尝试。返回值沿用原来 checkAuthLimit 的形状：
// allowed=false 表示已被封禁；allowed=true 时 remainingAttempts 是
// 这次之后还剩的次数（0 表示这次就是第 5 次，封禁已经生效）。
async function claimAttempt(bucket, logicalKey: string) {
  if (!bucket) {
    warnR2Error(new Error("no bucket bound"));
    return failOpen();
  }
  const r2key = limitObjectKey(logicalKey);
  const now = Math.floor(Date.now() / 1000);
  for (let round = 0; round < MAX_CAS_RETRIES; round++) {
    let obj = null;
    let data = null;
    try {
      obj = await bucket.get(r2key);
      if (obj) {
        try {
          data = JSON.parse(await obj.text());
        } catch {
          data = null; // 记录损坏：按空记录处理，下面会覆盖写掉
        }
      }
    } catch (error) {
      warnR2Error(error);
      return failOpen();
    }

    if (!data || typeof data.attempts !== "number" || typeof data.firstAttempt !== "number") {
      data = { attempts: 0, firstAttempt: now, lastAttempt: now };
    }

    // 先看封禁、再看窗口（顺序不能反：5 次尝试拖得久时，封禁可能比
    // 1 小时窗口晚到期；先重置窗口会把还没到期的封禁提前放掉）。
    if (data.bannedUntil && now < data.bannedUntil) {
      return bannedResponse(data.bannedUntil - now);
    }
    if (now - data.firstAttempt > LOGIN_LIMIT_CONFIG.ATTEMPT_WINDOW) {
      // 窗口过了：重新计数（旧记录就地覆盖，不用先删）。
      data = { attempts: 0, firstAttempt: now, lastAttempt: now };
    }

    if (data.attempts >= LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS) {
      // 已到上限但没写 bannedUntil（旧记录/脏数据）：现在就封禁。
      const next = {
        ...data,
        attempts: data.attempts + 1,
        lastAttempt: now,
        bannedUntil: now + LOGIN_LIMIT_CONFIG.BAN_DURATION,
      };
      const written = await casPut(bucket, r2key, next, obj);
      if (!written.ok) {
        if (written.error) {
          warnR2Error(written.error);
          return failOpen();
        }
        continue; // 冲突：重读重试
      }
      return {
        allowed: false,
        banned: true,
        remainingBanTime: LOGIN_LIMIT_CONFIG.BAN_DURATION,
        message: lockedMessage(),
      };
    }

    const next = { ...data, attempts: data.attempts + 1, lastAttempt: now };
    if (next.attempts >= LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS) {
      next.bannedUntil = now + LOGIN_LIMIT_CONFIG.BAN_DURATION;
    }
    const written = await casPut(bucket, r2key, next, obj);
    if (!written.ok) {
      if (written.error) {
        warnR2Error(written.error);
        return failOpen();
      }
      continue; // 冲突：重读重试
    }
    const remainingAttempts = Math.max(0, LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS - next.attempts);
    return {
      allowed: true,
      remainingAttempts,
      ...(next.attempts >= LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS
        ? { remainingBanTime: LOGIN_LIMIT_CONFIG.BAN_DURATION, message: lockedMessage() }
        : {}),
    };
  }
  warnCasExhausted();
  return failOpen();
}

// 认领一次登录尝试（登录接口、authenticateBasic 共用）。
export async function claimAuthAttempt(bucket, username, clientIP) {
  return claimAttempt(bucket, `login_limit:${username}:${clientIP}`);
}

// 登录成功时清掉计数记录（认领已经把这次记了一次，必须清）。
export async function clearAuthLimit(bucket, username, clientIP) {
  if (!bucket) return;
  try {
    await bucket.delete(limitObjectKey(`login_limit:${username}:${clientIP}`));
  } catch (error) {
    warnR2Error(error);
  }
}

// 读出计数记录（ban-status 用；没有记录返回 null）。
export async function getLimitState(bucket, username, clientIP) {
  if (!bucket) return null;
  try {
    const obj = await bucket.get(limitObjectKey(`login_limit:${username}:${clientIP}`));
    if (!obj) return null;
    const data = JSON.parse(await obj.text());
    if (!data || typeof data.attempts !== "number") return null;
    return data;
  } catch (error) {
    warnR2Error(error);
    return null;
  }
}

// 解封一个用户在所有 IP 上的限制（R2 可以按前缀 list，KV 做不到）。
// 返回删掉的条数。
export async function clearAllAuthLimitsForUser(bucket, username) {
  if (!bucket) return 0;
  const prefix = LIMIT_PREFIX + encodeURIComponent(`login_limit:${username}:`);
  let count = 0;
  try {
    let cursor: string | undefined = undefined;
    for (let page = 0; page < 20; page++) {
      const list = await bucket.list({ prefix, cursor });
      for (const o of list.objects || []) {
        await bucket.delete(o.key);
        count++;
      }
      if (!list.truncated) break;
      cursor = list.cursor;
    }
  } catch (error) {
    warnR2Error(error);
  }
  return count;
}

// ---------------------------------------------------------------------------
// F6：分享访问密码的试错限流（与登录限流同一套 R2 存储和阈值，键不同）。
// 分享 ID 是 10 位随机字符，猜不到；但拿到链接的人可以无限试密码。
// 键：share_limit:<分享ID>:<IP>。
// ---------------------------------------------------------------------------

// 认领一次分享密码尝试。
export async function claimSharePasswordAttempt(bucket, shareId, clientIP) {
  return claimAttempt(bucket, `share_limit:${shareId}:${clientIP}`);
}

// 分享密码验证通过时清掉计数记录（与登录成功清零同理）。
export async function clearSharePasswordLimit(bucket, shareId, clientIP) {
  if (!bucket) return;
  try {
    await bucket.delete(limitObjectKey(`share_limit:${shareId}:${clientIP}`));
  } catch (error) {
    warnR2Error(error);
  }
}
