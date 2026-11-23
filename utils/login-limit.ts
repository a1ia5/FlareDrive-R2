// 登录 / Basic 认证的失败计数限流（KV：LOGIN_ATTEMPTS）。
//
// 原先只在 /api/auth/login 里计数，Basic 认证走其它接口（/api/*、/dav/、
// /raw/）时可以无限试密码（F2）。现在把计数抽到这里共享：
//   - login.ts（登录接口）：沿用原来的流程（先查限流 → 校验 → 失败记数 / 成功清零）。
//   - utils/auth.ts 的 getRequestUser()：所有走 Basic 认证的接口都经过它，
//     在校验前先查是否被封禁（被封禁直接返回 null，不做 PBKDF2），
//     校验失败时记一次数。
// R3-2：计数改为 D1 里的原子"先占名额、再校验"（reserve-before-verify）。
// 原来的 KV 读-改-写既不是原子的（并行请求都先读到旧计数，同时开始校验），
// KV 在边缘节点之间还是最终一致的——"每 账号/IP 每小时 5 次"只对串行猜测有效。
// 现在：校验密码之前先对 login_attempts 表做一条
//   INSERT … ON CONFLICT DO UPDATE … RETURNING
// 单语句占一个名额；D1 同一时刻只有一个主库在写，该语句是原子的，也不受边缘
// 节点影响。占到 1–5 号名额的请求才去校验密码，第 6 个起直接拒绝（不做
// PBKDF2）——并行发 30 个不同的猜测，只有 5 个会被校验。校验成功清零、失败
// 保留名额，第 5 次失败写入 30 分钟封禁。
// 没有绑定 D1（DB）时退回原来的 KV 实现（LOGIN_ATTEMPTS，非原子，有并发窗口）；
// D1 出错时也退回 KV，再不行才 fail-open（日志里大声报，不静默）。
// 表 login_attempts 会在首次使用时自动创建（migrations/0002_login_attempts.sql
// 是同一份 DDL，可选手动执行）。

export const LOGIN_LIMIT_CONFIG = {
  MAX_ATTEMPTS: 5, // 最大尝试次数
  BAN_DURATION: 30 * 60, // 封禁时长（秒），30分钟
  ATTEMPT_WINDOW: 60 * 60, // 尝试次数重置窗口（秒），1小时
};

// 获取客户端IP地址
export function getClientIP(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For") ||
    request.headers.get("X-Real-IP") ||
    "unknown"
  );
}

// LOGIN_ATTEMPTS 未绑定时限流是静默关闭的——在日志里大声报一次
// （每个 isolate 只报一次，避免刷屏），并在 README 里列为必绑项。
let warnedNoLoginAttemptsKv = false;
function warnLoginLimitDisabled() {
  if (warnedNoLoginAttemptsKv) return;
  warnedNoLoginAttemptsKv = true;
  console.error(
    "[SECURITY] 登录限流已关闭（fail-open）：DB（D1）和 LOGIN_ATTEMPTS（KV）都没有绑定或都不可用，同一账号/IP 可无限尝试密码。请在 Cloudflare Pages 设置里绑定 D1 数据库 DB（推荐，原子限流）和/或 LOGIN_ATTEMPTS KV 命名空间。"
  );
}

// N10：KV 本身出错（配额、服务异常）时也要 fail-open，不能让一次 KV
// 读失败把所有认证请求都变成 500。只报一次，避免出错期间刷屏。
let warnedKvError = false;
function warnKvError(error) {
  if (warnedKvError) return;
  warnedKvError = true;
  console.error("[SECURITY] LOGIN_ATTEMPTS KV 出错，登录限流已临时关闭（fail-open）：", error);
}

// ---------------------------------------------------------------------------
// KV 实现（没有 D1 或 D1 出错时的退路；非原子）
// 键由调用方给：登录用 login_limit:<用户名>:<IP>，分享密码用
// share_limit:<分享ID>:<IP>，见 F6。
// ---------------------------------------------------------------------------

async function checkLimitByKey(env, key) {
  if (!env.LOGIN_ATTEMPTS) {
    warnLoginLimitDisabled();
    return { allowed: true, remainingAttempts: LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS };
  }

  let limitData;
  try {
    limitData = await env.LOGIN_ATTEMPTS.get(key);
  } catch (error) {
    // N10：KV 读失败时 fail-open，不阻塞认证（与"未绑定"同一处理）。
    warnKvError(error);
    return { allowed: true, remainingAttempts: LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS };
  }

  if (!limitData) {
    return { allowed: true, remainingAttempts: LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS };
  }

  const data = JSON.parse(limitData);
  const now = Math.floor(Date.now() / 1000);

  // 检查是否在封禁期内
  if (data.bannedUntil && now < data.bannedUntil) {
    const remainingBanTime = data.bannedUntil - now;
    return {
      allowed: false,
      banned: true,
      remainingBanTime,
      message: `账户已被临时锁定，请在 ${Math.ceil(remainingBanTime / 60)} 分钟后重试`,
    };
  }

  // 检查尝试次数是否超限
  if (data.attempts >= LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS) {
    // 检查是否超过重置窗口
    if (now - data.firstAttempt > LOGIN_LIMIT_CONFIG.ATTEMPT_WINDOW) {
      // 重置计数（删失败也只影响下一次重算，不阻塞本次放行）
      try {
        await env.LOGIN_ATTEMPTS.delete(key);
      } catch (error) {
        warnKvError(error);
      }
      return { allowed: true, remainingAttempts: LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS };
    } else {
      // 设置封禁
      const bannedUntil = now + LOGIN_LIMIT_CONFIG.BAN_DURATION;
      try {
        await env.LOGIN_ATTEMPTS.put(
          key,
          JSON.stringify({
            ...data,
            bannedUntil,
          }),
          { expirationTtl: LOGIN_LIMIT_CONFIG.BAN_DURATION + 3600 }
        );
      } catch (error) {
        // N10：封禁写不进去也按本次封禁返回（下次请求会重新算到这里，
        // 不会因为一次写失败就放过攻击者）。
        warnKvError(error);
      }

      return {
        allowed: false,
        banned: true,
        remainingBanTime: LOGIN_LIMIT_CONFIG.BAN_DURATION,
        message: `登录尝试次数过多，账户已被锁定 ${LOGIN_LIMIT_CONFIG.BAN_DURATION / 60} 分钟`,
      };
    }
  }

  return {
    allowed: true,
    remainingAttempts: LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS - data.attempts,
  };
}

async function recordFailureByKey(env, key) {
  if (!env.LOGIN_ATTEMPTS) {
    return;
  }

  let limitData;
  try {
    limitData = await env.LOGIN_ATTEMPTS.get(key);
  } catch (error) {
    // N10：读不到旧计数就不记这次（fail-open），不要覆盖掉已有记录。
    warnKvError(error);
    return;
  }
  const now = Math.floor(Date.now() / 1000);

  let data;
  if (limitData) {
    data = JSON.parse(limitData);
    // 如果超过重置窗口，重新开始计数
    if (now - data.firstAttempt > LOGIN_LIMIT_CONFIG.ATTEMPT_WINDOW) {
      data = { attempts: 1, firstAttempt: now, lastAttempt: now };
    } else {
      data.attempts += 1;
      data.lastAttempt = now;
    }
  } else {
    data = { attempts: 1, firstAttempt: now, lastAttempt: now };
  }

  // 设置过期时间为封禁时长 + 1小时的缓冲
  const ttl = LOGIN_LIMIT_CONFIG.BAN_DURATION + 3600;
  try {
    await env.LOGIN_ATTEMPTS.put(key, JSON.stringify(data), { expirationTtl: ttl });
  } catch (error) {
    // N10：写失败就丢这次计数（fail-open），下次请求重新读。
    warnKvError(error);
  }
}

// ---------------------------------------------------------------------------
// D1 实现（主路径，原子）
// ---------------------------------------------------------------------------

let warnedD1Error = false;
function warnD1Error(error) {
  if (warnedD1Error) return;
  warnedD1Error = true;
  console.error("[SECURITY] 登录限流的 D1 表出错，退回 KV 限流（非原子）：", error);
}

let tableReady: Promise<void> | null = null;
function ensureTable(db): Promise<void> {
  if (!tableReady) {
    tableReady = db
      .prepare(
        "CREATE TABLE IF NOT EXISTS login_attempts (" +
          "k TEXT PRIMARY KEY, attempts INTEGER NOT NULL, window_start INTEGER NOT NULL, " +
          "last_attempt INTEGER NOT NULL, banned_until INTEGER NOT NULL DEFAULT 0)"
      )
      .run()
      .then(() => undefined, (e) => {
        tableReady = null; // 下次再试
        throw e;
      });
  }
  return tableReady;
}

// 键（login_limit:<用户名>:<IP> / share_limit:<ID>:<IP>）取 SHA-256 作为 D1 主键：
// 定长、不含用户输入的原文（用户名可以任意长）。
async function hashKey(key: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface AttemptReservation {
  allowed: boolean;
  banned?: boolean;
  remainingBanTime?: number;
  message?: string;
  attempts?: number; // 占到的名额序号（1 起）
  backend: "d1" | "kv" | "none";
  key: string;
}

const lockedMessage = (seconds: number) => `账户已被临时锁定，请在 ${Math.ceil(seconds / 60)} 分钟后重试`;

// 原子占一个名额。单条语句同时完成"窗口/封禁到期重置""计数加一""读回结果"；
// SQLite 的 SET 表达式都按旧行取值，所以各列的 CASE 里反复用旧的 banned_until /
// window_start 是对的。封禁期内不加计数、不延长封禁。
async function d1Reserve(env, key: string): Promise<AttemptReservation> {
  await ensureTable(env.DB);
  const now = Math.floor(Date.now() / 1000);
  const W = LOGIN_LIMIT_CONFIG.ATTEMPT_WINDOW;
  const row: any = await env.DB.prepare(
    `INSERT INTO login_attempts (k, attempts, window_start, last_attempt, banned_until)
     VALUES (?1, 1, ?2, ?2, 0)
     ON CONFLICT(k) DO UPDATE SET
       attempts = CASE
         WHEN banned_until > ?2 THEN attempts
         WHEN banned_until > 0 OR ?2 - window_start > ?3 THEN 1
         ELSE attempts + 1 END,
       window_start = CASE
         WHEN banned_until <= ?2 AND (banned_until > 0 OR ?2 - window_start > ?3) THEN ?2
         ELSE window_start END,
       last_attempt = ?2,
       banned_until = CASE WHEN banned_until > 0 AND banned_until <= ?2 THEN 0 ELSE banned_until END
     RETURNING attempts, banned_until`
  )
    .bind(await hashKey(key), now, W)
    .first();
  if (!row) throw new Error("login_attempts upsert returned no row");

  // 顺手清理过期记录（约 2% 的请求），表不会被乱填的用户名撑大。
  if (Math.random() < 0.02) {
    try {
      await env.DB.prepare("DELETE FROM login_attempts WHERE banned_until <= ?1 AND window_start < ?1 - ?2").bind(now, W).run();
    } catch {
      // 清理失败不影响限流
    }
  }

  if (row.banned_until > now) {
    const remaining = row.banned_until - now;
    return { allowed: false, banned: true, remainingBanTime: remaining, message: lockedMessage(remaining), attempts: row.attempts, backend: "d1", key };
  }
  if (row.attempts > LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS) {
    // 名额已被前 5 个请求占满、封禁还没写下来（它在第 5 次失败时写）：同样拒绝。
    return {
      allowed: false,
      banned: true,
      remainingBanTime: LOGIN_LIMIT_CONFIG.BAN_DURATION,
      message: `登录尝试次数过多，账户已被锁定 ${LOGIN_LIMIT_CONFIG.BAN_DURATION / 60} 分钟`,
      attempts: row.attempts,
      backend: "d1",
      key,
    };
  }
  return { allowed: true, attempts: row.attempts, backend: "d1", key };
}

async function reserveByKey(env, key: string): Promise<AttemptReservation> {
  if (env.DB) {
    try {
      return await d1Reserve(env, key);
    } catch (error) {
      warnD1Error(error);
    }
  }
  if (env.LOGIN_ATTEMPTS) {
    const r: any = await checkLimitByKey(env, key);
    return { ...r, backend: "kv", key };
  }
  warnLoginLimitDisabled();
  return { allowed: true, backend: "none", key };
}

// 校验失败后调用：名额不退。占到最后一个名额的那次失败写入封禁。
async function failureByKey(env, key: string, reservation?: AttemptReservation) {
  if (reservation?.backend === "d1") {
    try {
      await ensureTable(env.DB);
      const now = Math.floor(Date.now() / 1000);
      const last = (reservation?.attempts ?? 0) >= LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS;
      if (last) {
        await env.DB.prepare("UPDATE login_attempts SET banned_until = ?2 + ?3 WHERE k = ?1 AND banned_until <= ?2")
          .bind(await hashKey(key), now, LOGIN_LIMIT_CONFIG.BAN_DURATION)
          .run();
        return {
          banned: true,
          remainingBanTime: LOGIN_LIMIT_CONFIG.BAN_DURATION,
          message: `登录尝试次数过多，账户已被锁定 ${LOGIN_LIMIT_CONFIG.BAN_DURATION / 60} 分钟`,
        };
      }
      return { banned: false };
    } catch (error) {
      warnD1Error(error);
      return { banned: false };
    }
  }
  if (reservation?.backend === "kv") {
    await recordFailureByKey(env, key);
    const after: any = await checkLimitByKey(env, key);
    return after.allowed ? { banned: false } : { banned: true, remainingBanTime: after.remainingBanTime, message: after.message };
  }
  return { banned: false };
}

// 校验成功 / 其它情况需要清零：D1 行和 KV 键都删（任一出错只告警）。
async function clearByKey(env, key: string) {
  if (env.DB) {
    try {
      await ensureTable(env.DB);
      await env.DB.prepare("DELETE FROM login_attempts WHERE k = ?1").bind(await hashKey(key)).run();
    } catch (error) {
      warnD1Error(error);
    }
  }
  if (env.LOGIN_ATTEMPTS) {
    try {
      await env.LOGIN_ATTEMPTS.delete(key);
    } catch (error) {
      // N10：删失败不影响登录成功本身，记录靠 TTL 自然过期。
      warnKvError(error);
    }
  }
}

// 校验过程中出了基础设施错误（不是密码错）：把占的名额还回去，
// 否则 D1/依赖故障期间合法用户会被自己的重试锁住。
async function releaseByKey(env, reservation?: AttemptReservation) {
  if (reservation?.backend !== "d1") return;
  try {
    await env.DB.prepare("UPDATE login_attempts SET attempts = MAX(attempts - 1, 0) WHERE k = ?1")
      .bind(await hashKey(reservation.key))
      .run();
  } catch (error) {
    warnD1Error(error);
  }
}

export const loginLimitKey = (username: string, clientIP: string) => `login_limit:${username}:${clientIP}`;
export const shareLimitKey = (shareId: string, clientIP: string) => `share_limit:${shareId}:${clientIP}`;

// ---- 登录 / Basic 认证 ----
export const reserveAuthAttempt = (env, username: string, clientIP: string) => reserveByKey(env, loginLimitKey(username, clientIP));
export const recordAuthFailure = (env, username: string, clientIP: string, reservation?: AttemptReservation) =>
  failureByKey(env, loginLimitKey(username, clientIP), reservation);
export const clearAuthLimit = (env, username: string, clientIP: string) => clearByKey(env, loginLimitKey(username, clientIP));
export const releaseAuthAttempt = (env, reservation?: AttemptReservation) => releaseByKey(env, reservation);

// ---------------------------------------------------------------------------
// F6：分享访问密码的试错限流（与登录限流共用同一套机制和阈值，键不同）。
// 分享 ID 是 10 位随机字符，猜不到；但拿到链接的人可以无限试密码。
// 键：share_limit:<分享ID>:<IP>。两个后端都没有时不限流（fail-open）。
// ---------------------------------------------------------------------------
export const reserveSharePasswordAttempt = (env, shareId: string, clientIP: string) => reserveByKey(env, shareLimitKey(shareId, clientIP));
export const recordSharePasswordFailure = (env, shareId: string, clientIP: string, reservation?: AttemptReservation) =>
  failureByKey(env, shareLimitKey(shareId, clientIP), reservation);
export const clearSharePasswordLimit = (env, shareId: string, clientIP: string) => clearByKey(env, shareLimitKey(shareId, clientIP));

// ---------------------------------------------------------------------------
// 管理接口用：读 / 删某个键的限流记录（ban-status / unban）。
// ---------------------------------------------------------------------------
export interface LimitRecord {
  attempts: number;
  firstAttempt: number;
  lastAttempt: number;
  bannedUntil: number;
  backend: "d1" | "kv";
}

export async function readLimitRecord(env, key: string): Promise<LimitRecord | null> {
  if (env.DB) {
    try {
      await ensureTable(env.DB);
      const row: any = await env.DB.prepare("SELECT attempts, window_start, last_attempt, banned_until FROM login_attempts WHERE k = ?1")
        .bind(await hashKey(key))
        .first();
      if (row) {
        return { attempts: row.attempts, firstAttempt: row.window_start, lastAttempt: row.last_attempt, bannedUntil: row.banned_until, backend: "d1" };
      }
    } catch (error) {
      warnD1Error(error);
    }
  }
  if (env.LOGIN_ATTEMPTS) {
    const raw = await env.LOGIN_ATTEMPTS.get(key);
    if (raw) {
      const d = JSON.parse(raw);
      return { attempts: d.attempts, firstAttempt: d.firstAttempt, lastAttempt: d.lastAttempt, bannedUntil: d.bannedUntil || 0, backend: "kv" };
    }
  }
  return null;
}

export const limiterEnabled = (env) => !!(env.DB || env.LOGIN_ATTEMPTS);
export const limiterBackend = (env): "d1" | "kv" | "none" => (env.DB ? "d1" : env.LOGIN_ATTEMPTS ? "kv" : "none");

export async function deleteLimitRecord(env, key: string): Promise<void> {
  await clearByKey(env, key);
}
