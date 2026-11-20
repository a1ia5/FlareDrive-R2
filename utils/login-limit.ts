// 登录 / Basic 认证的失败计数限流（KV：LOGIN_ATTEMPTS）。
//
// 原先只在 /api/auth/login 里计数，Basic 认证走其它接口（/api/*、/dav/、
// /raw/）时可以无限试密码（F2）。现在把计数抽到这里共享：
//   - login.ts（登录接口）：沿用原来的流程（先查限流 → 校验 → 失败记数 / 成功清零）。
//   - utils/auth.ts 的 getRequestUser()：所有走 Basic 认证的接口都经过它，
//     在校验前先查是否被封禁（被封禁直接返回 null，不做 PBKDF2），
//     校验失败时记一次数。
// KV 键格式与原来一致（login_limit:<用户名>:<IP>），ban-status / unban
// 接口直接读同一个键，不用改。LOGIN_ATTEMPTS 未绑定时限流静默关闭
// （只在日志里报一次），不阻塞登录——与原来行为一致。

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
    "[SECURITY] LOGIN_ATTEMPTS KV 未绑定，登录限流已关闭：同一账号/IP 可无限尝试密码。请在 Cloudflare Pages 设置里绑定 LOGIN_ATTEMPTS KV 命名空间。"
  );
}

// 检查用户是否被封禁
export async function checkAuthLimit(env, username, clientIP) {
  if (!env.LOGIN_ATTEMPTS) {
    warnLoginLimitDisabled();
    return { allowed: true, remainingAttempts: LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS };
  }

  const key = `login_limit:${username}:${clientIP}`;
  const limitData = await env.LOGIN_ATTEMPTS.get(key);

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
      // 重置计数
      await env.LOGIN_ATTEMPTS.delete(key);
      return { allowed: true, remainingAttempts: LOGIN_LIMIT_CONFIG.MAX_ATTEMPTS };
    } else {
      // 设置封禁
      const bannedUntil = now + LOGIN_LIMIT_CONFIG.BAN_DURATION;
      await env.LOGIN_ATTEMPTS.put(
        key,
        JSON.stringify({
          ...data,
          bannedUntil,
        }),
        { expirationTtl: LOGIN_LIMIT_CONFIG.BAN_DURATION + 3600 }
      );

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

// 记录一次认证失败
export async function recordAuthFailure(env, username, clientIP) {
  if (!env.LOGIN_ATTEMPTS) {
    return;
  }

  const key = `login_limit:${username}:${clientIP}`;
  const limitData = await env.LOGIN_ATTEMPTS.get(key);
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
  await env.LOGIN_ATTEMPTS.put(key, JSON.stringify(data), { expirationTtl: ttl });
}

// 清除登录限制记录（登录成功时调用）
export async function clearAuthLimit(env, username, clientIP) {
  if (!env.LOGIN_ATTEMPTS) {
    return;
  }

  const key = `login_limit:${username}:${clientIP}`;
  await env.LOGIN_ATTEMPTS.delete(key);
}
