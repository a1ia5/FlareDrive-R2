import { verifyD1Credentials, hasD1 } from "./d1auth";
import { getClientIP, reserveAuthAttempt, recordAuthFailure, clearAuthLimit, releaseAuthAttempt } from "./login-limit";

// ---------------------------------------------------------------------------
// 权限模型（所有接口共用这一套，不要在各个接口里再各写一份）
//
//   读：  已登录且目录权限匹配；或者路径在 GUEST 目录下（公开只读）
//   写：  必须已登录、非只读、目录权限匹配。GUEST 目录对已登录的可写用户
//         也开放写入，但**匿名访客永远不能写**。
//   内部：_$flaredrive$/ 下只有 thumbnails/ 可以被接口访问，其余（例如自动
//         生成的签名密钥）任何账户都读写不到。
//
// 2026-11 安全修复：此前 get_auth_status() 在检查 Authorization 之前就对
// GUEST 目录直接 return true，导致任何人不登录就能对 GUEST 目录（例如
// public/）执行 PUT / DELETE。现在访客分支只存在于"读"判断里。
// ---------------------------------------------------------------------------

export const INTERNAL_PREFIX = "_$flaredrive$/";
export const THUMBNAIL_PREFIX = "_$flaredrive$/thumbnails/";
export const FOLDER_MARKER = "_$folder$";

const THUMBNAIL_KEY_RE = /^_\$flaredrive\$\/thumbnails\/[0-9a-f]{40}\.png$/;

export interface UserInfo {
    exists: boolean;
    permissions: string[];
    isReadOnly: boolean;
    isAdmin: boolean;
    actualAccount: string;
    username: string;
    source: "d1" | "env";
}

// 把权限项规范成"目录前缀"：非 "*" 的项一律以 "/" 结尾，
// 避免权限 "docs" 意外匹配到 "docs-private/..."。
function normalizePrefix(p: string): string {
    const t = (p || "").trim();
    if (!t || t === "*") return t;
    return t.endsWith("/") ? t : t + "/";
}

function matchPrefixes(prefixes: string[], path: string): boolean {
    for (const raw of prefixes) {
        const p = normalizePrefix(raw);
        if (!p) continue;
        if (p === "*") return true;
        if (path.startsWith(p)) return true;
    }
    return false;
}

export function getGuestDirs(env): string[] {
    const guestEnv = env["GUEST"] || env["guest"];
    if (!guestEnv) return [];
    return String(guestEnv).split(",").map(normalizePrefix).filter(Boolean);
}

// 是否允许匿名访客"浏览目录列表"。默认不允许：GUEST 目录里的文件仍然可以
// 凭直链公开下载，但不登录无法枚举有哪些文件。设置 GUEST_LIST=true 可恢复
// 旧版"访客可直接浏览 GUEST 目录"的行为。
export function guestListingEnabled(env): boolean {
    const v = String(env["GUEST_LIST"] || env["guest_list"] || "").toLowerCase();
    return v === "true" || v === "1" || v === "yes";
}

export function isInternalPath(path: string): boolean {
    return path.startsWith(INTERNAL_PREFIX) || path === INTERNAL_PREFIX.slice(0, -1);
}

export function isThumbnailKey(path: string): boolean {
    return THUMBNAIL_KEY_RE.test(path);
}

// R2 的 key 是不透明字符串，"a/../b" 不会被当成路径解析，但它会让
// "startsWith(权限前缀)" 这种判断和用户看到的目录结构对不上，直接拒绝。
export function isSafeKey(path: string): boolean {
    if (typeof path !== "string" || path.length === 0 || path.length > 1024) return false;
    if (path.startsWith("/")) return false;
    if (/[\u0000-\u001f\u007f]/.test(path)) return false;
    const segments = path.split("/");
    for (let i = 0; i < segments.length; i++) {
        const s = segments[i];
        if (s === "." || s === "..") return false;
        // 允许末尾的空段（目录写法 "a/b/"），不允许中间出现 "a//b"
        if (s === "" && i !== segments.length - 1) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// 账户解析
// ---------------------------------------------------------------------------

// 同一个 isolate 内的短时缓存：每次校验 D1 账户都要做一次 10 万轮 PBKDF2，
// 而 WebDAV 客户端、文件列表、缩略图上传等会在短时间内发起大量请求。
// 只缓存"校验通过"的结果，key 是账户串的 SHA-256（不保存明文）。
// 代价：改密码后，旧密码在同一个 isolate 上最多还能用 CACHE_TTL_MS。
const CACHE_TTL_MS = 30_000;
const CACHE_MAX = 200;
const accountCache = new Map<string, { at: number; info: UserInfo }>();

async function sha256Hex(text: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function clearAccountCache(): void {
    accountCache.clear();
}

// 30 秒内已校验通过的账户串：命中说明凭据本来就是对的，不是"猜测"，
// 不需要（也不应该）再占限流名额。
async function getCachedAccount(account: string): Promise<UserInfo | null> {
    const cached = accountCache.get(await sha256Hex(account));
    return cached && Date.now() - cached.at < CACHE_TTL_MS ? cached.info : null;
}

// 解析并校验 "username:password"。优先查 D1，查不到再回退到旧版环境变量账户
// （变量名 "user:pass" 可读写，"user:pass:r" 只读，值为逗号分隔的目录列表）。
export async function resolveAccount(account: string, context): Promise<UserInfo> {
    const sepIndex = account.indexOf(":");
    const username = sepIndex >= 0 ? account.slice(0, sepIndex) : account;
    const password = sepIndex >= 0 ? account.slice(sepIndex + 1) : "";

    const cacheKey = await sha256Hex(account);
    const cached = accountCache.get(cacheKey);
    if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.info;

    let info: UserInfo | null = null;

    if (hasD1(context) && username) {
        const d1User = await verifyD1Credentials(context, username, password);
        if (d1User) {
            info = {
                exists: true,
                permissions: d1User.permissions,
                isReadOnly: d1User.isReadOnly,
                isAdmin: d1User.isAdmin,
                actualAccount: account,
                username,
                source: "d1",
            };
        }
    }

    if (!info) {
        let isReadOnly = false;
        let permissions: string[] | null = null;

        // 账户串里必须有 ":"，否则 "GUEST"、"BUCKET" 这类普通环境变量名
        // 会被当成一个没有密码的账户。
        if (sepIndex > 0) {
            // N1：账户串以 ":r" 结尾时不能再当成读写账户查——否则只读账户
            // （环境变量名本身就是 "user:pass:r"）用密码 "pass:r" 登录会被
            // 命中，直接拿到读写权限。读写账户的密码本身也不能以 ":r"
            // 结尾（与只读命名撞了，无法区分）；这类账户请改用 D1。
            const rw = account.endsWith(":r") ? undefined : context.env[account];
            const ro = context.env[account + ":r"];
            if (typeof rw === "string") {
                permissions = rw.split(",");
            } else if (typeof ro === "string") {
                permissions = ro.split(",");
                isReadOnly = true;
            }
        }

        info = {
            exists: !!permissions,
            permissions: permissions || [],
            isReadOnly,
            // 账户管理能力只来自 D1 里 is_admin = 1 的账户，
            // 环境变量账户即使配置了 "*" 也只是"能读写所有目录"。
            isAdmin: false,
            actualAccount: account,
            username,
            source: "env",
        };
    }

    if (info.exists) {
        if (accountCache.size >= CACHE_MAX) accountCache.clear();
        accountCache.set(cacheKey, { at: Date.now(), info });
    }
    return info;
}

// N2：供那些自己解析 Basic 头、不走 getRequestUser 的接口使用——
// 与 getRequestUser 完全相同的限流逻辑。
// R3-2：先在 D1 里原子占一个名额再校验（见 utils/login-limit.ts），占不到
// （已封禁，或名额被并行请求占满）直接拒绝、不做 PBKDF2；校验成功清零，
// 失败保留名额（第 5 次失败写 30 分钟封禁）。30 秒内校验通过的凭据（缓存
// 命中）不占名额。同一个 isolate 里"同 IP + 同一凭据"的并行请求合并成一次
// 校验（只占一个名额），合法客户端并发发多个请求不会被当成多次猜测。
// 返回 null 表示未登录/密码错/已被封禁（调用方统一按 401/403 处理，
// 不区分原因，避免泄露"密码错"还是"被封禁"）。
// login.ts 不用它（登录接口被封禁时要返回 429 和提示）。
const inflightAuth = new Map<string, Promise<{ info: UserInfo | null; banned: boolean }>>();

async function authenticateUncached(context, account: string, username: string, clientIP: string) {
    const reservation = await reserveAuthAttempt(context.env, username, clientIP);
    if (!reservation.allowed) return { info: null, banned: true };
    let info: UserInfo;
    try {
        info = await resolveAccount(account, context);
    } catch (error) {
        await releaseAuthAttempt(context.env, reservation); // 基础设施错误不算一次猜测
        throw error;
    }
    if (info.exists) {
        await clearAuthLimit(context.env, username, clientIP);
        return { info, banned: false };
    }
    await recordAuthFailure(context.env, username, clientIP, reservation);
    return { info: null, banned: false };
}

export async function authenticateBasic(context, account: string): Promise<UserInfo | null> {
    if (!account) return null;
    const username = account.split(":")[0];
    if (!username) return null;
    const hit = await getCachedAccount(account);
    if (hit) return hit;
    const clientIP = getClientIP(context.request);
    const dedupeKey = await sha256Hex(clientIP + "\n" + account);
    let pending = inflightAuth.get(dedupeKey);
    if (!pending) {
        pending = authenticateUncached(context, account, username, clientIP).finally(() => inflightAuth.delete(dedupeKey));
        inflightAuth.set(dedupeKey, pending);
    }
    const result = await pending;
    if (result.banned) context.__fdAuthBanned = true;
    return result.info;
}

// 从请求的 Authorization: Basic 头解析出已通过校验的账户；没有或无效时返回 null。
// 同一个请求内多次调用只校验一次。
// F2：所有走 Basic 认证的接口都经过这里，所以限流也在这里执行——
// 校验前先查该账号/IP 是否被封禁（被封禁直接返回 null，不做 PBKDF2，
// 攻击者也无法从 401 区分"密码错"和"已被封禁"）；校验失败记一次数。
// 被封禁时在 context 上打标记，供需要返回 429 的调用方区分（多数接口
// 直接按未登录返回 401 即可）。
export async function getRequestUser(context): Promise<UserInfo | null> {
    if (context.__fdUser !== undefined) return context.__fdUser;

    let user: UserInfo | null = null;
    const authHeader = context.request.headers.get("Authorization");
    if (authHeader && authHeader.startsWith("Basic ")) {
        let account = "";
        try {
            // atob 得到的是按字节的 latin1 字符串，再按 UTF-8 解码，支持中文用户名/密码
            const bin = atob(authHeader.slice(6).trim());
            const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
            try {
                account = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
            } catch {
                account = bin; // 不是合法 UTF-8（浏览器 btoa 的 latin1 写法），按原样使用
            }
        } catch {
            account = "";
        }
        if (account) {
            user = await authenticateBasic(context, account);
        }
    }

    context.__fdUser = user;
    return user;
}

// ---------------------------------------------------------------------------
// 权限判断（纯函数，方便测试）
// ---------------------------------------------------------------------------

export function userCanRead(user: UserInfo | null, env, path: string): boolean {
    if (isInternalPath(path)) return false;
    if (matchPrefixes(getGuestDirs(env), path)) return true;
    if (!user) return false;
    return matchPrefixes(user.permissions, path);
}

export function userCanWrite(user: UserInfo | null, env, path: string): boolean {
    if (!user || user.isReadOnly) return false;
    if (!isSafeKey(path)) return false;
    if (isInternalPath(path)) {
        // 缩略图：任何可写用户都能上传，但文件名必须是 "<sha1>.png"
        return isThumbnailKey(path);
    }
    if (matchPrefixes(user.permissions, path)) return true;
    // GUEST 目录不再默认开放写入：写权限只来自账户自身的 permissions
    // 列表；需要写 GUEST 目录的账户必须被显式授予该目录，否则即使是
    // 读写账户也写不了（2026-11-19 站主确认：默认开放写入不是想要的行为）。
    return false;
}

// 目录 dirPrefix（"" 或以 "/" 结尾）本身不可读，但它的某个下级目录可读时，
// 允许"路过"——用于在根目录等上级目录里显示出有权限的子目录。
// V7 注：双向判定是故意的（"路过"功能），不能按审计建议改成单向——只拥有
// "openclaw/sub/" 权限的用户需要靠反向判定进入上级目录 "openclaw/" 才能
// 导航到自己的子目录。真正的收紧在下面：dirPrefix 在函数内规范成目录边界
// （补末尾 "/"），否则不带 "/" 的 dirPrefix 会让 "openclaw" 误匹配到
// "openclaw2/"（同级目录混淆）。
export function userCanTraverse(user: UserInfo | null, env, dirPrefix: string): boolean {
    if (isInternalPath(dirPrefix)) return false;
    if (dirPrefix && !dirPrefix.endsWith("/")) dirPrefix += "/";
    const all = [...getGuestDirs(env), ...(user ? user.permissions.map(normalizePrefix) : [])];
    for (const p of all) {
        if (!p) continue;
        if (p === "*") return true;
        if (dirPrefix.startsWith(p) || p.startsWith(dirPrefix)) return true;
    }
    return false;
}

export async function checkPathPermission(context, path: string, needWrite: boolean): Promise<boolean> {
    const user = await getRequestUser(context);
    return needWrite ? userCanWrite(user, context.env, path) : userCanRead(user, context.env, path);
}

// /api/write/items/<path> 的写权限检查。
// 路径必须和实际写入 R2 时用的是同一个值（parseBucketPath），
// 否则"校验的路径"和"写入的路径"可能因为解码次数不同而对不上。
export async function get_auth_status(context): Promise<boolean> {
    let dopath: string;
    try {
        dopath = decodeURIComponent(((context.params?.path || []) as string[]).join("/"));
    } catch {
        return false;
    }
    if (!dopath) return false;
    return checkPathPermission(context, dopath, true);
}

// 文件列表访问权限。path 是不带末尾 "/" 的目录路径，根目录为 ""。
export async function get_list_auth_status(context, path = "") {
    const user = await getRequestUser(context);
    const dirPrefix = path ? (path.endsWith("/") ? path : path + "/") : "";

    if (!user && !guestListingEnabled(context.env)) {
        return { hasAccess: false, isGuest: true, user: null };
    }
    if (!user && getGuestDirs(context.env).length === 0) {
        return { hasAccess: false, isGuest: true, user: null };
    }

    const hasAccess = dirPrefix === ""
        ? true // 根目录始终可进入，内容再按权限过滤
        : userCanTraverse(user, context.env, dirPrefix);

    return { hasAccess, isGuest: !user, user };
}
