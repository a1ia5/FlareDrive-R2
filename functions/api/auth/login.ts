import { resolveAccount } from "@/utils/auth";
import { getBucket } from "@/utils/bucket";
// 限流计数已抽到 utils/login-limit.ts（与 getRequestUser 共用，见 F2）。
// v28（R3-2）：计数改用 R2 条件写（CAS），先原子认领、再校验。
import { getClientIP, claimAuthAttempt, clearAuthLimit } from "@/utils/login-limit";

export async function onRequestPost(context) {
    try {
        var headers = new Headers(context.request.headers);
        const clientIP = getClientIP(context.request);

        // 检查是否有Authorization头
        if(!headers.get('Authorization')) {
            return new Response(JSON.stringify({
                success: false,
                message: "缺少认证信息"
            }), {
                status: 401,
                headers: { "Content-Type": "application/json" }
            });
        }

        // 解析Basic Auth
        const authHeader = headers.get('Authorization');
        if (!authHeader.startsWith('Basic ')) {
            return new Response(JSON.stringify({
                success: false,
                message: "无效的认证格式"
            }), {
                status: 401,
                headers: { "Content-Type": "application/json" }
            });
        }

        const Authorization = authHeader.split("Basic ")[1];
        const account = atob(Authorization);

        if(!account) {
            return new Response(JSON.stringify({
                success: false,
                message: "无效的认证信息"
            }), {
                status: 401,
                headers: { "Content-Type": "application/json" }
            });
        }

        // 提取用户名用于限制检查
        let username = account.split(':')[0];

        // 检查登录限制（先原子认领一次尝试：并行猜密码时第 6 个请求
        // 读到的就是已封禁的状态，不会全放行——见 R3-2）。
        const bucket = getBucket(context);
        const limitCheck = await claimAuthAttempt(bucket, username, clientIP);
        if (!limitCheck.allowed) {
            return new Response(JSON.stringify({
                success: false,
                message: limitCheck.message,
                banned: limitCheck.banned,
                remainingBanTime: limitCheck.remainingBanTime
            }), {
                status: 429, // Too Many Requests
                headers: { "Content-Type": "application/json" }
            });
        }

        // 校验账户：优先查询 D1 数据库中的账户，找不到则回退到旧版环境变量账户
        const userInfo = await resolveAccount(account, context);
        const isReadOnly = userInfo.isReadOnly;
        const permissions = userInfo.exists ? userInfo.permissions : null;

        // 如果都不存在，返回错误。失败已经在认领时记过数，不用再记。
        // remainingAttempts === 0 说明这次就是第 5 次，封禁已生效，
        // 返回 429 而不是 401。
        if(!permissions) {
            // L3：失败消息不再透露剩余尝试次数（攻击者可用它判断账号是否存在 /
            // 探测限流状态）；只在已触发锁定时告知锁定。
            let message = "用户名或密码错误";
            let status = 401;
            if (limitCheck.remainingAttempts === 0) {
                message = limitCheck.message || "登录尝试次数过多，账户已被锁定";
                status = 429;
            }

            return new Response(JSON.stringify({
                success: false,
                message: message,
                banned: status === 429
            }), {
                status,
                headers: { "Content-Type": "application/json" }
            });
        }

        // 登录成功，清除限制记录
        await clearAuthLimit(bucket, username, clientIP);

        return new Response(JSON.stringify({
            success: true,
            message: "登录成功",
            user: {
                username: username,
                permissions: permissions,
                isAdmin: userInfo.isAdmin, // resolveAccount 已经按来源正确算好了，不要再用 permissions.includes("*") 覆盖它（这正是被发现的越权漏洞）
                isReadOnly: isReadOnly,
                accountSource: userInfo.source // "d1" 或 "env"，前端一般无需关心
            }
        }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        return new Response(JSON.stringify({
            success: false,
            message: "服务器内部错误"
        }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
        });
    }
}
