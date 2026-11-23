import { resolveAccount } from "@/utils/auth";
// 限流计数已抽到 utils/login-limit.ts（与 getRequestUser 共用，见 F2）。
import { getClientIP, reserveAuthAttempt, recordAuthFailure, clearAuthLimit, releaseAuthAttempt } from "@/utils/login-limit";

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

        // R3-2：先原子占名额、再校验（见 utils/login-limit.ts）。占不到
        // （已封禁 / 名额被并行请求占满）直接 429，不做密码校验。
        const limitCheck = await reserveAuthAttempt(context.env, username, clientIP);
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
        let userInfo;
        try {
            userInfo = await resolveAccount(account, context);
        } catch (error) {
            await releaseAuthAttempt(context.env, limitCheck); // 基础设施错误不算一次猜测
            throw error;
        }
        const isReadOnly = userInfo.isReadOnly;
        const permissions = userInfo.exists ? userInfo.permissions : null;

        // 如果都不存在，记录失败并返回错误
        if(!permissions) {
            // 失败保留名额；占到最后一个名额的这次失败写入封禁并返回锁定结果。
            const failure = await recordAuthFailure(context.env, username, clientIP, limitCheck);
            // L3：失败消息不再透露剩余尝试次数（攻击者可用它判断账号是否存在 /
            // 探测限流状态）；只在已触发锁定时告知锁定。
            let message = "用户名或密码错误";
            if (failure.banned) {
                message = failure.message;
            }

            return new Response(JSON.stringify({
                success: false,
                message: message,
                banned: !!failure.banned
            }), {
                status: failure.banned ? 429 : 401,
                headers: { "Content-Type": "application/json" }
            });
        }

        // 登录成功，清除限制记录
        await clearAuthLimit(context.env, username, clientIP);

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
