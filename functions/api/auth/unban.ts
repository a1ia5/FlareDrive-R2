import { authenticateBasic } from "@/utils/auth";
import { getBucket } from "@/utils/bucket";
import { clearAuthLimit, clearAllAuthLimitsForUser } from "@/utils/login-limit";
import { isCrossOriginRequest, crossOriginRejectedResponse } from "@/utils/csrf";

// 管理员解封用户API
export async function onRequestPost(context) {
    // M4：解封是状态变更接口，先做 Origin 同源校验（无 Origin 的 curl 不受影响）
    if (isCrossOriginRequest(context)) return crossOriginRejectedResponse();
    try {
        const headers = new Headers(context.request.headers);
        
        // 检查管理员权限
        if (!headers.get('Authorization')) {
            return new Response(JSON.stringify({
                success: false,
                message: "需要管理员权限"
            }), {
                status: 401,
                headers: { "Content-Type": "application/json" }
            });
        }

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

        // N2：走 authenticateBasic，失败也计数、封禁也生效。
        const adminInfo = !account ? null : await authenticateBasic(context, account);
        if (!adminInfo || !adminInfo.exists) {
            return new Response(JSON.stringify({
                success: false,
                message: "无效的管理员凭据"
            }), {
                status: 401,
                headers: { "Content-Type": "application/json" }
            });
        }

        // 检查是否为管理员
        if (!adminInfo.isAdmin) {
            return new Response(JSON.stringify({
                success: false,
                message: "需要管理员权限"
            }), {
                status: 403,
                headers: { "Content-Type": "application/json" }
            });
        }

        // 获取请求参数
        const requestBody = await context.request.json();
        const { username, clientIP } = requestBody;

        if (!username) {
            return new Response(JSON.stringify({
                success: false,
                message: "缺少用户名参数"
            }), {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
        }

        const bucket = getBucket(context);
        if (!bucket) {
            return new Response(JSON.stringify({
                success: false,
                message: "登录限制功能未启用"
            }), {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
        }

        // 如果指定了IP，解封特定IP的用户
        if (clientIP) {
            await clearAuthLimit(bucket, username, clientIP);

            return new Response(JSON.stringify({
                success: true,
                message: `已解封用户 ${username} (IP: ${clientIP})`
            }), {
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
        } else {
            // 不指定 IP 时解封该用户在所有 IP 上的限制（R2 可以按前缀
            // list，KV 做不到；v28 起支持）。
            const count = await clearAllAuthLimitsForUser(bucket, username);
            return new Response(JSON.stringify({
                success: true,
                message: count > 0
                    ? `已解封用户 ${username} 在 ${count} 个 IP 上的登录限制`
                    : `用户 ${username} 无登录限制记录`
            }), {
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
        }

    } catch (error) {
        console.error('Unban error:', error);
        return new Response(JSON.stringify({
            success: false,
            message: "服务器内部错误"
        }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
        });
    }
}
