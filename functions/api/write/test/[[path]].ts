import { authenticateBasic } from "@/utils/auth";

export async function onRequest(context) {
    try {
        var headers = new Headers(context.request.headers);

        // 检查是否有Authorization头
        // M4：这里不再返回 WWW-Authenticate，避免浏览器缓存 Basic 凭据后
        // 被跨站请求利用（见 utils/csrf.ts）。未登录只返回普通 401。
        if(!headers.get('Authorization')) {
            return new Response("没有操作权限", {
                status: 401,
            });
        }

        // 解析Basic Auth
        const authHeader = headers.get('Authorization');
        if (!authHeader.startsWith('Basic ')) {
            return new Response("无效的认证格式", {
                status: 401,
            });
        }

        const Authorization = authHeader.split("Basic ")[1];
        const account = atob(Authorization);

        if(!account) {
            return new Response("无效的认证信息", {
                status: 401,
            });
        }

        // 校验账户：优先查 D1，再回退旧版环境变量账户。
        // N2：走 authenticateBasic，失败也计数、封禁也生效（以前直接调
        // resolveAccount，这个口子可以无限试密码）。
        const userInfo = await authenticateBasic(context, account);
        if(!userInfo) {
            return new Response("用户名或密码错误", {
                status: 401,
            });
        }

        // 认证成功
        return new Response("access", {
            status: 200,
        });

    } catch (error) {
        console.error('Login test error:', error);
        return new Response("服务器内部错误", {
            status: 500,
        });
    }
}