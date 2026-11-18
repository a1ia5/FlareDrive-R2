import { checkPathPermission, getRequestUser } from "@/utils/auth";

// 和真正的写接口用同一个判断函数，避免两处逻辑不一致
async function checkWritePermission(context, dopath) {
    return checkPathPermission(context, dopath, true);
}

export async function onRequestPost(context) {
    // V4：必须先登录再检查。未登录时返回 401 + {hasPermission:false}，
    // 不回显请求体里的 path，也不回显内部构造的测试路径。
    const user = await getRequestUser(context);
    if (!user) {
        return new Response(JSON.stringify({ hasPermission: false }), {
            status: 401,
            headers: { "Content-Type": "application/json" },
        });
    }

    try {
        const requestBody = await context.request.json();
        const { path } = requestBody || {};

        // 构造测试路径，模拟真实的文件操作
        const testPath = path === '' ? 'test_file.txt' : `${path}test_file.txt`;

        const hasPermission = await checkWritePermission(context, testPath);

        return new Response(JSON.stringify({ hasPermission }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    } catch (error) {
        console.error('check-write-permission error:', error);
        return new Response(JSON.stringify({ hasPermission: false }), {
            status: 200, // 返回200避免触发浏览器错误处理
            headers: { "Content-Type": "application/json" },
        });
    }
}
