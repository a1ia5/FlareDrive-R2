import { checkPathPermission } from "@/utils/auth";

// 和真正的写接口用同一个判断函数，避免两处逻辑不一致
async function checkWritePermission(context, dopath) {
    return checkPathPermission(context, dopath, true);
}

export async function onRequestPost(context) {
    // 声明在 try 外层，这样即使解析请求体失败，catch 块里也能安全访问 path
    let requestBody: { path?: string } = {};

    try {
        requestBody = await context.request.json();
        const { path } = requestBody;

        console.log('check-write-permission - checking path:', path);

        // 构造测试路径，模拟真实的文件操作
        const testPath = path === '' ? 'test_file.txt' : `${path}test_file.txt`;

        console.log('check-write-permission - test path:', testPath);

        const hasPermission = await checkWritePermission(context, testPath);

        console.log('check-write-permission - result:', hasPermission);

        return new Response(JSON.stringify({
            hasPermission: hasPermission,
            path: path,
            testPath: testPath
        }), {
            status: 200,
            headers: {
                "Content-Type": "application/json"
            }
        });

    } catch (error) {
        console.error('check-write-permission error:', error);
        return new Response(JSON.stringify({
            hasPermission: false,
            error: error.message,
            path: requestBody.path || 'unknown'
        }), {
            status: 200, // 返回200避免触发浏览器错误处理
            headers: {
                "Content-Type": "application/json"
            }
        });
    }
}
