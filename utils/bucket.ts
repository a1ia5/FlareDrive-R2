export function notFound() {
  return new Response("Not found", { status: 404 });
}

// L10：路径里的 % 序列非法时 decodeURIComponent 会抛 URIError；此前未捕获，
// 会一路冒泡成 500。这里抛一个带 status 400 的错误，调用方按 status 返回 400。
export class BadPathError extends Error {
  status = 400;
  constructor() {
    super("路径无效");
    this.name = "BadPathError";
  }
}

export function getBucket(context): any {
  const { request, env } = context;
  const driveid = new URL(request.url).hostname.replace(/\..*/, "");
  return env[driveid] || env["BUCKET"];
}

export function parseBucketPath(context): [any, string] {
  const { request, env, params } = context;
  const url = new URL(request.url);

  const pathSegments = (params.path || []) as String[];
  let path: string;
  try {
    path = decodeURIComponent(pathSegments.join("/"));
  } catch {
    throw new BadPathError();
  }
  const driveid = url.hostname.replace(/\..*/, "");

  return [env[driveid] || env["BUCKET"], path];
}
