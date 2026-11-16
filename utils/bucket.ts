export function notFound() {
  return new Response("Not found", { status: 404 });
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
  const path = decodeURIComponent(pathSegments.join("/"));
  const driveid = url.hostname.replace(/\..*/, "");

  return [env[driveid] || env["BUCKET"], path];
}
