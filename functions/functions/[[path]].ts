// V1 stopgap (publish root is the repo root): block anonymous reads of
// source and internal files that Cloudflare Pages serves as static assets.
// The functions/ directory itself is not published as static files by
// Pages, but this makes the 404 explicit and keeps _routes.json complete.
export async function onRequest() {
  return new Response("Not found", { status: 404 });
}
