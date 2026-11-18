// V1 stopgap (publish root is the repo root): block anonymous reads of
// source and internal files that Cloudflare Pages serves as static assets.
// The proper fix is Pages -> Build settings -> Output directory -> dist/
// (a dashboard setting the owner must apply). See _routes.json and README.md.
export async function onRequest() {
  return new Response("Not found", { status: 404 });
}
