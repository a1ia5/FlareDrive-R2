// V1 stopgap: dev-only test pages must not be served publicly.
export async function onRequest() {
  return new Response("Not found", { status: 404 });
}
