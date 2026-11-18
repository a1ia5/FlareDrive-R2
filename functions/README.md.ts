// V1 stopgap: the repo README documents the internal security model and
// is not part of the app; it is public on GitHub, so it need not be served.
export async function onRequest() {
  return new Response("Not found", { status: 404 });
}
