export async function onRequest(context) {
  const url = new URL(context.request.url);
  const targetUrl = new URL(`https://api.nomadik.site${url.pathname}${url.search}`);

  const proxyRequest = new Request(targetUrl, context.request);
  proxyRequest.headers.set("Host", "api.nomadik.site");
  proxyRequest.headers.set("X-Forwarded-For", context.request.headers.get("CF-Connecting-IP"));

  return fetch(proxyRequest);
}
