export async function onRequest(context) {
  const url = new URL(context.request.url);
  const targetUrl = new URL(`https://nomadik-sentinel-api.onrender.com${url.pathname}${url.search}`);

  const proxyRequest = new Request(targetUrl, context.request);
  proxyRequest.headers.set("Host", "nomadik-sentinel-api.onrender.com");
  proxyRequest.headers.set("X-Forwarded-For", context.request.headers.get("CF-Connecting-IP"));

  return fetch(proxyRequest);
}
