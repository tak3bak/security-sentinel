export async function onRequest(context) {
  const url = new URL(context.request.url);
  const backendHost = "nomadik-sentinel-api.onrender.com";
  const targetUrl = `https://${backendHost}${url.pathname}${url.search}`;

  const forwardHeaders = new Headers(context.request.headers);
  forwardHeaders.set("Host", backendHost);
  forwardHeaders.set("X-Forwarded-Host", url.hostname);
  forwardHeaders.set("X-Real-IP", context.request.headers.get("CF-Connecting-IP") || "");

  const init = {
    method: context.request.method,
    headers: forwardHeaders,
    body: context.request.body,
    redirect: "follow"
  };

  return fetch(targetUrl, init);
}
