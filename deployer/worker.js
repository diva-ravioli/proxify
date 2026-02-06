/**
 * Deployer CORS Proxy
 *
 * A lightweight Cloudflare Worker that proxies requests to the Cloudflare API,
 * adding CORS headers so the deploy-web.html page can call the API from the browser.
 *
 * Only proxies to api.cloudflare.com — not an open proxy.
 * Does not log, store, or inspect any tokens or credentials.
 */

const ALLOWED_ORIGINS = [
  "https://diva-ravioli.github.io",
  "http://localhost:8787",
  "http://127.0.0.1:8787",
];

const CF_API = "https://api.cloudflare.com";

// Only allow the specific API paths needed for deployment
const ALLOWED_PATH_PREFIXES = [
  "/client/v4/user/tokens/verify",
  "/client/v4/accounts/",
];

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

function isAllowedOrigin(request) {
  const origin = request.headers.get("Origin") || "";
  return ALLOWED_ORIGINS.includes(origin) ? origin : null;
}

function isAllowedPath(path) {
  return ALLOWED_PATH_PREFIXES.some((prefix) => path.startsWith(prefix));
}

export default {
  async fetch(request) {
    const origin = isAllowedOrigin(request);

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin || ALLOWED_ORIGINS[0]),
      });
    }

    // Reject requests from disallowed origins
    if (!origin) {
      return new Response(JSON.stringify({ error: "Origin not allowed" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Parse the target path from the request URL
    const url = new URL(request.url);
    const targetPath = url.pathname + url.search;

    // Only allow specific CF API paths
    if (!isAllowedPath(targetPath)) {
      return new Response(JSON.stringify({ error: "Path not allowed" }), {
        status: 403,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders(origin),
        },
      });
    }

    // Forward to Cloudflare API
    const targetUrl = CF_API + targetPath;

    const proxyHeaders = new Headers();
    // Forward auth header
    const auth = request.headers.get("Authorization");
    if (auth) proxyHeaders.set("Authorization", auth);
    // Forward content-type
    const contentType = request.headers.get("Content-Type");
    if (contentType) proxyHeaders.set("Content-Type", contentType);

    const proxyRequest = new Request(targetUrl, {
      method: request.method,
      headers: proxyHeaders,
      body: ["GET", "HEAD"].includes(request.method) ? null : request.body,
    });

    try {
      const response = await fetch(proxyRequest);
      // Clone response and add CORS headers
      const newHeaders = new Headers(response.headers);
      Object.entries(corsHeaders(origin)).forEach(([k, v]) =>
        newHeaders.set(k, v),
      );

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders,
      });
    } catch (err) {
      return new Response(
        JSON.stringify({ error: "Proxy request failed", detail: err.message }),
        {
          status: 502,
          headers: {
            "Content-Type": "application/json",
            ...corsHeaders(origin),
          },
        },
      );
    }
  },
};
