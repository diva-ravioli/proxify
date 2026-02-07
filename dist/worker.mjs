// src/index.ts
var WORKER_SOURCE_URL = "https://raw.githubusercontent.com/diva-ravioli/proxify/main/dist/worker.mjs";
var corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};
var notFound = () => new Response("Not Found", { status: 404 });
function isSetupComplete(env) {
  return !!(env.API_KEY && env.SPOTIFY_CLIENT_ID && env.SPOTIFY_CLIENT_SECRET);
}
var src_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const workerName = url.hostname.split(".")[0];
    ctx.waitUntil(env.SPOTIFY_DATA.put("_worker_name", workerName));
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }
    try {
      const secretsConfigured = isSetupComplete(env);
      const oauthTokens = await getStoredTokens(env);
      const fullyConfigured = secretsConfigured && oauthTokens;
      if (pathname === "/callback") {
        return handleCallback(request, env);
      }
      if (!secretsConfigured) {
        switch (pathname) {
          case "/":
            return Response.redirect(
              new URL("/credentials", request.url).toString(),
              302
            );
          case "/credentials":
            return handleCredentials(request, env);
          default:
            return notFound();
        }
      }
      if (!fullyConfigured) {
        switch (pathname) {
          case "/":
            return Response.redirect(
              new URL("/setup", request.url).toString(),
              302
            );
          case "/setup":
            return handleSetup(request, env);
          default:
            return notFound();
        }
      }
      if (pathname === "/") {
        if (request.method === "POST") {
          return handleDashboardLogin(request, env);
        }
        return handleLoginPage();
      }
      const authResult = await requireApiKey(request, env);
      if (authResult)
        return authResult;
      switch (pathname) {
        case "/now-playing":
          return handleNowPlaying(request, env);
        case "/recent":
          return handleRecent(request, env);
        case "/health":
          return handleHealth(request, env);
        case "/api/update":
          return handleManualUpdate(request, env);
        default:
          return notFound();
      }
    } catch (error) {
      console.error("Error handling request:", error);
      return new Response("Internal Server Error", {
        status: 500,
        headers: corsHeaders
      });
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(checkForUpdates(env));
  }
};
async function checkForUpdates(env) {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID)
    return;
  try {
    const resp = await fetch(WORKER_SOURCE_URL);
    if (!resp.ok)
      return;
    const latestCode = await resp.text();
    const hashBuffer = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(latestCode)
    );
    const latestHash = Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
    const storedHash = await env.SPOTIFY_DATA.get("_worker_hash");
    if (storedHash === latestHash)
      return;
    let workerName = await env.SPOTIFY_DATA.get("_worker_name");
    if (!workerName) {
      await env.SPOTIFY_DATA.put("_worker_hash", latestHash);
      return;
    }
    const kvList = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/storage/kv/namespaces?per_page=100`,
      { headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` } }
    );
    const kvData = await kvList.json();
    const kvNamespace = kvData.result?.find(
      (ns) => ns.title.includes("SPOTIFY_DATA")
    );
    if (!kvNamespace)
      return;
    const bindings = [
      { type: "kv_namespace", name: "SPOTIFY_DATA", namespace_id: kvNamespace.id },
      { type: "plain_text", name: "ENVIRONMENT", text: env.ENVIRONMENT || "production" },
      { type: "plain_text", name: "CF_ACCOUNT_ID", text: env.CF_ACCOUNT_ID },
      { type: "secret_text", name: "CF_API_TOKEN", text: env.CF_API_TOKEN }
    ];
    if (env.API_KEY) {
      bindings.push({ type: "secret_text", name: "API_KEY", text: env.API_KEY });
    }
    if (env.SPOTIFY_CLIENT_ID) {
      bindings.push({ type: "secret_text", name: "SPOTIFY_CLIENT_ID", text: env.SPOTIFY_CLIENT_ID });
    }
    if (env.SPOTIFY_CLIENT_SECRET) {
      bindings.push({ type: "secret_text", name: "SPOTIFY_CLIENT_SECRET", text: env.SPOTIFY_CLIENT_SECRET });
    }
    const metadata = {
      main_module: "worker.mjs",
      bindings,
      compatibility_date: "2024-01-01"
    };
    const formData = new FormData();
    formData.append(
      "metadata",
      new Blob([JSON.stringify(metadata)], { type: "application/json" })
    );
    formData.append(
      "worker.mjs",
      new Blob([latestCode], { type: "application/javascript+module" }),
      "worker.mjs"
    );
    const deployResp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/workers/scripts/${workerName}`,
      {
        method: "PUT",
        headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` },
        body: formData
      }
    );
    if (deployResp.ok) {
      await env.SPOTIFY_DATA.put("_worker_hash", latestHash);
      console.log(`Auto-updated to ${latestHash.slice(0, 8)}`);
    }
  } catch (e) {
    console.error("Auto-update failed:", e);
  }
}
function handleLoginPage() {
  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Login</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); width: 100%; max-width: 380px; }
  h1 { font-size: 1.4em; margin-bottom: 24px; color: #333; text-align: center; }
  input[type="password"] { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 15px; margin-bottom: 16px; }
  input:focus { outline: none; border-color: #1db954; }
  button { width: 100%; padding: 12px; background: #1db954; color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; }
  button:hover { background: #1ed760; }
  .error { color: #c62828; text-align: center; margin-bottom: 12px; font-size: 14px; display: none; }
  .hint { text-align: center; margin-top: 16px; font-size: 13px; color: #888; }
  .hint a { color: #1db954; text-decoration: none; }
  .hint a:hover { text-decoration: underline; }
</style></head>
<body>
  <div class="card">
    <h1>API Proxy</h1>
    <div class="error" id="err">Invalid API key</div>
    <form method="POST">
      <input type="password" name="key" placeholder="API Key" autofocus required />
      <button type="submit">Login</button>
    </form>
    <p class="hint">Your API key is stored in your <a href="https://dash.cloudflare.com/" target="_blank">Cloudflare Dashboard</a> under Worker Settings &gt; Variables</p>
  </div>
</body></html>`;
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}
async function handleDashboardLogin(request, env) {
  const formData = await request.formData();
  const key = formData.get("key");
  if (!key || key !== env.API_KEY) {
    const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Login</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); width: 100%; max-width: 380px; }
  h1 { font-size: 1.4em; margin-bottom: 24px; color: #333; text-align: center; }
  input[type="password"] { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 15px; margin-bottom: 16px; }
  input:focus { outline: none; border-color: #1db954; }
  button { width: 100%; padding: 12px; background: #1db954; color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; }
  button:hover { background: #1ed760; }
  .error { color: #c62828; text-align: center; margin-bottom: 12px; font-size: 14px; }
  .hint { text-align: center; margin-top: 16px; font-size: 13px; color: #888; }
  .hint a { color: #1db954; text-decoration: none; }
  .hint a:hover { text-decoration: underline; }
</style></head>
<body>
  <div class="card">
    <h1>API Proxy</h1>
    <div class="error">Invalid API key</div>
    <form method="POST">
      <input type="password" name="key" placeholder="API Key" autofocus required />
      <button type="submit">Login</button>
    </form>
    <p class="hint">Your API key is stored in your <a href="https://dash.cloudflare.com/" target="_blank">Cloudflare Dashboard</a> under Worker Settings &gt; Variables</p>
  </div>
</body></html>`;
    return new Response(html, {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
  return renderDashboard(key, env);
}
async function renderDashboard(apiKey, env) {
  const tokens = await getStoredTokens(env);
  const storedHash = await env.SPOTIFY_DATA.get("_worker_hash") || "unknown";
  const hasAutoUpdate = !!(env.CF_API_TOKEN && env.CF_ACCOUNT_ID);
  let nowPlaying = null;
  if (tokens) {
    try {
      const resp = await callSpotifyAPI("/v1/me/player/currently-playing", tokens.access_token);
      if (resp.status === 200) {
        nowPlaying = await resp.json();
      }
    } catch {
    }
  }
  const trackName = nowPlaying?.item ? escapeHtml(nowPlaying.item.name) : null;
  const trackArtist = nowPlaying?.item ? escapeHtml(nowPlaying.item.artists?.map((a) => a.name).join(", ") || "Unknown") : null;
  const trackInfo = trackName ? "<strong>" + trackName + "</strong> by " + trackArtist : "Nothing playing";
  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; padding: 20px; }
  .container { max-width: 640px; margin: 0 auto; }
  .card { background: white; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); padding: 24px; margin-bottom: 16px; }
  h1 { font-size: 1.4em; color: #333; margin-bottom: 4px; }
  .subtitle { color: #888; font-size: 0.9em; margin-bottom: 20px; }
  h2 { font-size: 1.1em; color: #333; margin-bottom: 12px; }
  .stat { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
  .stat:last-child { border: none; }
  .stat .label { color: #666; }
  .stat .value { font-weight: 600; color: #333; }
  .stat .value.ok { color: #2e7d32; }
  .stat .value.warn { color: #f57c00; }
  .now-playing { font-size: 15px; color: #333; }
  .btn { display: inline-block; padding: 10px 20px; background: #1db954; color: white; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; text-decoration: none; }
  .btn:hover { background: #1ed760; }
  .btn.secondary { background: #666; }
  .btn.secondary:hover { background: #888; }
  .btn:disabled { background: #ccc; cursor: not-allowed; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
  #update-status { margin-top: 8px; font-size: 13px; color: #666; }
  .logout { text-align: center; margin-top: 12px; }
  .logout a { color: #888; font-size: 13px; text-decoration: none; }
  .logout a:hover { color: #333; }
</style></head>
<body>
<div class="container">
  <div class="card">
    <h1>Dashboard</h1>
    <p class="subtitle">API Proxy Admin</p>

    <div class="now-playing">${trackInfo}</div>
  </div>

  <div class="card">
    <h2>Status</h2>
    <div class="stat"><span class="label">OAuth</span><span class="value ok">Connected</span></div>
    <div class="stat"><span class="label">API Key</span><span class="value ok">Configured</span></div>
    <div class="stat"><span class="label">Auto-update</span><span class="value ${hasAutoUpdate ? "ok" : "warn"}">${hasAutoUpdate ? "Enabled" : "Not configured"}</span></div>
    <div class="stat"><span class="label">Version hash</span><span class="value">${storedHash.slice(0, 12) || "n/a"}...</span></div>
  </div>

  <div class="card">
    <h2>Actions</h2>
    <div class="actions">
      <button class="btn" onclick="checkUpdate()" id="update-btn">Check for updates</button>
      <a href="/health" class="btn secondary" id="health-link">Health check</a>
    </div>
    <div id="update-status"></div>
  </div>

  <div class="logout"><a href="/">Logout</a></div>
</div>

<script>
  const API_KEY = '${apiKey}';
  const headers = { 'Authorization': 'Bearer ' + API_KEY };

  // Fix health link to use auth
  document.getElementById('health-link').addEventListener('click', async (e) => {
    e.preventDefault();
    const resp = await fetch('/health', { headers });
    const data = await resp.json();
    document.getElementById('update-status').textContent = JSON.stringify(data, null, 2);
  });

  async function checkUpdate() {
    const btn = document.getElementById('update-btn');
    const status = document.getElementById('update-status');
    btn.disabled = true;
    btn.textContent = 'Checking...';
    status.textContent = '';
    try {
      const resp = await fetch('/api/update', { method: 'POST', headers });
      const data = await resp.json();
      status.textContent = data.message || JSON.stringify(data);
      if (data.updated) {
        status.style.color = '#2e7d32';
        status.textContent = 'Updated! The page will reload in a few seconds...';
        setTimeout(() => location.reload(), 5000);
      }
    } catch (e) {
      status.textContent = 'Update check failed: ' + e.message;
      status.style.color = '#c62828';
    }
    btn.disabled = false;
    btn.textContent = 'Check for updates';
  }
<\/script>
</body></html>`;
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}
function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
async function handleManualUpdate(request, env) {
  if (request.method !== "POST")
    return notFound();
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) {
    return Response.json(
      { updated: false, message: "Auto-update not configured (missing CF_API_TOKEN or CF_ACCOUNT_ID)." },
      { headers: corsHeaders }
    );
  }
  try {
    const resp = await fetch(WORKER_SOURCE_URL);
    if (!resp.ok) {
      return Response.json(
        { updated: false, message: "Failed to fetch latest source." },
        { headers: corsHeaders }
      );
    }
    const latestCode = await resp.text();
    const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(latestCode));
    const latestHash = Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
    const storedHash = await env.SPOTIFY_DATA.get("_worker_hash");
    if (storedHash === latestHash) {
      return Response.json(
        { updated: false, message: "Already up to date." },
        { headers: corsHeaders }
      );
    }
    await checkForUpdates(env);
    const newHash = await env.SPOTIFY_DATA.get("_worker_hash");
    const didUpdate = newHash === latestHash;
    return Response.json(
      { updated: didUpdate, message: didUpdate ? "Updated successfully." : "Update may have failed. Check logs." },
      { headers: corsHeaders }
    );
  } catch (e) {
    return Response.json(
      { updated: false, message: "Update failed: " + e.message },
      { status: 500, headers: corsHeaders }
    );
  }
}
async function handleSetup(request, env) {
  const hasSpotifyCredentials = !!(env.SPOTIFY_CLIENT_ID && env.SPOTIFY_CLIENT_SECRET);
  if (!hasSpotifyCredentials) {
    return Response.redirect(
      new URL("/credentials", request.url).toString(),
      302
    );
  }
  if (request.method === "POST") {
    const redirectUri = `${new URL(request.url).origin}/callback`;
    const scope = "user-read-currently-playing user-read-recently-played user-read-playback-state";
    const state = generateRandomString(16);
    await env.SPOTIFY_DATA.put(`oauth_state_${state}`, "pending", {
      expirationTtl: 600
    });
    const authUrl = `https://accounts.spotify.com/authorize?response_type=code&client_id=${env.SPOTIFY_CLIENT_ID}&scope=${encodeURIComponent(scope)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;
    return Response.redirect(authUrl, 302);
  }
  const html = await getSetupHTML();
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      ...corsHeaders
    }
  });
}
async function handleCredentials(request, env) {
  const html = await getCredentialsHTML(void 0, request.url, env);
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      ...corsHeaders
    }
  });
}
async function handleCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");
  if (error) {
    return new Response(`OAuth Error: ${error}`, { status: 400 });
  }
  if (!code || !state) {
    return new Response("Missing authorization code or state", { status: 400 });
  }
  const storedState = await env.SPOTIFY_DATA.get(`oauth_state_${state}`);
  if (!storedState) {
    return new Response("Invalid or expired state parameter", { status: 400 });
  }
  const tokenResponse = await exchangeCodeForTokens(code, request.url, env);
  if (!tokenResponse.success) {
    return new Response(`Token exchange failed: ${tokenResponse.error}`, {
      status: 400
    });
  }
  await env.SPOTIFY_DATA.put(
    "spotify_tokens",
    JSON.stringify({
      ...tokenResponse.data,
      obtained_at: Date.now()
    })
  );
  await env.SPOTIFY_DATA.delete(`oauth_state_${state}`);
  return new Response(
    `
    <html>
      <head><meta charset="UTF-8"><title>Setup Complete</title></head>
      <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h1>Setup Complete</h1>
        <p>Your account has been connected. The proxy is ready to use.</p>
      </body>
    </html>
  `,
    {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        ...corsHeaders
      }
    }
  );
}
async function handleNowPlaying(request, env) {
  const tokens = await getStoredTokens(env);
  if (!tokens) {
    return new Response(
      JSON.stringify({
        error: "Not configured."
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      }
    );
  }
  const spotifyResponse = await callSpotifyAPI(
    "/v1/me/player/currently-playing",
    tokens.access_token
  );
  if (spotifyResponse.status === 204) {
    return new Response(
      JSON.stringify({ playing: false, message: "No track currently playing" }),
      {
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      }
    );
  }
  if (!spotifyResponse.ok) {
    return new Response(
      JSON.stringify({ error: "Failed to fetch current track" }),
      {
        status: spotifyResponse.status,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      }
    );
  }
  const data = await spotifyResponse.json();
  return new Response(JSON.stringify(data), {
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders
    }
  });
}
async function handleRecent(request, env) {
  const tokens = await getStoredTokens(env);
  if (!tokens) {
    return new Response(
      JSON.stringify({
        error: "Not configured."
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      }
    );
  }
  const spotifyResponse = await callSpotifyAPI(
    "/v1/me/player/recently-played?limit=10",
    tokens.access_token
  );
  if (!spotifyResponse.ok) {
    return new Response(
      JSON.stringify({ error: "Failed to fetch recent tracks" }),
      {
        status: spotifyResponse.status,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      }
    );
  }
  const data = await spotifyResponse.json();
  return new Response(JSON.stringify(data), {
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders
    }
  });
}
async function handleHealth(request, env) {
  const tokens = await getStoredTokens(env);
  const hasValidCredentials = !!(env.SPOTIFY_CLIENT_ID && env.SPOTIFY_CLIENT_SECRET);
  const hasValidTokens = tokens !== null;
  const hasApiKey = !!env.API_KEY;
  const health = {
    status: "ok",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    credentials_configured: hasValidCredentials,
    oauth_configured: hasValidTokens,
    ready: hasApiKey && hasValidCredentials && hasValidTokens
  };
  return new Response(JSON.stringify(health, null, 2), {
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders
    }
  });
}
function generateRandomString(length) {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return result;
}
function generateSecureApiKey() {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let result = "";
  for (let i = 0; i < 64; i++) {
    result += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return result;
}
async function exchangeCodeForTokens(code, callbackUrl, env) {
  const redirectUri = new URL(callbackUrl).origin + "/callback";
  if (!env.SPOTIFY_CLIENT_ID || !env.SPOTIFY_CLIENT_SECRET) {
    return {
      success: false,
      error: "Credentials not configured."
    };
  }
  const response = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${btoa(
        `${env.SPOTIFY_CLIENT_ID}:${env.SPOTIFY_CLIENT_SECRET}`
      )}`
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri
    })
  });
  if (!response.ok) {
    return {
      success: false,
      error: `Token exchange failed: ${response.statusText}`
    };
  }
  const data = await response.json();
  return { success: true, data };
}
async function getStoredTokens(env) {
  const tokensJson = await env.SPOTIFY_DATA.get("spotify_tokens");
  if (!tokensJson)
    return null;
  const tokens = JSON.parse(tokensJson);
  const expiresIn = tokens.expires_in || 3600;
  const obtainedAt = tokens.obtained_at || 0;
  const isExpired = Date.now() > obtainedAt + (expiresIn - 300) * 1e3;
  if (isExpired && tokens.refresh_token && env.SPOTIFY_CLIENT_ID && env.SPOTIFY_CLIENT_SECRET) {
    const refreshed = await refreshAccessToken(tokens.refresh_token, env);
    if (refreshed) {
      const newTokens = {
        ...tokens,
        ...refreshed,
        obtained_at: Date.now()
      };
      await env.SPOTIFY_DATA.put("spotify_tokens", JSON.stringify(newTokens));
      return newTokens;
    }
  }
  return tokens;
}
async function refreshAccessToken(refreshToken, env) {
  try {
    const response = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${btoa(
          `${env.SPOTIFY_CLIENT_ID}:${env.SPOTIFY_CLIENT_SECRET}`
        )}`
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken
      })
    });
    if (!response.ok)
      return null;
    return await response.json();
  } catch {
    return null;
  }
}
async function callSpotifyAPI(endpoint, accessToken) {
  return fetch(`https://api.spotify.com${endpoint}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    }
  });
}
async function getSetupHTML() {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Setup</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          max-width: 600px;
          margin: 50px auto;
          padding: 20px;
          background-color: #f5f5f5;
        }
        .container {
          background: white;
          padding: 30px;
          border-radius: 10px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .button {
          display: inline-block;
          padding: 12px 24px;
          background: #1db954;
          color: white;
          text-decoration: none;
          border-radius: 25px;
          margin: 10px 0;
          border: none;
          cursor: pointer;
          font-size: 16px;
        }
        .button:hover { background: #1ed760; }
        .button.secondary {
          background: #666;
          font-size: 14px;
          padding: 8px 16px;
        }
        .button.secondary:hover { background: #888; }
        .info {
          background: #e8f5e8;
          padding: 15px;
          border-radius: 5px;
          margin: 20px 0;
        }
        .step {
          margin: 15px 0;
          padding: 10px;
          background: #f9f9f9;
          border-left: 4px solid #1db954;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Connect Account</h1>

        <div class="info">
          <h3>Credentials Configured</h3>
          <p>Your app credentials are set. Connect your account to finish setup.</p>
        </div>

        <div class="step">
          <h3>Authorize</h3>
          <p>Click below to connect your account via OAuth:</p>
          <form method="POST">
            <button type="submit" class="button">Connect Account</button>
          </form>
        </div>

        <p>
          <a href="/credentials" class="button secondary">Back to Credentials</a>
        </p>
      </div>
    </body>
    </html>
  `;
}
async function getCredentialsHTML(errorMessage, requestUrl, env) {
  const origin = requestUrl ? new URL(requestUrl).origin : "https://your-worker.workers.dev";
  const apiKey = generateSecureApiKey();
  const workerName = requestUrl ? new URL(requestUrl).hostname.split(".")[0] : "";
  const cfAccountId = env?.CF_ACCOUNT_ID || "";
  const dashboardUrl = cfAccountId && workerName ? `https://dash.cloudflare.com/${cfAccountId}/workers/services/view/${workerName}/production/settings#variables` : "https://dash.cloudflare.com/";
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Proxy Setup</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          max-width: 800px;
          margin: 50px auto;
          padding: 20px;
          background-color: #f5f5f5;
        }
        .container {
          background: white;
          padding: 30px;
          border-radius: 10px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .button {
          display: inline-block;
          padding: 12px 24px;
          background: #1db954;
          color: white;
          text-decoration: none;
          border-radius: 25px;
          margin: 10px 5px;
          border: none;
          cursor: pointer;
          font-size: 16px;
        }
        .button:hover { background: #1ed760; }
        .button.secondary {
          background: #666;
          font-size: 14px;
          padding: 8px 16px;
        }
        .button.secondary:hover { background: #888; }
        .button.dashboard {
          background: #f38020;
          font-size: 18px;
          padding: 15px 30px;
        }
        .button.dashboard:hover { background: #e66f00; }
        .form-group {
          margin: 20px 0;
        }
        .form-group label {
          display: block;
          margin-bottom: 5px;
          font-weight: bold;
        }
        .form-group input {
          width: 100%;
          padding: 10px;
          border: 2px solid #ddd;
          border-radius: 5px;
          font-size: 14px;
          box-sizing: border-box;
        }
        .form-group input:focus {
          border-color: #1db954;
          outline: none;
        }
        .error {
          background: #ffebee;
          color: #c62828;
          padding: 15px;
          border-radius: 5px;
          margin: 20px 0;
        }
        .info {
          background: #e3f2fd;
          padding: 15px;
          border-radius: 5px;
          margin: 20px 0;
        }
        .warning {
          background: #fff3e0;
          color: #f57c00;
          padding: 15px;
          border-radius: 5px;
          margin: 20px 0;
        }
        .step {
          margin: 15px 0;
          padding: 15px;
          background: #f9f9f9;
          border-left: 4px solid #1db954;
          border-radius: 5px;
        }
        .step h3 {
          margin-top: 0;
          color: #1db954;
        }
        .api-key {
          background: #fffde7;
          border: 2px solid #ffc107;
          padding: 15px;
          border-radius: 5px;
          margin: 10px 0;
          font-family: monospace;
          word-break: break-all;
          font-size: 16px;
          font-weight: bold;
        }
        .section {
          margin: 30px 0;
          padding: 20px;
          border: 2px solid #e0e0e0;
          border-radius: 10px;
        }
        .section h2 {
          margin-top: 0;
          color: #333;
        }
        code {
          background: #f5f5f5;
          padding: 2px 6px;
          border-radius: 3px;
          font-family: monospace;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Proxy Setup</h1>

        <div class="warning">
          <h3>Setup Required</h3>
          <p>This proxy needs an API key and app credentials configured as Cloudflare Worker secrets.</p>
        </div>

        ${errorMessage ? `<div class="error">${errorMessage}</div>` : ""}

        <!-- API Key Section -->
        <div class="section">
          <h2>Step 1: API Key Setup</h2>

          <div class="step">
            <h3>Generate Your API Key</h3>
            <p>We've generated a secure API key for you:</p>
            <div class="api-key" id="apiKey">${apiKey}</div>
            <button class="button secondary" onclick="copyApiKey()">Copy API Key</button>
            <button class="button secondary" onclick="generateNewKey()">Generate New Key</button>
          </div>

          <div class="step">
            <h3>Set API_KEY Secret in Cloudflare</h3>
            <p><strong>Open your Cloudflare Workers dashboard:</strong></p>

            <a href="${dashboardUrl}" target="_blank" class="button dashboard">Open Worker Settings</a>

            <div style="margin: 20px 0;">
              <p><strong>Instructions:</strong></p>
              <ol>
                <li>On the Settings page, find <strong>"Variables and Secrets"</strong></li>
                <li>Click <strong>"Add"</strong></li>
                <li>Set <strong>Variable name:</strong> <code>API_KEY</code></li>
                <li>Set <strong>Value:</strong> paste the API key from above</li>
                <li>Leave <strong>"Encrypt"</strong> unchecked so you can retrieve it later</li>
                <li>Click <strong>"Save and deploy"</strong></li>
              </ol>
            </div>
          </div>
        </div>

        <!-- App Credentials Section -->
        <div class="section">
          <h2>Step 2: App Credentials</h2>

          <div class="info">
            <h3>Get your app credentials</h3>
            <p>You'll need a <strong>Client ID</strong> and <strong>Client Secret</strong> from your app provider.</p>
            <p>Set your callback URL to: <code>${origin}/callback</code></p>
          </div>

          <div class="step">
            <h3>Set App Secrets in Cloudflare</h3>
            <p>Follow the same process as Step 1 to add these two secrets:</p>

            <div style="margin: 15px 0; padding: 10px; background: #f0f0f0; border-radius: 5px;">
              <strong>Secret 1:</strong><br>
              Variable name: <code>SPOTIFY_CLIENT_ID</code><br>
              Value: Your Client ID<br>
              Check "Encrypt"
            </div>

            <div style="margin: 15px 0; padding: 10px; background: #f0f0f0; border-radius: 5px;">
              <strong>Secret 2:</strong><br>
              Variable name: <code>SPOTIFY_CLIENT_SECRET</code><br>
              Value: Your Client Secret<br>
              Check "Encrypt"
            </div>
          </div>
        </div>



        <!-- Next Steps -->
        <div class="step">
          <h3>Step 3: Connect Account</h3>
          <p>After setting all secrets in the Cloudflare Dashboard:</p>
          <ol>
            <li>Click below to proceed to OAuth setup</li>
            <li>Authorize the app to connect your account</li>
          </ol>

          <div style="margin: 20px 0;">
            <a href="/setup" class="button">Continue to OAuth Setup</a>
          </div>
        </div>
      </div>

      <script>
        let currentApiKey = '${apiKey}';

        function copyApiKey() {
          navigator.clipboard.writeText(currentApiKey).then(() => {
            const btn = event.target;
            const originalText = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = originalText, 2000);
          });
        }

        function generateNewKey() {
          // Generate a new secure API key
          const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
          let newKey = '';
          for (let i = 0; i < 64; i++) {
            newKey += chars.charAt(Math.floor(Math.random() * chars.length));
          }

          currentApiKey = newKey;
          document.getElementById('apiKey').textContent = newKey;
        }
      <\/script>
    </body>
    </html>
  `;
}
async function requireApiKey(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) {
    return new Response(
      JSON.stringify({
        error: "Unauthorized."
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      }
    );
  }
  if (!authHeader.startsWith("Bearer ")) {
    return new Response(
      JSON.stringify({
        error: "Unauthorized."
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      }
    );
  }
  const providedApiKey = authHeader.slice(7);
  if (!env.API_KEY) {
    return new Response(
      JSON.stringify({
        error: "Unauthorized."
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      }
    );
  }
  if (providedApiKey !== env.API_KEY) {
    return new Response(
      JSON.stringify({
        error: "Unauthorized."
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      }
    );
  }
  return null;
}
export {
  src_default as default
};
