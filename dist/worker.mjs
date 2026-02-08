// src/index.ts
var WORKER_SOURCE_URL = "https://raw.githubusercontent.com/diva-ravioli/proxify/main/dist/worker.mjs";
var _cachedTokens = null;
var UPDATE_LOCK_KEY = "_update_lock";
var UPDATE_LOCK_TTL = 120;
async function acquireUpdateLock(kv) {
  const existing = await kv.get(UPDATE_LOCK_KEY);
  if (existing) {
    return false;
  }
  await kv.put(UPDATE_LOCK_KEY, Date.now().toString(), { expirationTtl: UPDATE_LOCK_TTL });
  const check = await kv.get(UPDATE_LOCK_KEY);
  return check === Date.now().toString() || check !== null;
}
async function releaseUpdateLock(kv) {
  await kv.delete(UPDATE_LOCK_KEY);
}
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
        case "/queue":
          return handleQueue(request, env);
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
async function deployWorkerCode(env, workerName, latestCode, latestHash) {
  const requiredSecrets = {
    API_KEY: env.API_KEY,
    SPOTIFY_CLIENT_ID: env.SPOTIFY_CLIENT_ID,
    SPOTIFY_CLIENT_SECRET: env.SPOTIFY_CLIENT_SECRET,
    CF_API_TOKEN: env.CF_API_TOKEN,
    CF_ACCOUNT_ID: env.CF_ACCOUNT_ID
  };
  const missingSecrets = Object.entries(requiredSecrets).filter(([_, value]) => !value || value.trim() === "").map(([key]) => key);
  if (missingSecrets.length > 0) {
    console.error(`Aborting deploy: missing secrets: ${missingSecrets.join(", ")}`);
    return false;
  }
  if (!workerName || workerName.trim() === "") {
    console.error("Aborting deploy: workerName is empty");
    return false;
  }
  const kvList = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/storage/kv/namespaces?per_page=100`,
    { headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` } }
  );
  const kvData = await kvList.json();
  const kvNamespace = kvData.result?.find(
    (ns) => ns.title.includes("SPOTIFY_DATA")
  );
  if (!kvNamespace) {
    console.error("Aborting deploy: KV namespace not found");
    return false;
  }
  const bindings = [
    { type: "kv_namespace", name: "SPOTIFY_DATA", namespace_id: kvNamespace.id },
    { type: "plain_text", name: "ENVIRONMENT", text: env.ENVIRONMENT || "production" },
    { type: "plain_text", name: "WORKER_NAME", text: workerName },
    { type: "plain_text", name: "CF_ACCOUNT_ID", text: env.CF_ACCOUNT_ID },
    { type: "secret_text", name: "CF_API_TOKEN", text: env.CF_API_TOKEN },
    { type: "secret_text", name: "API_KEY", text: env.API_KEY },
    { type: "secret_text", name: "SPOTIFY_CLIENT_ID", text: env.SPOTIFY_CLIENT_ID },
    { type: "secret_text", name: "SPOTIFY_CLIENT_SECRET", text: env.SPOTIFY_CLIENT_SECRET }
  ];
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
    console.log(`Deployed ${latestHash.slice(0, 8)}`);
    return true;
  }
  return false;
}
async function checkForUpdates(env) {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID || !env.WORKER_NAME)
    return;
  const lockAcquired = await acquireUpdateLock(env.SPOTIFY_DATA);
  if (!lockAcquired) {
    console.log("Update lock held by another invocation, skipping");
    return;
  }
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
    if (!storedHash) {
      await env.SPOTIFY_DATA.put("_worker_hash", latestHash);
      return;
    }
    await deployWorkerCode(env, env.WORKER_NAME, latestCode, latestHash);
  } catch (e) {
    console.error("Auto-update failed:", e);
  } finally {
    await releaseUpdateLock(env.SPOTIFY_DATA);
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
    <p class="hint">Use the API key you chose during setup</p>
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
</style></head>
<body>
  <div class="card">
    <h1>API Proxy</h1>
    <div class="error">Invalid API key</div>
    <form method="POST">
      <input type="password" name="key" placeholder="API Key" autofocus required />
      <button type="submit">Login</button>
    </form>
    <p class="hint">Use the API key you chose during setup</p>
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
  const workerName = env.WORKER_NAME || new URL(request.url).hostname.split(".")[0];
  const lockAcquired = await acquireUpdateLock(env.SPOTIFY_DATA);
  if (!lockAcquired) {
    return Response.json(
      { updated: false, message: "Another update is in progress. Try again in a moment." },
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
    const didUpdate = await deployWorkerCode(env, workerName, latestCode, latestHash);
    if (!didUpdate && !storedHash) {
      await env.SPOTIFY_DATA.put("_worker_hash", latestHash);
      return Response.json(
        { updated: false, message: "Version hash initialized. Already running latest code." },
        { headers: corsHeaders }
      );
    }
    return Response.json(
      { updated: didUpdate, message: didUpdate ? "Updated successfully." : "Update failed. Check worker logs." },
      { headers: corsHeaders }
    );
  } catch (e) {
    return Response.json(
      { updated: false, message: "Update failed: " + e.message },
      { status: 500, headers: corsHeaders }
    );
  } finally {
    await releaseUpdateLock(env.SPOTIFY_DATA);
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
  if (request.method === "POST") {
    return handleCredentialsSubmit(request, env);
  }
  const apiKey = generateSecureApiKey();
  const origin = new URL(request.url).origin;
  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Setup</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; padding: 20px; }
  .container { max-width: 520px; margin: 40px auto; }
  .card { background: white; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); padding: 32px; }
  h1 { font-size: 1.4em; color: #333; margin-bottom: 8px; }
  .subtitle { color: #888; font-size: 0.9em; margin-bottom: 24px; }
  label { display: block; font-weight: 600; font-size: 14px; color: #444; margin-bottom: 6px; }
  input { width: 100%; padding: 10px 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 14px; font-family: inherit; margin-bottom: 4px; }
  input:focus { outline: none; border-color: #1db954; }
  .field { margin-bottom: 18px; }
  .hint { font-size: 12px; color: #888; margin-top: 4px; }
  .hint a { color: #1db954; }
  button { width: 100%; padding: 12px; background: #1db954; color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; margin-top: 8px; }
  button:hover { background: #1ed760; }
  .divider { border: none; border-top: 1px solid #eee; margin: 24px 0; }
  .section-label { font-size: 13px; font-weight: 600; color: #888; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 16px; }
  .error { background: #fde8e8; color: #c62828; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
</style></head>
<body>
<div class="container">
  <div class="card">
    <h1>Proxy Setup</h1>
    <p class="subtitle">Configure your API key and app credentials</p>

    <div id="error-box"></div>

    <form method="POST" id="setup-form">
      <div class="section-label">Authentication</div>

      <div class="field">
        <label for="api_key">API Key</label>
        <input type="text" name="api_key" id="api_key" value="${apiKey}" required />
        <p class="hint">Auto-generated. Change it or keep it \u2014 you'll need it to log in.</p>
      </div>

      <hr class="divider" />
      <div class="section-label">App Credentials</div>

      <div class="field">
        <label for="client_id">Client ID</label>
        <input type="text" name="client_id" id="client_id" placeholder="Your Spotify Client ID" required />
        <p class="hint">From <a href="https://developer.spotify.com/dashboard" target="_blank">developer.spotify.com/dashboard</a></p>
      </div>

      <div class="field">
        <label for="client_secret">Client Secret</label>
        <input type="password" name="client_secret" id="client_secret" placeholder="Your Spotify Client Secret" required />
      </div>

      <div class="field">
        <label>Callback URL</label>
        <input type="text" value="${origin}/callback" readonly style="background: #f9f9f9; color: #666;" />
        <p class="hint">Add this URL to your Spotify app's redirect URIs</p>
      </div>

      <button type="submit">Save &amp; Continue</button>
    </form>
  </div>
</div>
</body></html>`;
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}
async function handleCredentialsSubmit(request, env) {
  const formData = await request.formData();
  const apiKey = (formData.get("api_key") || "").trim();
  const clientId = (formData.get("client_id") || "").trim();
  const clientSecret = (formData.get("client_secret") || "").trim();
  if (!apiKey || !clientId || !clientSecret) {
    return new Response("All fields are required.", { status: 400 });
  }
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) {
    return new Response("Auto-configuration not available (missing CF_API_TOKEN).", { status: 500 });
  }
  const workerName = env.WORKER_NAME || new URL(request.url).hostname.split(".")[0];
  const cfApi = "https://api.cloudflare.com/client/v4";
  const secretsUrl = `${cfApi}/accounts/${env.CF_ACCOUNT_ID}/workers/scripts/${workerName}/secrets`;
  const secrets = [
    { name: "API_KEY", text: apiKey, type: "secret_text" },
    { name: "SPOTIFY_CLIENT_ID", text: clientId, type: "secret_text" },
    { name: "SPOTIFY_CLIENT_SECRET", text: clientSecret, type: "secret_text" }
  ];
  const errors = [];
  for (const secret of secrets) {
    const resp = await fetch(secretsUrl, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${env.CF_API_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(secret)
    });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      const msg = data.errors?.map((e) => e.message).join(", ") || resp.statusText;
      errors.push(`${secret.name}: ${msg}`);
    }
  }
  if (errors.length > 0) {
    return new Response("Failed to save credentials: " + errors.join("; "), { status: 500 });
  }
  _cachedTokens = null;
  await env.SPOTIFY_DATA.delete("spotify_tokens");
  const setupUrl = new URL("/setup", request.url).toString();
  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Saving...</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); text-align: center; max-width: 380px; }
  h1 { font-size: 1.3em; color: #333; margin-bottom: 12px; }
  p { color: #888; font-size: 14px; }
</style>
<script>
  let attempt = 0;
  async function check() {
    attempt++;
    try {
      const r = await fetch("${setupUrl}");
      // 200 = setup page ready; anything other than 404 means secrets propagated
      if (r.ok) {
        window.location.href = "${setupUrl}";
        return;
      }
    } catch {}
    if (attempt < 15) setTimeout(check, 2000);
    else window.location.href = "${setupUrl}";
  }
  setTimeout(check, 2000);
<\/script>
</head>
<body>
  <div class="card">
    <h1>Credentials saved</h1>
    <p>Waiting for changes to take effect...</p>
  </div>
</body></html>`;
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" }
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
  const callbackTokens = {
    ...tokenResponse.data,
    obtained_at: Date.now()
  };
  await env.SPOTIFY_DATA.put("spotify_tokens", JSON.stringify(callbackTokens));
  const cbExpiresAt = callbackTokens.obtained_at + ((callbackTokens.expires_in || 3600) - 300) * 1e3;
  _cachedTokens = { data: callbackTokens, expiresAt: cbExpiresAt };
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
async function handleQueue(request, env) {
  const tokens = await getStoredTokens(env);
  if (!tokens) {
    return new Response(
      JSON.stringify({ error: "Not configured." }),
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
    "/v1/me/player/queue",
    tokens.access_token
  );
  if (!spotifyResponse.ok) {
    return new Response(
      JSON.stringify({ error: "Failed to fetch queue" }),
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
  if (_cachedTokens && Date.now() < _cachedTokens.expiresAt) {
    return _cachedTokens.data;
  }
  const tokensJson = await env.SPOTIFY_DATA.get("spotify_tokens");
  if (!tokensJson) {
    _cachedTokens = null;
    return null;
  }
  const tokens = JSON.parse(tokensJson);
  const expiresIn = tokens.expires_in || 3600;
  const obtainedAt = tokens.obtained_at || 0;
  const tokenExpiresAt = obtainedAt + (expiresIn - 300) * 1e3;
  const isExpired = Date.now() > tokenExpiresAt;
  if (isExpired && tokens.refresh_token && env.SPOTIFY_CLIENT_ID && env.SPOTIFY_CLIENT_SECRET) {
    const refreshed = await refreshAccessToken(tokens.refresh_token, env);
    if (refreshed) {
      const newTokens = {
        ...tokens,
        ...refreshed,
        obtained_at: Date.now()
      };
      await env.SPOTIFY_DATA.put("spotify_tokens", JSON.stringify(newTokens));
      const newExpiresAt = newTokens.obtained_at + ((newTokens.expires_in || 3600) - 300) * 1e3;
      _cachedTokens = { data: newTokens, expiresAt: newExpiresAt };
      return newTokens;
    }
  }
  _cachedTokens = { data: tokens, expiresAt: tokenExpiresAt };
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
