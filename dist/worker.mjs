// src/index.ts
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
      const setupComplete = isSetupComplete(env);
      if (pathname === "/callback") {
        return handleCallback(request, env);
      }
      if (!setupComplete) {
        switch (pathname) {
          case "/":
            return Response.redirect(
              new URL("/credentials", request.url).toString(),
              302
            );
          case "/credentials":
            return handleCredentials(request, env);
          case "/setup":
            return handleSetup(request, env);
          default:
            return notFound();
        }
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
  }
};
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
    JSON.stringify(tokenResponse.data),
    { expirationTtl: 3600 }
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
  return tokensJson ? JSON.parse(tokensJson) : null;
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
                <li>Make sure to check <strong>"Encrypt"</strong> (this makes it a secret)</li>
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
