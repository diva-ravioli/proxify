/**
 * Cloudflare Worker — API proxy with OAuth.
 */

export interface Env {
  SPOTIFY_DATA: KVNamespace;
  SPOTIFY_CLIENT_ID: string;
  SPOTIFY_CLIENT_SECRET: string;
  API_KEY: string;
  ENVIRONMENT: string;
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
}

const WORKER_SOURCE_URL =
  "https://raw.githubusercontent.com/diva-ravioli/proxify/main/dist/worker.mjs";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

const notFound = () => new Response("Not Found", { status: 404 });

function isSetupComplete(env: Env): boolean {
  return !!(env.API_KEY && env.SPOTIFY_CLIENT_ID && env.SPOTIFY_CLIENT_SECRET);
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Store worker name for auto-updates (derived from hostname)
    const workerName = url.hostname.split(".")[0];
    ctx.waitUntil(env.SPOTIFY_DATA.put("_worker_name", workerName));

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      const setupComplete = isSetupComplete(env);

      // /callback must always be public (OAuth redirect target)
      if (pathname === "/callback") {
        return handleCallback(request, env);
      }

      // When setup is NOT complete, only expose setup-related pages
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

      // Setup IS complete — everything requires auth, nothing leaks
      const authResult = await requireApiKey(request, env);
      if (authResult) return authResult;

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
        headers: corsHeaders,
      });
    }
  },

  async scheduled(
    event: ScheduledEvent,
    env: Env,
    ctx: ExecutionContext
  ): Promise<void> {
    ctx.waitUntil(checkForUpdates(env));
  },
};

/**
 * Self-update: fetch latest worker source and re-deploy if changed.
 */
async function checkForUpdates(env: Env): Promise<void> {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return;

  try {
    // Fetch latest source from repo
    const resp = await fetch(WORKER_SOURCE_URL);
    if (!resp.ok) return;
    const latestCode = await resp.text();

    // Hash it and compare with stored hash
    const hashBuffer = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(latestCode)
    );
    const latestHash = Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    const storedHash = await env.SPOTIFY_DATA.get("_worker_hash");
    if (storedHash === latestHash) return; // No update needed

    // Determine worker name from KV or fallback
    // We store it during first update check
    let workerName = await env.SPOTIFY_DATA.get("_worker_name");
    if (!workerName) {
      // Try to get it from the account's worker list — skip update on first run,
      // just store the current hash so next time we can compare
      await env.SPOTIFY_DATA.put("_worker_hash", latestHash);
      return;
    }

    // Re-deploy with the new code
    const kvList = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/storage/kv/namespaces?per_page=100`,
      { headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` } }
    );
    const kvData: any = await kvList.json();
    const kvNamespace = kvData.result?.find(
      (ns: any) => ns.title.includes("SPOTIFY_DATA")
    );
    if (!kvNamespace) return;

    // Re-include all bindings so nothing is lost
    const bindings: any[] = [
      { type: "kv_namespace", name: "SPOTIFY_DATA", namespace_id: kvNamespace.id },
      { type: "plain_text", name: "ENVIRONMENT", text: env.ENVIRONMENT || "production" },
      { type: "plain_text", name: "CF_ACCOUNT_ID", text: env.CF_ACCOUNT_ID },
      { type: "secret_text", name: "CF_API_TOKEN", text: env.CF_API_TOKEN },
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
      compatibility_date: "2024-01-01",
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
        body: formData,
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

/**
 * Handle setup endpoint - OAuth configuration
 */
async function handleSetup(request: Request, env: Env): Promise<Response> {
  // Check if we have Spotify credentials configured as secrets
  const hasSpotifyCredentials = !!(
    env.SPOTIFY_CLIENT_ID && env.SPOTIFY_CLIENT_SECRET
  );

  if (!hasSpotifyCredentials) {
    // No credentials configured, redirect to credentials page
    return Response.redirect(
      new URL("/credentials", request.url).toString(),
      302
    );
  }

  // If POST request, handle OAuth initiation
  if (request.method === "POST") {
    const redirectUri = `${new URL(request.url).origin}/callback`;
    const scope =
      "user-read-currently-playing user-read-recently-played user-read-playback-state";
    const state = generateRandomString(16);

    // Store state in KV for verification
    await env.SPOTIFY_DATA.put(`oauth_state_${state}`, "pending", {
      expirationTtl: 600,
    });

    const authUrl =
      `https://accounts.spotify.com/authorize?` +
      `response_type=code&` +
      `client_id=${env.SPOTIFY_CLIENT_ID}&` +
      `scope=${encodeURIComponent(scope)}&` +
      `redirect_uri=${encodeURIComponent(redirectUri)}&` +
      `state=${state}`;

    return Response.redirect(authUrl, 302);
  }

  // Return setup HTML
  const html = await getSetupHTML();
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      ...corsHeaders,
    },
  });
}

/**
 * Handle credentials endpoint - Store Spotify app credentials
 */
async function handleCredentials(
  request: Request,
  env: Env
): Promise<Response> {
  // Show credentials setup page (secrets-based approach only)
  const html = await getCredentialsHTML(undefined, request.url, env);
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      ...corsHeaders,
    },
  });
}

/**
 * Handle OAuth callback
 */
async function handleCallback(request: Request, env: Env): Promise<Response> {
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

  // Verify state
  const storedState = await env.SPOTIFY_DATA.get(`oauth_state_${state}`);
  if (!storedState) {
    return new Response("Invalid or expired state parameter", { status: 400 });
  }

  // Exchange code for tokens
  const tokenResponse = await exchangeCodeForTokens(code, request.url, env);
  if (!tokenResponse.success) {
    return new Response(`Token exchange failed: ${tokenResponse.error}`, {
      status: 400,
    });
  }

  // Store tokens in KV
  await env.SPOTIFY_DATA.put(
    "spotify_tokens",
    JSON.stringify(tokenResponse.data),
    { expirationTtl: 3600 }
  );

  // Clean up state
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
        ...corsHeaders,
      },
    }
  );
}

/**
 * Handle now-playing endpoint
 */
async function handleNowPlaying(request: Request, env: Env): Promise<Response> {
  const tokens = await getStoredTokens(env);
  if (!tokens) {
    return new Response(
      JSON.stringify({
        error: "Not configured.",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders,
        },
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
          ...corsHeaders,
        },
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
          ...corsHeaders,
        },
      }
    );
  }

  const data = await spotifyResponse.json();
  return new Response(JSON.stringify(data), {
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
    },
  });
}

/**
 * Handle recent tracks endpoint
 */
async function handleRecent(request: Request, env: Env): Promise<Response> {
  const tokens = await getStoredTokens(env);
  if (!tokens) {
    return new Response(
      JSON.stringify({
        error: "Not configured.",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders,
        },
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
          ...corsHeaders,
        },
      }
    );
  }

  const data = await spotifyResponse.json();
  return new Response(JSON.stringify(data), {
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
    },
  });
}

/**
 * Handle health check endpoint
 */
async function handleHealth(request: Request, env: Env): Promise<Response> {
  const tokens = await getStoredTokens(env);
  const hasValidCredentials = !!(
    env.SPOTIFY_CLIENT_ID && env.SPOTIFY_CLIENT_SECRET
  );
  const hasValidTokens = tokens !== null;
  const hasApiKey = !!env.API_KEY;

  const health = {
    status: "ok",
    timestamp: new Date().toISOString(),
    credentials_configured: hasValidCredentials,
    oauth_configured: hasValidTokens,
    ready: hasApiKey && hasValidCredentials && hasValidTokens,
  };

  return new Response(JSON.stringify(health, null, 2), {
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
    },
  });
}

/**
 * Utility Functions
 */

function generateRandomString(length: number): string {
  const charset =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return result;
}

function generateSecureApiKey(): string {
  const charset =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let result = "";
  for (let i = 0; i < 64; i++) {
    result += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return result;
}

async function exchangeCodeForTokens(
  code: string,
  callbackUrl: string,
  env: Env
) {
  const redirectUri = new URL(callbackUrl).origin + "/callback";

  if (!env.SPOTIFY_CLIENT_ID || !env.SPOTIFY_CLIENT_SECRET) {
    return {
      success: false,
      error: "Credentials not configured.",
    };
  }

  const response = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${btoa(
        `${env.SPOTIFY_CLIENT_ID}:${env.SPOTIFY_CLIENT_SECRET}`
      )}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code,
      redirect_uri: redirectUri,
    }),
  });

  if (!response.ok) {
    return {
      success: false,
      error: `Token exchange failed: ${response.statusText}`,
    };
  }

  const data = await response.json();
  return { success: true, data };
}

async function getStoredTokens(env: Env) {
  const tokensJson = await env.SPOTIFY_DATA.get("spotify_tokens");
  return tokensJson ? JSON.parse(tokensJson) : null;
}

async function callSpotifyAPI(endpoint: string, accessToken: string) {
  return fetch(`https://api.spotify.com${endpoint}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  });
}

async function getSetupHTML(): Promise<string> {
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

async function getCredentialsHTML(
  errorMessage?: string,
  requestUrl?: string,
  env?: Env
): Promise<string> {
  const origin = requestUrl
    ? new URL(requestUrl).origin
    : "https://your-worker.workers.dev";
  const apiKey = generateSecureApiKey();

  // Build direct link to worker settings in CF dashboard
  const workerName = requestUrl
    ? new URL(requestUrl).hostname.split(".")[0]
    : "";
  const cfAccountId = env?.CF_ACCOUNT_ID || "";
  const dashboardUrl = cfAccountId && workerName
    ? `https://dash.cloudflare.com/${cfAccountId}/workers/services/view/${workerName}/production/settings#variables`
    : "https://dash.cloudflare.com/";

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
      </script>
    </body>
    </html>
  `;
}

/**
 * Authentication helper functions
 */

async function requireApiKey(
  request: Request,
  env: Env
): Promise<Response | null> {
  const authHeader = request.headers.get("Authorization");

  if (!authHeader) {
    return new Response(
      JSON.stringify({
        error:
          "Unauthorized.",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders,
        },
      }
    );
  }

  if (!authHeader.startsWith("Bearer ")) {
    return new Response(
      JSON.stringify({
        error:
          "Unauthorized.",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders,
        },
      }
    );
  }

  const providedApiKey = authHeader.slice(7); // Remove "Bearer " prefix

  if (!env.API_KEY) {
    return new Response(
      JSON.stringify({
        error:
          "Unauthorized.",
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders,
        },
      }
    );
  }

  if (providedApiKey !== env.API_KEY) {
    return new Response(
      JSON.stringify({
        error: "Unauthorized.",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders,
        },
      }
    );
  }

  return null; // Auth successful
}
