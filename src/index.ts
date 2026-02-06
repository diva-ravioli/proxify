/**
 * Spotify Proxy - Cloudflare Worker
 *
 * A personal Spotify API proxy that handles OAuth authentication
 * and provides simple endpoints for accessing Spotify data.
 */

export interface Env {
  SPOTIFY_DATA: KVNamespace;
  SPOTIFY_CLIENT_ID: string;
  SPOTIFY_CLIENT_SECRET: string;
  API_KEY: string;
  ENVIRONMENT: string;
}

// CORS headers for all responses
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Handle preflight requests
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Require API key authentication for all endpoints except health and setup endpoints
      const publicEndpoints = [
        "/health",
        "/credentials",
        "/setup",
        "/callback",
      ];
      if (!publicEndpoints.includes(pathname)) {
        const authResult = await requireApiKey(request, env);
        if (authResult) return authResult; // Return 401 if auth failed
      }

      // Route handling
      switch (pathname) {
        case "/":
          return handleRoot(request, env);
        case "/setup":
          return handleSetup(request, env);
        case "/credentials":
          return handleCredentials(request, env);
        case "/callback":
          return handleCallback(request, env);
        case "/now-playing":
          return handleNowPlaying(request, env);
        case "/recent":
          return handleRecent(request, env);
        case "/health":
          return handleHealth(request, env);
        default:
          return new Response("Not Found", {
            status: 404,
            headers: corsHeaders,
          });
      }
    } catch (error) {
      console.error("Error handling request:", error);
      return new Response("Internal Server Error", {
        status: 500,
        headers: corsHeaders,
      });
    }
  },
};

/**
 * Handle root endpoint - redirect to setup
 */
async function handleRoot(request: Request, env: Env): Promise<Response> {
  const hasApiKey = !!env.API_KEY;
  const hasSpotifyCredentials = !!(
    env.SPOTIFY_CLIENT_ID && env.SPOTIFY_CLIENT_SECRET
  );
  const storedTokens = await getStoredTokens(env);

  // If no API key or Spotify credentials, redirect to credentials setup
  if (!hasApiKey || !hasSpotifyCredentials) {
    return Response.redirect(
      new URL("/credentials", request.url).toString(),
      302
    );
  }

  let setupStatus = "not_started";
  let nextAction = "/credentials";
  let nextActionText = "Setup Credentials";

  if (hasSpotifyCredentials) {
    if (storedTokens) {
      setupStatus = "complete";
      nextAction = "/now-playing";
      nextActionText = "View Now Playing";
    } else {
      setupStatus = "credentials_only";
      nextAction = "/setup";
      nextActionText = "Connect Spotify Account";
    }
  }

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Spotify Proxy</title>
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
          text-align: center;
        }
        .button {
          display: inline-block;
          padding: 12px 24px;
          background: #1db954;
          color: white;
          text-decoration: none;
          border-radius: 25px;
          margin: 10px;
          font-size: 16px;
        }
        .button:hover { background: #1ed760; }
        .button.secondary {
          background: #666;
          font-size: 14px;
          padding: 8px 16px;
        }
        .button.secondary:hover { background: #888; }
        .status {
          padding: 15px;
          border-radius: 5px;
          margin: 20px 0;
        }
        .status.complete { background: #e8f5e8; color: #2e7d32; }
        .status.partial { background: #fff3e0; color: #f57c00; }
        .status.pending { background: #e3f2fd; color: #1976d2; }
        .endpoints {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 10px;
          margin: 20px 0;
        }
        .endpoint {
          padding: 10px;
          background: #f9f9f9;
          border-radius: 5px;
          text-align: left;
        }
        .endpoint a {
          color: #1db954;
          text-decoration: none;
          font-weight: bold;
        }
        .endpoint a:hover {
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🎵 Spotify Proxy</h1>
        <p>Your personal Spotify API proxy</p>

        <div class="info" style="background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <h3>🔐 Secure Authentication</h3>
          <p>This proxy is secured with API key authentication via Cloudflare secrets. Include your API key in requests:</p>
          <code style="background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-family: monospace;">Authorization: Bearer YOUR_API_KEY</code>
        </div>

        ${
          setupStatus === "complete"
            ? `
          <div class="status complete">
            ✅ <strong>Setup Complete!</strong><br>
            Your Spotify account is connected and ready to use.
          </div>
        `
            : setupStatus === "credentials_only"
            ? `
          <div class="status partial">
            ⚠️ <strong>Credentials Set, OAuth Pending</strong><br>
            Connect your Spotify account to start using the proxy.
          </div>
        `
            : `
          <div class="status pending">
            🔧 <strong>Setup Required</strong><br>
            Enter your Spotify app credentials to get started.
          </div>
        `
        }

        <div>
          <a href="${nextAction}" class="button">${nextActionText}</a>
          <a href="/health" class="button secondary">Health Check</a>
        </div>

        ${
          setupStatus === "complete"
            ? `
          <div class="endpoints">
            <div class="endpoint">
              <a href="/now-playing">/now-playing</a>
              <div>Current track & playback</div>
            </div>
            <div class="endpoint">
              <a href="/recent">/recent</a>
              <div>Recently played tracks</div>
            </div>
            <div class="endpoint">
              <a href="/health">/health</a>
              <div>API status & health</div>
            </div>
          </div>
        `
            : ""
        }

        ${
          setupStatus !== "not_started"
            ? `
          <div style="margin-top: 20px;">
            <a href="/credentials" class="button secondary">Update Credentials</a>
          </div>
        `
            : ""
        }
      </div>
    </body>
    </html>
  `;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html",
      ...corsHeaders,
    },
  });
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
      "Content-Type": "text/html",
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
  const html = await getCredentialsHTML(undefined, request.url);
  return new Response(html, {
    headers: {
      "Content-Type": "text/html",
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
      <head><title>OAuth Success</title></head>
      <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h1>✅ OAuth Setup Complete!</h1>
        <p>Your Spotify account has been successfully connected.</p>
        <p>You can now use the API endpoints:</p>
        <ul style="display: inline-block; text-align: left;">
          <li><a href="/now-playing">/now-playing</a></li>
          <li><a href="/recent">/recent</a></li>
          <li><a href="/health">/health</a></li>
        </ul>
        <p><a href="/">&larr; Back to Home</a></p>
      </body>
    </html>
  `,
    {
      headers: {
        "Content-Type": "text/html",
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
        error: "No valid tokens found. Please complete OAuth setup first.",
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
        error: "No valid tokens found. Please complete OAuth setup first.",
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
    status: "healthy",
    timestamp: new Date().toISOString(),
    environment: env.ENVIRONMENT || "unknown",
    api_key_configured: hasApiKey,
    credentials_configured: hasValidCredentials,
    oauth_configured: hasValidTokens,
    setup_complete: hasApiKey && hasValidCredentials && hasValidTokens,
    next_step: !hasApiKey
      ? "Configure secrets (API key + Spotify credentials) at /credentials"
      : !hasValidCredentials
      ? "Configure Spotify credentials at /credentials"
      : !hasValidTokens
      ? "Complete OAuth setup at /setup"
      : "Ready to use API endpoints",
    endpoints: {
      home: "/",
      credentials: "/credentials",
      setup: "/setup",
      callback: "/callback",
      now_playing: "/now-playing",
      recent: "/recent",
      health: "/health",
    },
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
      error: "No Spotify credentials configured. Please complete setup first.",
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
      <title>Spotify Proxy Setup</title>
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
        <h1>🎵 Spotify Proxy Setup</h1>

        <div class="info">
          <h3>✅ Credentials Configured</h3>
          <p>Your Spotify app credentials are ready. Now connect your account!</p>
        </div>

        <div class="step">
          <h3>Step 1: Authorize with Spotify</h3>
          <p>Click the button below to connect your Spotify account:</p>
          <form method="POST">
            <button type="submit" class="button">🔗 Connect Spotify Account</button>
          </form>
        </div>

        <div class="step">
          <h3>Step 2: Test Your Setup</h3>
          <p>After authorization, test these endpoints:</p>
          <ul>
            <li><a href="/now-playing">/now-playing</a> - Current track</li>
            <li><a href="/recent">/recent</a> - Recent tracks</li>
            <li><a href="/health">/health</a> - Health check</li>
          </ul>
        </div>

        <p>
          <a href="/">&larr; Back to Home</a> |
          <a href="/credentials" class="button secondary">Update Credentials</a>
        </p>
      </div>
    </body>
    </html>
  `;
}

async function getCredentialsHTML(
  errorMessage?: string,
  requestUrl?: string
): Promise<string> {
  const origin = requestUrl
    ? new URL(requestUrl).origin
    : "https://your-worker.workers.dev";
  const apiKey = generateSecureApiKey();

  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Spotify Proxy - Setup</title>
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
        <h1>🔐 Spotify Proxy Setup</h1>

        <div class="warning">
          <h3>⚠️ Secure Setup Required</h3>
          <p>Your Spotify proxy needs both an API key and Spotify credentials configured as Cloudflare secrets for maximum security.</p>
        </div>

        ${errorMessage ? `<div class="error">❌ ${errorMessage}</div>` : ""}

        <!-- API Key Section -->
        <div class="section">
          <h2>🔑 Step 1: API Key Setup</h2>

          <div class="step">
            <h3>Generate Your API Key</h3>
            <p>We've generated a secure API key for you:</p>
            <div class="api-key" id="apiKey">${apiKey}</div>
            <button class="button secondary" onclick="copyApiKey()">📋 Copy API Key</button>
            <button class="button secondary" onclick="generateNewKey()">🔄 Generate New Key</button>
          </div>

          <div class="step">
            <h3>Set API_KEY Secret in Cloudflare</h3>
            <p><strong>Open your Cloudflare Workers dashboard:</strong></p>

            <a href="https://dash.cloudflare.com/" target="_blank" class="button dashboard">🌩️ Open Cloudflare Dashboard</a>

            <div style="margin: 20px 0;">
              <p><strong>Instructions:</strong></p>
              <ol>
                <li>Navigate to <strong>Workers & Pages</strong> → <strong>Your Worker</strong></li>
                <li>Go to <strong>Settings</strong> → <strong>Variables</strong></li>
                <li>Under <strong>"Environment Variables"</strong>, click <strong>"Add variable"</strong></li>
                <li>Set <strong>Variable name:</strong> <code>API_KEY</code></li>
                <li>Set <strong>Value:</strong> paste the API key from above</li>
                <li>✅ Make sure to check <strong>"Encrypt"</strong> (this makes it a secret)</li>
                <li>Click <strong>"Save and deploy"</strong></li>
              </ol>
            </div>
          </div>
        </div>

        <!-- Spotify Credentials Section -->
        <div class="section">
          <h2>🎵 Step 2: Spotify App Setup</h2>

          <div class="info">
            <h3>Get Spotify Credentials:</h3>
            <ol>
              <li>Go to <a href="https://developer.spotify.com/dashboard" target="_blank">Spotify Developer Dashboard</a></li>
              <li>Create a new app (or use existing)</li>
              <li>Copy your <strong>Client ID</strong> and <strong>Client Secret</strong></li>
              <li>Add this callback URL: <code>${origin}/callback</code></li>
            </ol>
          </div>

          <div class="step">
            <h3>Set Spotify Secrets in Cloudflare</h3>
            <p>Follow the same process as above to set these two additional secrets:</p>

            <div style="margin: 15px 0; padding: 10px; background: #f0f0f0; border-radius: 5px;">
              <strong>Secret 1:</strong><br>
              Variable name: <code>SPOTIFY_CLIENT_ID</code><br>
              Value: Your Spotify Client ID<br>
              ✅ Check "Encrypt"
            </div>

            <div style="margin: 15px 0; padding: 10px; background: #f0f0f0; border-radius: 5px;">
              <strong>Secret 2:</strong><br>
              Variable name: <code>SPOTIFY_CLIENT_SECRET</code><br>
              Value: Your Spotify Client Secret<br>
              ✅ Check "Encrypt"
            </div>
          </div>
        </div>



        <!-- Next Steps -->
        <div class="step">
          <h3>🚀 Step 3: Complete Setup</h3>
          <p>After setting all secrets in Cloudflare Dashboard:</p>
          <ol>
            <li>Refresh this page to verify secrets are configured</li>
            <li>Proceed to OAuth setup to connect your Spotify account</li>
            <li>Start using your secured Spotify proxy!</li>
          </ol>

          <div style="margin: 20px 0;">
            <a href="/health" class="button" target="_blank">🔍 Check Configuration Status</a>
            <a href="/setup" class="button">▶️ Continue to OAuth Setup</a>
          </div>
        </div>

        <div class="info">
          <h3>🔐 Why Use Cloudflare Secrets?</h3>
          <ul>
            <li><strong>Maximum Security</strong> - Encrypted and never exposed in code or logs</li>
            <li><strong>Environment Isolation</strong> - Different secrets for development/production</li>
            <li><strong>Industry Standard</strong> - Best practice for sensitive credentials</li>
            <li><strong>No CLI Required</strong> - Set everything via the web dashboard</li>
          </ul>
        </div>

        <p><a href="/">&larr; Back to Home</a></p>
      </div>

      <script>
        let currentApiKey = '${apiKey}';

        function copyApiKey() {
          navigator.clipboard.writeText(currentApiKey).then(() => {
            const btn = event.target;
            const originalText = btn.textContent;
            btn.textContent = '✅ Copied!';
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
          "Missing Authorization header. Include 'Authorization: Bearer YOUR_API_KEY' in your request.",
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
          "Invalid Authorization header format. Use 'Authorization: Bearer YOUR_API_KEY'.",
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
          "API key not configured. Please set up via Cloudflare dashboard.",
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
        error: "Invalid API key.",
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
