# proxify – Spotify API Proxy

A personal Spotify API proxy that you can deploy to your own Cloudflare Workers account. Exposes simple endpoints like `/now-playing` and `/recent` without worrying about CORS or managing a server.

## Deploy

**[Deploy Now](https://diva-ravioli.github.io/proxify/deploy-web.html)** — deploys directly to your Cloudflare account from your browser. No GitHub account or CLI needed.

You'll need a free [Cloudflare account](https://dash.cloudflare.com/sign-up) with:

1. **API Token** — [Create one here](https://dash.cloudflare.com/profile/api-tokens) with **Workers Scripts: Edit** and **Workers KV Storage: Edit** permissions
2. **Account ID** — visible in your Cloudflare Dashboard URL: `dash.cloudflare.com/<account-id>/...`

After deployment, visit your worker URL and the built-in setup UI will walk you through configuring your Spotify credentials and completing the OAuth flow.

## Setup

After deployment, visit your worker URL. You'll be guided through:

1. **API Key** — A key is generated for you. Set it as an encrypted `API_KEY` variable in the Cloudflare dashboard.
2. **Spotify Credentials** — Create a [Spotify Developer App](https://developer.spotify.com/dashboard), then set `SPOTIFY_CLIENT_ID` and `SPOTIFY_CLIENT_SECRET` as encrypted variables.
3. **OAuth** — Connect your Spotify account with one click.

All configuration is done through the worker's web UI and the Cloudflare dashboard — no CLI required.

## API Endpoints

All endpoints except `/health`, `/credentials`, `/setup`, and `/callback` require an `Authorization: Bearer YOUR_API_KEY` header.

| Endpoint | Description |
|----------|-------------|
| `/` | Home / status page |
| `/now-playing` | Current track and playback state |
| `/recent` | Recently played tracks (last 10) |
| `/health` | Health check and configuration status |
| `/setup` | OAuth setup |
| `/credentials` | Credential setup instructions |

### Example: `/now-playing`

```json
{
  "is_playing": true,
  "item": {
    "name": "Song Name",
    "artists": [{"name": "Artist Name"}],
    "album": {
      "name": "Album Name",
      "images": [{"url": "https://..."}]
    }
  },
  "progress_ms": 45000
}
```

## Development

```bash
npm install
npm run dev
```

The worker will be available at `http://localhost:8787`.

To rebuild the compiled worker (used by the web deploy page):

```bash
npm run build
```

## Security

- API key authentication on all data endpoints
- All credentials stored as encrypted Cloudflare Workers secrets
- OAuth tokens stored temporarily in Cloudflare KV
- All Spotify API calls are server-side

## Troubleshooting

- **Deployment fails** — Check that your API token has both Workers Scripts and KV Storage edit permissions
- **OAuth errors** — Make sure your Spotify app callback URL matches `https://your-worker.workers.dev/callback`
- **"No valid tokens"** — Complete the credential and OAuth setup via the worker's web UI
- Check `/health` for current configuration status
