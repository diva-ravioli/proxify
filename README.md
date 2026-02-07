# proxify – Spotify API Proxy

A personal Spotify API proxy that you can deploy to your own Cloudflare Workers account. Exposes simple endpoints like `/now-playing`, `/recent`, and `/queue` without worrying about CORS or managing a server.

## Deploy

**[Deploy Now](https://diva-ravioli.github.io/proxify/deploy-web.html)** — deploys directly to your Cloudflare account from your browser. No GitHub account or CLI needed.

You'll need a free [Cloudflare account](https://dash.cloudflare.com/sign-up) with:

1. **API Token** — [Create one here](https://dash.cloudflare.com/profile/api-tokens) with **Workers Scripts: Edit** and **Workers KV Storage: Edit** permissions
2. **Account ID** — visible in your Cloudflare Dashboard URL: `dash.cloudflare.com/<account-id>/...`

## Setup

After deployment, visit your worker URL. The built-in setup UI walks you through everything — no Cloudflare dashboard configuration needed.

1. **Credentials** — Enter your API key and Spotify app credentials directly in the form. They're saved as Worker secrets automatically.
2. **OAuth** — Connect your Spotify account with one click.

You'll need a [Spotify Developer App](https://developer.spotify.com/dashboard) with the callback URL set to `https://your-worker.workers.dev/callback`.

## API Endpoints

All endpoints require an `Authorization: Bearer YOUR_API_KEY` header.

| Endpoint | Description |
|----------|-------------|
| `/now-playing` | Current track and playback state |
| `/recent` | Recently played tracks (last 10) |
| `/queue` | Player queue (currently playing + upcoming) |
| `/health` | Health check and configuration status |

The root `/` serves a login form for the admin dashboard (enter your API key to view stats and trigger updates).

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

## Auto-Updates

Deployed workers check for updates every 6 hours and automatically redeploy when new code is available.

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
- Credentials stored as encrypted Cloudflare Workers secrets
- OAuth tokens stored in Cloudflare KV with automatic refresh
- All Spotify API calls are server-side

## Troubleshooting

- **Deployment fails** — Check that your API token has both Workers Scripts and KV Storage edit permissions
- **OAuth errors** — Make sure your Spotify app callback URL matches `https://your-worker.workers.dev/callback`
- **"Not configured"** — Complete the credential and OAuth setup via the worker's web UI
- Check `/health` for current configuration status
