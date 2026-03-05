# Latent: Zero-Trust Distributed Chat

Latent is a decentralized, high-performance chat platform where **Identity is Sovereign** (powered by ATProto) and **Storage is Distributed** (independent backends).

This repository is designed for multi-platform flexibility. You can host your own client on any static provider and your own backend on Cloudflare or any Docker-compatible host.

---

## 🏗 Deployment Guide

### 1. The Client (Static Hosting)
The client is a single-page application (SPA). You can deploy it to any provider that supports static assets.

#### **Cloudflare Pages (Recommended)**
1. Ensure `wrangler` is installed.
2. Run: `bun run deploy:client`
3. Configure your custom domain in the Cloudflare Dashboard.

#### **Netlify**
1. Ensure `netlify-cli` is installed.
2. Run: `bun run deploy:client-netlify`
3. This uses the pre-configured `packages/client-netlify/netlify.toml` for SPA routing.

---

### 2. The Backend (Distributed Storage)
Latent backends are stateless identity relays. They verify users via DPoP proofs and store message data locally.

#### **Cloudflare Workers (D1 + Durable Objects)**
Ideal for low-cost, global edge distribution.
1. `cd packages/server`
2. Update `wrangler.toml` with your account details and D1 database ID.
3. Run: `bun x wrangler deploy`
4. *Note:* Real-time WebSockets are powered by Durable Objects.

#### **Docker / Bun (SQLite)**
Ideal for self-hosting on VPS, Fly.io, or Railway.
1. `cd packages/server-docker`
2. **Fly.io Deployment**:
   - `fly launch` (first time)
   - `fly deploy --remote-only --yes --config fly.toml --dockerfile Dockerfile`
3. This implementation uses a local `data.db` SQLite file. Ensure you have a persistent volume mounted at `/app/data`.

---

### 3. Identity Configuration (ATProto)
To allow users to log in via BlueSky/ATProto, you must host a valid `client-metadata.json` at your production origin.

1. Edit `client-metadata.json` in the project root.
2. Update `client_id` and `redirect_uris` to match your domain (e.g., `https://chat.example.com/`).
3. Deploy the client; the file will be served at `your-domain.com/client-metadata.json`.

---

## 🛠 Local Development

### Prerequisites
- [Bun](https://bun.sh)
- [Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/) (for Cloudflare testing)

### Commands
| Command | Description |
| :--- | :--- |
| `bun run dev:client` | Start the frontend on `http://127.0.0.1:3010` |
| `bun run dev:docker` | Start the local Bun/SQLite backend on port `8789` |
| `bun run dev:server` | Start local Cloudflare Worker backend on port `8787` |
| `bun run build` | Build the frontend production bundle |

---

## 🔒 Security Mandates
- **Stateless Verification**: Backends never store private keys. They verify identity by relaying browser-signed proofs to the user's PDS.
- **DPoP Compliance**: All API calls are secured with DPoP-bound tokens.
- **Stateless Sessions**: Servers issue short-lived (24hr) session tokens after the first DPoP verification to maximize speed without compromising security.
