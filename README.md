# Zero-Trust ATProto Identity Proxy

This project demonstrates a **Zero-Trust Architecture** for authenticating users via the AT Protocol (Bluesky) on unowned or untrusted third-party servers. 

## The Core Theory

In traditional OAuth, a "Trusted Backend" handles the session, stores the private keys, and manages the tokens. In this project, we invert that model. We treat the backend as a **Stateless Messenger** and the browser as the **Sole Sovereign** of the user's identity.

### 1. Public Client vs. Confidential Client
- **Confidential Client (Standard)**: The server owns the private keys. If the server is compromised, all user sessions are at risk.
- **Public Client (This Project)**: The **Browser** generates an asymmetric ES256 key pair via the WebCrypto API. The private key never leaves the browser's IndexedDB. The token issued by the PDS is cryptographically bound to **this specific browser key**.

### 2. DPoP (Demonstrating Proof-of-Possession)
The heart of this system is **DPoP (RFC 9449)**. Unlike standard Bearer tokens which can be stolen and reused, a DPoP-bound token is useless without a matching "Proof."

A **DPoP Proof** is a short-lived JWT signed by the browser that includes:
- `htm`: The HTTP method (e.g., GET)
- `htu`: The exact URL being called (e.g., the PDS verification endpoint)
- `ath`: A hash of the Access Token itself
- `jkt`: The thumbprint of the browser's public key

### 3. The Identity Proxy Handshake
To "log in" to an untrusted server without giving it your session, the following sequence occurs:

1. **Sign**: The Browser creates a DPoP proof signed specifically for the PDS `getProfile` endpoint.
2. **Relay**: The Browser sends its **Access Token** and this **Proof** to the untrusted Backend.
3. **Verify**: The Backend (which has no ATProto auth code) simply "proxies" these credentials to the user's PDS.
4. **Confirm**: The PDS acts as a global "Identity Notary." If the PDS returns `200 OK`, the Backend is mathematically certain that the request came from the person who owns that DID, because only they could have signed that specific proof.

## Architecture

The project is split into two isolated Cloudflare projects to ensure zero shared state:

### Frontend (`packages/client`)
- **Host**: Cloudflare Pages (Static)
- **Library**: `@atproto/oauth-client-browser`
- **Role**: Key management, OAuth dance, signing identity proofs.
- **Storage**: Browser-local only (IndexedDB).

### Backend (`packages/server`)
- **Host**: Cloudflare Worker
- **Storage**: Cloudflare D1 (SQLite)
- **Role**: Stateless relay and authorized storage. It only saves data to the database **after** the PDS confirms the user's identity via the relayed proof.

## Why this matters
This pattern allows for the creation of decentralized applications where you can interact with any number of "unowned" servers (message boards, games, analytics) using your single ATProto identity, without those servers ever being able to "impersonate" you or steal your account.

---

## Development

### Prerequisites
- [Bun](https://bun.sh)
- [Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/) (Cloudflare CLI)

### Commands
- `bun run build`: Bundle the frontend client.
- `bun run dev:client`: Start local Pages server (Port 3010).
- `bun run dev:server`: Start local Worker server (Port 8787).
- `bun run deploy:client`: Deploy to Cloudflare Pages.
- `bun run deploy:server`: Deploy to Cloudflare Workers.
