import express from 'express'
import * as path from 'node:path'

const PORT = 3010
const APP_ORIGIN = `http://127.0.0.1:${PORT}`
const REDIRECT_URI = `${APP_ORIGIN}/`
const CLIENT_ID = `http://localhost/?redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=atproto%20transition:generic`

const app = express()
app.use(express.json())

// Serve the bundled frontend
app.use('/public', express.static('public'))

// 1. STATELESS METADATA
app.get('/client-metadata.json', (req, res) => {
  res.json({
    client_id: CLIENT_ID,
    client_name: 'Canonical Browser Client',
    application_type: 'web',
    token_endpoint_auth_method: 'none',
    dpop_bound_access_tokens: true,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: [REDIRECT_URI],
    scope: 'atproto transition:generic',
  })
})

// 2. THE "UNOWNED" EXTERNAL SERVER
app.post('/api/external-verify', async (req, res) => {
  const { accessToken, dpopProof, pdsUrl, did } = req.body
  try {
    const probeUrl = `${String(pdsUrl).replace(/\/+$/, '')}/xrpc/app.bsky.actor.getProfile?actor=${did}`
    console.log('[external-server] Verifying identity via: ' + probeUrl)
    
    const pdsRes = await fetch(probeUrl, {
      headers: { 'Authorization': `DPoP ${accessToken}`, 'DPoP': dpopProof }
    })
    
    const dpopNonce = pdsRes.headers.get('dpop-nonce')
    const data = await pdsRes.json()
    
    res.status(pdsRes.status).json({
      external_server_verified: pdsRes.ok,
      pdsResponse: data,
      dpopNonce
    })
  } catch (err) {
    res.status(500).json({ error: String(err) })
  }
})

// 3. THE MAIN PAGE
app.get('/', (req, res) => {
  res.send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Canonical ATProto Client</title>
  <style>
    body { font-family: system-ui; max-width: 800px; margin: 2rem auto; line-height: 1.5; padding: 0 1rem; }
    .panel { border: 1px solid #ccc; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem; background: #fdfdfd; }
    button { padding: 0.6rem 1.2rem; cursor: pointer; background: #007bff; color: white; border: none; border-radius: 4px; font-weight: bold; }
    pre { background: #111; color: #0f0; padding: 1rem; border-radius: 6px; overflow: auto; max-height: 400px; font-size: 0.85rem; }
    input { padding: 0.5rem; width: 300px; border: 1px solid #ccc; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>Canonical Browser-Bound Client</h1>
  <p>Uses the official <code>@atproto/oauth-client-browser</code> library bundled with Bun.</p>

  <div id="login-panel" class="panel">
    <label style="display:block; font-weight:bold;">Handle</label>
    <input id="handle" value="nandi.latha.org" placeholder="handle.bsky.social">
    <button onclick="startLogin()">Login via PDS</button>
  </div>

  <div id="app-panel" class="panel" style="display:none">
    <h3>Session Active (Managed by Library)</h3>
    <p>DID: <code id="user-did"></code></p>
    <button onclick="verifyWithExternalServer()" style="background: #28a745;">Verify with External Server</button>
    <button onclick="localStorage.clear();location.href='/'" style="background:#666; margin-left:1rem;">Logout</button>
  </div>

  <pre id="console">Loading bundle...</pre>

  <!-- Load our Bun-built bundle -->
  <script src="/public/bundle.js"></script>
</body>
</html>
  `)
})

app.listen(PORT, '127.0.0.1', () => console.log(`Server listening on ${APP_ORIGIN}`))
