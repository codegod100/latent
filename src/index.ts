import express from 'express'
import {
  NodeOAuthClient,
  type NodeSavedSession,
  type NodeSavedState,
} from '@atproto/oauth-client-node'

// 1. CONFIGURATION
const PORT = 3010
const APP_ORIGIN = `http://127.0.0.1:${PORT}`
const REDIRECT_URI = `${APP_ORIGIN}/callback`
const SESSION_COOKIE = 'atproto_did'

// ATProto Loopback Client ID
const clientMetadata = {
  client_id: `http://localhost/?redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=atproto%20transition:generic`,
  client_name: 'Multi-Server Identity Proxy',
  application_type: 'web' as const,
  token_endpoint_auth_method: 'none' as const,
  dpop_bound_access_tokens: true,
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  redirect_uris: [REDIRECT_URI],
  scope: 'atproto transition:generic',
}

// 2. STORES (Memory)
const stateStore = new Map<string, NodeSavedState>()
const sessionStore = new Map<string, NodeSavedSession>()

const oauthClient = new NodeOAuthClient({
  allowHttp: true,
  clientMetadata,
  stateStore: {
    set: async (k, v) => { stateStore.set(k, v) },
    get: async (k) => stateStore.get(k),
    del: async (k) => { stateStore.delete(k) },
  },
  sessionStore: {
    set: async (k, v) => { sessionStore.set(k, v) },
    get: async (k) => sessionStore.get(k),
    del: async (k) => { sessionStore.delete(k) },
  },
})

const app = express()
app.use(express.json())

const getSessionDid = (req: express.Request) => {
  const cookie = req.headers.cookie?.split('; ').find(row => row.startsWith(SESSION_COOKIE + '='))
  return cookie ? decodeURIComponent(cookie.split('=')[1]) : null
}

// 3. ROUTES
app.get('/', (req, res) => {
  const did = getSessionDid(req)
  if (did) return res.redirect('/app')
  res.send(`
    <body style="font-family:system-ui; padding:2rem; max-width:400px; margin:auto;">
      <h1>ATProto Identity Gateway</h1>
      <p>Log in once here to use your identity across multiple servers.</p>
      <form method="POST" action="/login">
        <input name="handle" placeholder="nandi.latha.org" required style="width:100%; padding:0.5rem; margin-bottom:1rem;">
        <button type="submit" style="width:100%; padding:0.5rem; background:#007bff; color:white; border:none; border-radius:4px; cursor:pointer;">Login</button>
      </form>
    </body>
  `)
})

app.post('/login', express.urlencoded({ extended: true }), async (req, res, next) => {
  try {
    const authUrl = await oauthClient.authorize(req.body.handle)
    res.redirect(authUrl.toString())
  } catch (err) { next(err) }
})

app.get('/callback', async (req, res, next) => {
  try {
    const params = new URLSearchParams(req.url.split('?')[1])
    const { session } = await oauthClient.callback(params)
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(session.did)}; Path=/; HttpOnly; SameSite=Lax`)
    res.redirect('/app')
  } catch (err) { next(err) }
})

app.get('/app', async (req, res) => {
  const did = getSessionDid(req)
  if (!did) return res.redirect('/')

  try {
    const session = await oauthClient.restore(did)
    res.send(`
      <body style="font-family:system-ui; padding:2rem; max-width:600px; margin:auto;">
        <h1>Gateway Active</h1>
        <p>Logged in as: <code>${session.did}</code></p>
        <p>PDS: <code>${session.serverMetadata.issuer}</code></p>
        
        <div style="border:1px solid #ccc; padding:1rem; border-radius:8px; background:#f9f9f9;">
          <h3>Proxy Action</h3>
          <p>The button below calls a <strong>Non-ATProto Endpoint</strong> on this server. This server then proxies the request to your PDS to verify you.</p>
          <button id="proxyBtn" style="padding:0.5rem 1rem; background:#28a745; color:white; border:none; border-radius:4px; cursor:pointer;">
            Verify Identity (Backend Relay)
          </button>
        </div>
        <br>
        <a href="/logout">Logout</a>
        <pre id="log" style="background:#111; color:#0f0; padding:1rem; border-radius:4px; margin-top:1rem; display:none;"></pre>

        <script>
          document.getElementById('proxyBtn').onclick = async () => {
            const el = document.getElementById('log');
            el.style.display = 'block';
            el.textContent = 'Calling proxy...';
            const res = await fetch('/api/proxy-verify');
            const data = await res.json();
            el.textContent = JSON.stringify(data, null, 2);
          };
        </script>
      </body>
    `)
  } catch (err) { res.redirect('/logout') }
})

// 4. THE PROXY ENDPOINT
// This is your "Non-ATProto" logic. It uses the library to safely
// verify the user with the PDS without exposing raw tokens to the browser.
app.get('/api/proxy-verify', async (req, res) => {
  const did = getSessionDid(req)
  if (!did) return res.status(401).json({ error: 'Auth required' })

  try {
    console.log(`[proxy] Verifying session for ${did}`)
    const session = await oauthClient.restore(did)
    
    // The library handles DPoP, nonces, and binding automatically here!
    const pdsRes = await session.fetchHandler('/xrpc/com.atproto.server.getSession')
    const data = await pdsRes.json()

    res.json({
      ok: pdsRes.ok,
      message: 'Identity verified by PDS',
      user: data
    })
  } catch (err) {
    res.status(500).json({ error: String(err) })
  }
})

app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; Max-Age=0`)
  res.redirect('/')
})

app.listen(PORT, '127.0.0.1', () => console.log(`Server running at http://127.0.0.1:${PORT}`))
