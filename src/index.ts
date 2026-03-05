import express from 'express'
import { randomUUID } from 'node:crypto'
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

import * as fs from 'node:fs'
import * as path from 'node:path'

// 2. STORES (File-based for persistence across restarts)
const SESSION_FILE = path.resolve('sessions.json')
const STATE_FILE = path.resolve('states.json')

function loadMap(file: string) {
  if (!fs.existsSync(file)) return new Map()
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'))
    return new Map(Object.entries(data))
  } catch (e) { return new Map() }
}

function saveMap(file: string, map: Map<string, any>) {
  fs.writeFileSync(file, JSON.stringify(Object.fromEntries(map), null, 2))
}

const stateStoreMap = loadMap(STATE_FILE)
const sessionStoreMap = loadMap(SESSION_FILE)

const oauthClient = new NodeOAuthClient({
  allowHttp: true,
  clientMetadata: {
    client_id: `http://localhost/?redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=atproto%20transition:generic`,
    client_name: 'ATProto Identity Proxy',
    application_type: 'web',
    token_endpoint_auth_method: 'none',
    dpop_bound_access_tokens: true,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: [REDIRECT_URI],
    scope: 'atproto transition:generic',
  },
  stateStore: {
    set: async (k, v) => { stateStoreMap.set(k, v); saveMap(STATE_FILE, stateStoreMap) },
    get: async (k) => stateStoreMap.get(k),
    del: async (k) => { stateStoreMap.delete(k); saveMap(STATE_FILE, stateStoreMap) },
  },
  sessionStore: {
    set: async (k, v) => { sessionStoreMap.set(k, v); saveMap(SESSION_FILE, sessionStoreMap) },
    get: async (k) => sessionStoreMap.get(k),
    del: async (k) => { sessionStoreMap.delete(k); saveMap(SESSION_FILE, sessionStoreMap) },
  },
})

const app = express()
app.use(express.json())

const getSessionDid = (req: express.Request) => {
  const cookie = req.headers.cookie?.split('; ').find(row => row.startsWith(SESSION_COOKIE + '='))
  return cookie ? decodeURIComponent(cookie.split('=')[1]) : null
}

// 2. ROUTES
app.get('/', (req, res) => {
  if (getSessionDid(req)) return res.redirect('/app')
  res.send(`
    <body style="font-family:system-ui; padding:2rem; max-width:400px; margin:auto;">
      <h1>ATProto Identity Proxy</h1>
      <form method="POST" action="/login" style="display:flex; flex-direction:column; gap:1rem;">
        <input name="handle" placeholder="your-handle.bsky.social" required style="padding:0.5rem;">
        <button type="submit" style="padding:0.5rem; background:#007bff; color:white; border:none; border-radius:4px; cursor:pointer;">Login</button>
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

// 3. THE PROXY LOGIC: Generate a proof for an External Server
app.get('/api/get-external-proof', async (req, res, next) => {
  const did = getSessionDid(req)
  const targetUrl = req.query.url as string
  const nonce = req.query.nonce as string | undefined
  if (!did || !targetUrl) return res.status(400).json({ error: 'Missing session or target url' })

  try {
    const session = await oauthClient.restore(did)
    const tokenSet = await (session as any).getTokenSet('auto')
    
    // Manual proof generation using the session's internal key
    const key = (session as any).server.dpopKey
    // Filter for a signing algorithm (DPoP requires signing, not encryption like ECDH-ES)
    const alg = key.algorithms.find((a: string) => a.startsWith('ES') || a.startsWith('RS')) || 'ES256'
    const jwk = key.bareJwk
    const now = Math.floor(Date.now() / 1000)
    
    // Calculate Access Token Hash (ath)
    const { createHash } = await import('node:crypto')
    const ath = createHash('sha256').update(tokenSet.access_token).digest('base64url')

    const dpopJwt = await key.createJwt(
      { alg, typ: 'dpop+jwt', jwk },
      {
        iat: now,
        jti: randomUUID(),
        htm: 'GET',
        htu: targetUrl.split('?')[0].split('#')[0],
        ath,
        nonce // Include the nonce if provided
      }
    )

    res.json({
      accessToken: tokenSet.access_token,
      dpopProof: dpopJwt,
      pdsUrl: String(tokenSet.aud).replace(/\/+$/, ''), // Strip trailing slashes
      did: session.did
    })
  } catch (err) {
    next(err)
  }
})

app.get('/app', async (req, res) => {
  const did = getSessionDid(req)
  if (!did) return res.redirect('/')

  try {
    const session = await oauthClient.restore(did)
    res.send(`
      <body style="font-family:system-ui; padding:2rem; max-width:600px; margin:auto;">
        <h1>Client Gateway Active</h1>
        <p>Logged in as: <code>${session.did}</code></p>
        
        <div style="border:1px solid #ccc; padding:1.5rem; border-radius:8px; background:#f9f9f9;">
          <h3>Connect to External "Unowned" Server</h3>
          <p>The button below calls a <strong>Non-ATProto Server</strong> endpoint. Our backend provides the signed identity proof.</p>
          <button id="callBtn" style="padding:0.7rem 1.5rem; background:#28a745; color:white; border:none; border-radius:4px; cursor:pointer;">
            Prove Identity to External Server
          </button>
        </div>
        <br>
        <a href="/logout">Logout</a>
        <pre id="log" style="background:#111; color:#0f0; padding:1rem; border-radius:4px; margin-top:1rem; display:none; overflow:auto;"></pre>

        <script>
          document.getElementById('callBtn').onclick = async () => {
            const el = document.getElementById('log');
            el.style.display = 'block';
            el.textContent = '1. Requesting signed proof for external server...\\n';
            
            // The external server's verification endpoint
            const targetUrl = '${APP_ORIGIN}/api/mock-external-verify';
            
            const verify = async (nonce = null) => {
              // 1. Get credentials and signed proof for the SPECIFIC verification endpoint
              // Note: the backend handles the mapping now
              const probeUrlBase = '/api/get-external-proof?url=';
              
              // We need to know the target PDS endpoint to sign for it
              // For the demo, we'll get the metadata first
              const credsRes = await fetch('/api/get-external-proof?url=' + encodeURIComponent('placeholder'));
              const initialCreds = await credsRes.json();
              
              const actualProbeUrl = initialCreds.pdsUrl + '/xrpc/app.bsky.actor.getProfile?actor=' + initialCreds.did;
              
              const finalUrl = '/api/get-external-proof?url=' + encodeURIComponent(actualProbeUrl) + (nonce ? '&nonce=' + encodeURIComponent(nonce) : '');
              const proofRes = await fetch(finalUrl);
              const creds = await proofRes.json();
              
              el.textContent += '2. Sending proof to external server...\\n';
              
              const res = await fetch('/api/mock-external-verify', {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify(creds)
              });
              
              const data = await res.json();
              
              if (!res.ok && data.pds_response?.error === 'use_dpop_nonce') {
                const newNonce = data.pds_response.dpopNonce || res.headers.get('dpop-nonce');
                if (newNonce) {
                  el.textContent += 'Challenge: Nonce received, retrying...\\n';
                  return verify(newNonce);
                }
              }
              
              el.textContent += '3. Final Response:\\n' + JSON.stringify(data, null, 2);
            };

            try {
              await verify();
            } catch (e) {
              el.textContent += 'Error: ' + e.message;
            }
          };
        </script>
      </body>
    `)
  } catch (err) { res.redirect('/logout') }
})

app.post('/api/mock-external-verify', async (req, res) => {
  const { accessToken, dpopProof, pdsUrl, did } = req.body
  
  try {
    // We use a resource-level endpoint (getProfile) to verify the token.
    // This is more reliable for OAuth tokens than getSession.
    const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${did}`
    console.log('[external-server] probing URL: ' + probeUrl)
    
    const pdsRes = await fetch(probeUrl, {
      headers: { 
        'Authorization': `DPoP ${accessToken}`,
        'DPoP': dpopProof 
      }
    })
    
    console.log('[external-server] PDS response status: ' + pdsRes.status + ' content-type: ' + pdsRes.headers.get('content-type'))
    
    const dpopNonce = pdsRes.headers.get('dpop-nonce')
    const contentType = pdsRes.headers.get('content-type') || ''
    
    if (!contentType.includes('application/json')) {
      const text = await pdsRes.text()
      console.error('[external-server] PDS returned non-JSON: ' + text.slice(0, 200))
      return res.status(500).json({ error: 'PDS returned non-JSON response', status: pdsRes.status, preview: text.slice(0, 100) })
    }

    const data = await pdsRes.json()
    
    res.status(pdsRes.status).json({
      external_server_verified: pdsRes.ok,
      identity: pdsRes.ok ? { did: data.did, handle: data.handle } : null,
      pds_response: { ...data, dpopNonce }
    })
  } catch (err) {
    res.status(500).json({ error: String(err) })
  }
})

app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; Max-Age=0`)
  res.redirect('/')
})

app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[server error]', err)
  res.status(500).json({ error: String(err), stack: err.stack })
})

app.listen(PORT, '127.0.0.1', () => console.log(`Server running at ${APP_ORIGIN}`))
