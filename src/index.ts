import express from 'express'
import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import {
  NodeOAuthClient,
  type NodeSavedSession,
  type NodeSavedState,
  type OAuthClientMetadataInput,
} from '@atproto/oauth-client-node'
import type { LexiconDoc } from '@atproto/lexicon'
import { createServer } from '@atproto/xrpc-server'

const PORT = Number(process.env.PORT ?? 3010)
const HOST = process.env.HOST ?? '127.0.0.1'
const APP_ORIGIN = process.env.APP_ORIGIN ?? `http://${HOST}:${PORT}`
const REDIRECT_URI = process.env.REDIRECT_URI ?? `http://127.0.0.1:${PORT}/callback`
const OAUTH_SCOPE = process.env.OAUTH_SCOPE ?? 'atproto transition:generic'
const SESSION_COOKIE = 'atproto_did'
const APP_AUTH_SECRET = process.env.APP_AUTH_SECRET ?? 'dev-change-me'
const DERIVED_TOKEN_TTL_SECONDS = Number(process.env.DERIVED_TOKEN_TTL_SECONDS ?? 300)

class MemoryStore<V> {
  private readonly data = new Map<string, V>()

  async set(key: string, value: V): Promise<void> {
    this.data.set(key, value)
  }

  async get(key: string): Promise<V | undefined> {
    return this.data.get(key)
  }

  async del(key: string): Promise<void> {
    this.data.delete(key)
  }
}

type AppAuthPayload = {
  iat: number
  did: string
  exp: number
  iss: string
  aud: string
  scope: string
  source: 'atproto-oauth'
}

function toBase64Url(input: string | Buffer): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function fromBase64Url(input: string): Buffer {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  return Buffer.from(padded, 'base64')
}

function signAppAuthToken(payload: AppAuthPayload): string {
  const header = { alg: 'HS256', typ: 'JWT' }
  const encodedHeader = toBase64Url(JSON.stringify(header))
  const encodedPayload = toBase64Url(JSON.stringify(payload))
  const data = `${encodedHeader}.${encodedPayload}`
  const signature = createHmac('sha256', APP_AUTH_SECRET).update(data).digest()
  return `${data}.${toBase64Url(signature)}`
}

function verifyAppAuthToken(token: string): AppAuthPayload | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const [encodedHeader, encodedPayload, encodedSignature] = parts
  const data = `${encodedHeader}.${encodedPayload}`
  const expected = createHmac('sha256', APP_AUTH_SECRET).update(data).digest()
  const provided = fromBase64Url(encodedSignature)
  if (expected.length !== provided.length) return null
  if (!timingSafeEqual(expected, provided)) return null

  const payload = JSON.parse(fromBase64Url(encodedPayload).toString('utf8')) as AppAuthPayload
  if (!payload.did || !payload.exp) return null
  if (Date.now() >= payload.exp * 1000) return null
  return payload
}

const clientMetadata: OAuthClientMetadataInput = {
  client_id: `http://localhost/?redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=${encodeURIComponent(OAUTH_SCOPE)}`,
  client_name: 'Local ATProto App',
  application_type: 'web',
  token_endpoint_auth_method: 'none',
  dpop_bound_access_tokens: true,
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  redirect_uris: [REDIRECT_URI],
  scope: OAUTH_SCOPE,
}

type NodeSavedStateWithKey = NodeSavedState & { browserPublicKey?: any }

const stateStore = new MemoryStore<NodeSavedStateWithKey>()
const sessionStore = new MemoryStore<NodeSavedSession>()

const oauthClient = new NodeOAuthClient({
  allowHttp: true,
  clientMetadata,
  stateStore,
  sessionStore,
})
console.log('[oauth] client initialized with client_id=' + clientMetadata.client_id)

const lexicons: LexiconDoc[] = [
  {
    lexicon: 1,
    id: 'com.example.echo',
    defs: {
      main: {
        type: 'query',
        description: 'Returns data for an XRPC request',
        parameters: {
          type: 'params',
          required: ['name'],
          properties: {
            name: { type: 'string' },
            flavor: { type: 'string', default: 'vanilla' },
          },
        },
        output: {
          encoding: 'application/json',
          schema: {
            type: 'object',
            required: ['ok', 'greeting', 'time'],
            properties: {
              ok: { type: 'boolean' },
              greeting: { type: 'string' },
              time: { type: 'string' },
              flavor: { type: 'string' },
              authedDid: { type: 'string' },
            },
          },
        },
      },
    },
  },
]

const xrpc = createServer(lexicons)
xrpc.method('com.example.echo', ({ params, req }) => {
  const name = String(params.name)
  const flavor = params.flavor ? String(params.flavor) : 'vanilla'
  const traceId = req.header('x-trace-id') ?? 'no-trace'
  const authDid = ((req as express.Request & { authedDid?: string }).authedDid ?? 'none')

  console.log(`[${traceId}] [xrpc] received request name=${name} flavor=${flavor}`)
  console.log(`[${traceId}] [xrpc] verified auth did=${authDid}`)

  return {
    encoding: 'application/json',
    body: {
      ok: true,
      greeting: `hello ${name}`,
      flavor,
      time: new Date().toISOString(),
      // surfaced so you can verify the auth value passed through the cycle
      authedDid: authDid || 'none',
    },
  }
})

const app = express()
app.use(express.urlencoded({ extended: true }))
app.use(express.json())

function parseCookies(req: express.Request): Record<string, string> {
  const raw = req.header('cookie') ?? ''
  const out: Record<string, string> = {}

  for (const part of raw.split(';')) {
    const trimmed = part.trim()
    if (!trimmed) continue
    const eq = trimmed.indexOf('=')
    if (eq === -1) continue
    const key = trimmed.slice(0, eq)
    const value = trimmed.slice(eq + 1)
    out[key] = decodeURIComponent(value)
  }

  return out
}

function getSessionDid(req: express.Request): string | null {
  const cookies = parseCookies(req)
  return cookies[SESSION_COOKIE] ?? null
}

app.get('/', (req, res) => {
  const did = getSessionDid(req)
  if (did) {
    res.redirect('/app')
    return
  }
  res.type('html').send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ATProto OAuth Localhost Demo</title>
    <style>
      body { font-family: ui-sans-serif, system-ui; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
      form, code { display: block; margin-top: 1rem; }
      input { width: 100%; padding: 0.5rem; margin-top: 0.25rem; }
      button { margin-top: 1rem; padding: 0.6rem 1rem; }
    </style>
  </head>
  <body>
    <h1>ATProto OAuth (localhost)</h1>
    <p>Start auth, then complete callback at <code>/callback</code>.</p>
    <form id="loginForm" method="post" action="/login">
      <label>Handle (ex: alice.bsky.social)</label>
      <input id="handle" name="handle" required />
      <label>App state (optional)</label>
      <input id="state" name="state" />
      <input type="hidden" id="browserPublicKey" name="browserPublicKey" />
      <button type="submit">Sign in with ATProto</button>
    </form>
    <script>
      async function getOrCreateKeyJwk() {
        const stored = localStorage.getItem('dpop_pub')
        if (stored) return JSON.parse(stored)
        
        const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])
        const pubJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
        const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)
        
        localStorage.setItem('dpop_pub', JSON.stringify(pubJwk))
        localStorage.setItem('dpop_key', JSON.stringify(privJwk))
        return pubJwk
      }

      const form = document.getElementById('loginForm')
      form.addEventListener('submit', async (e) => {
        e.preventDefault()
        try {
          const jwk = await getOrCreateKeyJwk()
          document.getElementById('browserPublicKey').value = JSON.stringify(jwk)
          form.submit()
        } catch (err) {
          alert('Failed to generate DPoP key: ' + err.message)
        }
      })
    </script>
    <p>After login, you will be redirected to <code>/app</code> with a button that triggers an authenticated backend XRPC call.</p>
  </body>
</html>`)
})

app.get('/client-metadata.json', (_req, res) => {
  res.type('application/json').send(clientMetadata)
})

app.get('/jwks.json', (_req, res) => {
  res.type('application/json').send(oauthClient.jwks)
})

app.post('/login', async (req, res, next) => {
  try {
    const handle = String(req.body.handle || '').trim()
    const browserPublicKey = req.body.browserPublicKey // JWK from browser
    
    // Explicitly generate state so we can track it reliably even with PAR
    const state = String(req.body.state || '').trim() || randomUUID()

    if (!handle) {
      res.status(400).json({ error: 'Missing handle' })
      return
    }

    console.log('[oauth] starting authorize for handle=' + handle + ' state=' + state)
    const authUrl = await oauthClient.authorize(handle, {
      state,
    })

    console.log('[oauth] authorize produced url=' + authUrl.toString())
    res.redirect(authUrl.toString())
  } catch (err) {
    console.error('[oauth] authorize failed', err)
    next(err)
  }
})

// Debug endpoint to see what's in the store (for development only)
app.get('/api/debug/state', async (req, res) => {
  const state = String(req.query.state ?? '')
  const saved = await stateStore.get(state)
  res.json({
    requestedState: state,
    found: !!saved,
    saved: saved ? { ...saved, pkce: 'redacted' } : null
  })
})

app.get('/callback', async (req, res, next) => {
  try {
    const qs = req.originalUrl.split('?')[1] ?? ''
    const params = new URLSearchParams(qs)
    const state = params.get('state')
    const code = params.get('code')

    if (!state || !code) {
      res.status(400).send('Missing state or code')
      return
    }

    // Instead of completing the callback here, we send the code back to the /app
    // so the browser can sign the exchange request with its private key.
    res.redirect(`/app?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`)
  } catch (err) {
    next(err)
  }
})

app.post('/api/exchange-code', async (req, res, next) => {
  const traceId = randomUUID()
  try {
    const { code, state, dpopJwt, browserPublicKey } = req.body
    console.log('[' + traceId + '] [api] exchange-code start for state=' + state)

    if (!code || !state || !dpopJwt) {
      res.status(400).json({ error: 'Missing code, state, or dpopJwt' })
      return
    }

    const savedState = await stateStore.get(state)
    if (!savedState) {
      console.error('[' + traceId + '] [api] exchange-code: state not found')
      res.status(400).json({ error: 'Invalid or expired state' })
      return
    }

    // We need to find the token endpoint for the issuer
    console.log('[' + traceId + '] [api] exchange-code: resolving agent for ' + savedState.iss)
    const { metadata } = await (oauthClient as any).oauthResolver.resolve(savedState.iss)
    const tokenEndpoint = metadata.token_endpoint

    console.log('[' + traceId + '] [api] exchange-code: hitting PDS relay=' + tokenEndpoint)
    
    // Manual exchange using browser's proof
    const body = new URLSearchParams()
    body.append('grant_type', 'authorization_code')
    body.append('code', code)
    body.append('redirect_uri', REDIRECT_URI)
    body.append('client_id', clientMetadata.client_id!)
    if ((savedState as any).pkce) {
      body.append('code_verifier', (savedState as any).pkce.verifier)
    }

    const headers: Record<string, string> = {
      'content-type': 'application/x-www-form-urlencoded',
      'dpop': dpopJwt,
    }

    const tokenRes = await fetch(tokenEndpoint, {
      method: 'POST',
      headers,
      body: body.toString(),
    })

    // Capture nonce for retry if needed
    const dpopNonce = tokenRes.headers.get('dpop-nonce')

    const data = await tokenRes.json()
    console.log('[' + traceId + '] [api] exchange-code: PDS response status=' + tokenRes.status)

    if (!tokenRes.ok) {
      console.error('[' + traceId + '] [api] exchange-code: failed', data)
      res.status(tokenRes.status).json({ ...data, dpopNonce })
      return
    }

    // Save the session manually in sessionStore
    const did = data.sub
    console.log('[' + traceId + '] [api] exchange-code: success for did=' + did)
    
    const session: any = {
      tokenSet: {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        token_type: data.token_type,
        scope: data.scope,
        expires_at: data.expires_in ? new Date(Date.now() + data.expires_in * 1000).toISOString() : undefined,
        iss: savedState.iss,
        sub: did,
        aud: data.aud || savedState.iss,
      },
      dpopKey: browserPublicKey, // Stored directly from request
    }

    await sessionStore.set(did, session)
    await stateStore.del(state)

    const cookie = `${SESSION_COOKIE}=${encodeURIComponent(did)}; Path=/; HttpOnly; SameSite=Lax`
    res.setHeader('Set-Cookie', cookie)

    res.json({ ok: true, did, accessToken: data.access_token })
  } catch (err) {
    console.error('[' + traceId + '] [api] exchange-code error', err)
    next(err)
  }
})

import * as jose from 'jose'

app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', SESSION_COOKIE + '=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')
  res.redirect('/')
})

app.get('/api/token-endpoint', async (req, res, next) => {
  const traceId = randomUUID()
  try {
    const state = String(req.query.state ?? '')
    console.log('[' + traceId + '] [api] token-endpoint request for state=' + state)
    
    const savedState = await stateStore.get(state)
    if (!savedState) {
      console.log('[' + traceId + '] [api] token-endpoint: state not found in store')
      res.status(404).json({ error: 'State not found' })
      return
    }

    console.log('[' + traceId + '] [api] token-endpoint: state found, issuer=' + savedState.iss)
    const { metadata } = await (oauthClient as any).oauthResolver.resolve(savedState.iss)
    const endpoint = metadata.token_endpoint
    
    console.log('[' + traceId + '] [api] token-endpoint: resolved to ' + endpoint)
    res.json({ tokenEndpoint: endpoint })
  } catch (err) {
    console.error('[' + traceId + '] [api] token-endpoint failed', err)
    next(err)
  }
})

app.get('/app', async (req, res) => {
  const did = getSessionDid(req)
  const code = req.query.code

  // If we have a code, we are in the middle of a browser-side exchange.
  // We don't need to restore the session yet.
  if (code) {
    return res.type('html').send(`<!doctype html>
<html>
  <head>
    <title>Finalizing Login...</title>
    <style>body { font-family: system-ui; padding: 2rem; }</style>
  </head>
  <body>
    <h1>Finalizing Login...</h1>
    <pre id="log">Exchanging code for browser-bound token...</pre>
    <script>
      // Reuse the same logic but simplified for the splash screen
      async function createDPoPProof(method, url, accessToken, nonce = null) {
        const priv = JSON.parse(localStorage.getItem('dpop_key'))
        const pub = JSON.parse(localStorage.getItem('dpop_pub'))
        const privateKey = await crypto.subtle.importKey('jwk', priv, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])
        
        const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '')
        const strB64 = (str) => b64(new TextEncoder().encode(str))

        const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: pub }
        const payload = {
          jti: crypto.randomUUID(),
          htm: method,
          htu: url,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 60,
        }
        if (accessToken) {
          payload.ath = b64(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken)))
        }
        if (nonce) payload.nonce = nonce

        const encodedHeader = strB64(JSON.stringify(header))
        const encodedPayload = strB64(JSON.stringify(payload))
        const data = encodedHeader + '.' + encodedPayload
        const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, new TextEncoder().encode(data))
        return data + '.' + b64(signature)
      }

      async function finalize() {
        const urlParams = new URLSearchParams(window.location.search)
        const code = urlParams.get('code')
        const state = urlParams.get('state')
        const logEl = document.getElementById('log')
        const storedPub = localStorage.getItem('dpop_pub')
        const browserPublicKey = storedPub ? JSON.parse(storedPub) : null

        try {
          const statusRes = await fetch('/api/token-endpoint?state=' + encodeURIComponent(state))
          const statusData = await statusRes.json()
          const tokenEndpoint = statusData.tokenEndpoint
          
          if (!tokenEndpoint) {
            throw new Error('Could not resolve token endpoint for this session')
          }

          // The PDS URL is usually the origin of the token endpoint
          let pdsUrl = ''
          try {
            pdsUrl = new URL(tokenEndpoint).origin
          } catch (e) {
            console.error('Invalid token endpoint URL', tokenEndpoint)
          }

          logEl.textContent = 'Generating proof for exchange...'
          let dpopJwt = await createDPoPProof('POST', tokenEndpoint, '')
          
          logEl.textContent = 'Sending initial exchange request...'
          let res = await fetch('/api/exchange-code', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ code, state, dpopJwt, browserPublicKey }),
          })
          
          let data = await res.json()
          
          // Handle nonce retry
          if (!res.ok && data.error === 'use_dpop_nonce' && data.dpopNonce) {
            const nonce = data.dpopNonce
            logEl.textContent = 'Exchange challenged with nonce, retrying...'
            
            dpopJwt = await createDPoPProof('POST', tokenEndpoint, '', nonce)
            
            res = await fetch('/api/exchange-code', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ code, state, dpopJwt, browserPublicKey }),
            })
            data = await res.json()
          }

          if (data.ok) {
            // STORE LOCALLY
            localStorage.setItem('atproto_token', data.accessToken)
            localStorage.setItem('atproto_did', data.did)
            localStorage.setItem('atproto_pds', pdsUrl)
            
            logEl.textContent = 'Login successful! Redirecting...'
            window.location.href = '/app'
          } else {
            logEl.textContent = 'Exchange failed: ' + JSON.stringify(data, null, 2)
          }
        } catch (err) {
          logEl.textContent = 'Error: ' + err.message
        }
      }
      finalize()
    </script>
  </body>
</html>`)
  }

  if (!did) {
    res.redirect('/')
    return
  }

  // Pre-generate tokens for the UI
  let appToken = ''
  let atprotoToken = ''
  try {
    const session = await oauthClient.restore(did)
    const tokenSet = await (session as any).getTokenSet('auto')
    atprotoToken = String(tokenSet.access_token)
    
    const tokenInfo = await session.getTokenInfo('auto')
    const now = Math.floor(Date.now() / 1000)
    const exp = now + DERIVED_TOKEN_TTL_SECONDS
    appToken = signAppAuthToken({
      iat: now,
      did: tokenInfo.sub,
      exp: exp,
      iss: tokenInfo.iss,
      aud: tokenInfo.aud,
      scope: tokenInfo.scope,
      source: 'atproto-oauth',
    })
  } catch (err) {
    console.error('failed to restore session, clearing', err)
    res.setHeader('Set-Cookie', SESSION_COOKIE + '=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')
    res.redirect('/')
    return
  }

  res.type('html').send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>DPoP PDS Probe Demo</title>
    <style>
      body { font-family: ui-sans-serif, system-ui; max-width: 820px; margin: 2rem auto; padding: 0 1rem; }
      .row { display: flex; gap: 0.75rem; margin: 0.75rem 0; }
      input, textarea { width: 100%; padding: 0.5rem; margin: 0.4rem 0; font-family: ui-monospace, monospace; font-size: 0.85rem; }
      textarea { min-height: 80px; }
      button { padding: 0.6rem 1rem; cursor: pointer; background: #28a745; color: white; border: none; border-radius: 4px; }
      button:hover { background: #218838; }
      pre { background: #111; color: #d9f7d9; padding: 1rem; border-radius: 10px; overflow: auto; min-height: 250px; white-space: pre-wrap; word-break: break-all; font-size: 0.85rem; }
      code { background: #f3f4f6; padding: 0.1rem 0.3rem; border-radius: 4px; }
      .panel { border: 1px solid #ddd; border-radius: 10px; padding: 1rem; margin-top: 1rem; }
      .token-box { background: #f8f9fa; border: 1px solid #e9ecef; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; word-break: break-all; font-size: 0.8rem; }
      label { font-weight: bold; display: block; margin-top: 0.5rem; }
    </style>
  </head>
  <body>
    <h1>DPoP Verification (via PDS Probe)</h1>
    <p>Logged in DID: <code id="displayDid">${did}</code> | <a href="/logout" onclick="localStorage.clear()">Sign out</a></p>
    
    <div class="panel">
      <h3>1. Tokens</h3>
      <label>Local App JWT (HS256):</label>
      <div class="token-box">
        <code id="appToken">${appToken}</code>
      </div>
      <label>ATProto Access Token (DPoP-bound):</label>
      <div class="token-box">
        <code id="atprotoToken">${atprotoToken}</code>
      </div>
    </div>

    <div class="panel">
      <h3>2. Backend Probe Configuration</h3>
      <p>The backend will use the <strong>ATProto Access Token</strong> and a DPoP proof generated by this browser to hit the PDS <code>/xrpc/com.atproto.server.getSession</code> endpoint.</p>
      
      <label>PDS URL:</label>
      <input id="pdsUrl" value="https://amanita.us-east.host.bsky.network" />

      <label>Generated DPoP Proof for PDS:</label>
      <textarea id="dpopProof" readonly placeholder="Click Verify to generate and send..."></textarea>
      
      <button id="verifyBtn">Verify Token via PDS Probe</button>
    </div>

    <div class="panel">
      <h3>3. Server-Side Automated Probe</h3>
      <p>The backend uses its own internal DPoP key (the one used during login) to hit the PDS. This is the "correct" way for a confidential client.</p>
      <button id="serverProbeBtn" style="background: #007bff;">Run Server-Side Probe</button>
    </div>

    <div class="panel">
      <h3>Backend Response</h3>
      <pre id="log">Waiting for action...</pre>
    </div>

    <script>
      const logEl = document.getElementById('log')
      const atprotoTokenEl = document.getElementById('atprotoToken')
      const dpopProofEl = document.getElementById('dpopProof')
      const pdsUrlEl = document.getElementById('pdsUrl')
      const verifyBtn = document.getElementById('verifyBtn')
      const serverProbeBtn = document.getElementById('serverProbeBtn')
      const displayDid = document.getElementById('displayDid')

      // NEW: Use local storage tokens if available to avoid re-auth on refresh
      if (localStorage.getItem('atproto_token')) {
        atprotoTokenEl.textContent = localStorage.getItem('atproto_token')
      }
      if (localStorage.getItem('atproto_did')) {
        displayDid.textContent = localStorage.getItem('atproto_did')
      }
      if (localStorage.getItem('atproto_pds')) {
        pdsUrlEl.value = localStorage.getItem('atproto_pds')
      }

      function log(msg, obj) {
        const timestamp = new Date().toLocaleTimeString()
        const line = obj ? \`[\${timestamp}] \${msg} \` + JSON.stringify(obj, null, 2) : \`[\${timestamp}] \${msg}\`
        logEl.textContent = line + '\\n' + logEl.textContent
      }

      serverProbeBtn.addEventListener('click', async () => {
        log('Starting server-side probe...')
        try {
          const res = await fetch('/api/probe-pds')
          const data = await res.json()
          log('Server-side probe result', data)
        } catch (err) {
          log('Server probe failed', { error: err.message })
        }
      })

      async function getOrCreateKey() {
        const stored = localStorage.getItem('dpop_key')
        if (stored) {
          const jwk = JSON.parse(stored)
          return await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])
        }
        const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])
        const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)
        localStorage.setItem('dpop_key', JSON.stringify(jwk))
        localStorage.setItem('dpop_pub', JSON.stringify(await crypto.subtle.exportKey('jwk', keyPair.publicKey)))
        return keyPair.privateKey
      }

      async function createDPoPProof(method, url, accessToken, nonce = null) {
        const privateKey = await getOrCreateKey()
        const publicKeyJwk = JSON.parse(localStorage.getItem('dpop_pub'))
        const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '')
        const strB64 = (str) => b64(new TextEncoder().encode(str))

        const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: publicKeyJwk }
        const payload = {
          jti: crypto.randomUUID(),
          htm: method,
          htu: url,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 60, // 60 seconds expiry
        }
        if (accessToken) {
          payload.ath = b64(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken)))
        }
        if (nonce) payload.nonce = nonce

        const encodedHeader = strB64(JSON.stringify(header))
        const encodedPayload = strB64(JSON.stringify(payload))
        const data = encodedHeader + '.' + encodedPayload
        const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, new TextEncoder().encode(data))
        return data + '.' + b64(signature)
      }

      verifyBtn.addEventListener('click', async () => {
        const accessToken = atprotoTokenEl.textContent.trim()
        const pdsUrl = pdsUrlEl.value.trim()
        const probeUrl = pdsUrl + '/xrpc/com.atproto.server.getSession'
        
        log('Generating DPoP proof for PDS...')
        try {
          let proof = await createDPoPProof('GET', probeUrl, accessToken)
          dpopProofEl.value = proof
          
          log('Sending probe request to backend...')
          let res = await fetch('/api/verify-dpop-token', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ pdsUrl, accessToken, dpopJwt: proof }),
          })
          let data = await res.json()
          
          if (data.verification?.dpopNonce) {
            const nonce = data.verification.dpopNonce
            log('PDS challenged with nonce, retrying...', { nonce })
            proof = await createDPoPProof('GET', probeUrl, accessToken, nonce)
            dpopProofEl.value = proof
            res = await fetch('/api/verify-dpop-token', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ pdsUrl, accessToken, dpopJwt: proof }),
            })
            data = await res.json()
          }

          log('Final result', data)
        } catch (err) {
          log('Error', { error: err.message })
        }
      })

      // NEW: Browser-side exchange logic
      async function handleExchange() {
        const urlParams = new URLSearchParams(window.location.search)
        const code = urlParams.get('code')
        const state = urlParams.get('state')
        if (!code || !state) return

        log('Detected code in URL, performing browser-bound exchange...')
        try {
          // 1. Get the token endpoint from server metadata (or just use the relay)
          // For simplicity, our backend relay /api/exchange-code will fetch metadata
          
          // 2. Create DPoP proof for the exchange (the backend will tell us the URL if needed, 
          // but usually it's the token endpoint). We need to guess it or fetch it.
          // Since we are relaying, we'll just sign for the PDS we expect.
          // Actually, let's just sign for the PDS token endpoint.
          // We'll fetch the issuer from the backend first.
          
          const statusRes = await fetch('/api/token-endpoint?state=' + encodeURIComponent(state))
          const { tokenEndpoint } = await statusRes.json()
          
          log('Signing proof for token endpoint: ' + tokenEndpoint)
          const dpopJwt = await createDPoPProof('POST', tokenEndpoint, '') // empty ath for code exchange
          
          log('Sending exchange request to backend...')
          const res = await fetch('/api/exchange-code', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ code, state, dpopJwt }),
          })
          const data = await res.json()
          if (data.ok) {
            log('Exchange successful! Reloading page...')
            window.location.href = '/app'
          } else {
            log('Exchange failed', data)
          }
        } catch (err) {
          log('Exchange error', { error: err.message })
        }
      }

      handleExchange()
    </script>
  </body>
</html>`)
})

app.get('/api/token', async (req, res, next) => {
  try {
    const did = getSessionDid(req)
    if (!did) {
      res.status(401).json({ error: 'Not authenticated' })
      return
    }
    const session = await oauthClient.restore(did)
    const tokenInfo = await session.getTokenInfo('auto')
    const now = Math.floor(Date.now() / 1000)
    const exp = now + DERIVED_TOKEN_TTL_SECONDS
    const token = signAppAuthToken({
      iat: now,
      did: tokenInfo.sub,
      exp: exp,
      iss: tokenInfo.iss,
      aud: tokenInfo.aud,
      scope: tokenInfo.scope,
      source: 'atproto-oauth',
    })
    res.json({ token })
  } catch (err) {
    console.error('API token restoration failed', err)
    res.setHeader('Set-Cookie', SESSION_COOKIE + '=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')
    res.status(401).json({ error: 'Session expired or invalid' })
  }
})

app.get('/api/verify-jwt', async (req, res) => {
  const authHeader = req.header('authorization') ?? ''
  const dpopHeader = req.header('dpop') ?? ''

  if (!authHeader.startsWith('DPoP ')) {
    res.status(401).json({ ok: false, error: 'Missing or invalid Authorization header (expected DPoP)' })
    return
  }
  if (!dpopHeader) {
    res.status(401).json({ ok: false, error: 'Missing DPoP header' })
    return
  }

  try {
    const token = authHeader.replace(/^DPoP\s+/i, '').trim()
    
    // 1. Basic JWT payload check (our server-issued token)
    const payload = verifyAppAuthToken(token)
    if (!payload) {
      res.status(401).json({ ok: false, error: 'Invalid or expired access token' })
      return
    }

    // 2. Verify DPoP Proof
    const [headerB64] = dpopHeader.split('.')
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString())
    if (!header.jwk) throw new Error('DPoP proof missing jwk')

    const publicKey = await jose.importJWK(header.jwk, 'ES256')
    const { payload: dpopPayload } = await jose.jwtVerify(dpopHeader, publicKey, {
      typ: 'dpop',
    })

    // 3. Verify DPoP Claims
    const reqUrl = APP_ORIGIN + '/api/verify-jwt'
    if (dpopPayload.htm !== 'GET') throw new Error('DPoP htm mismatch')
    if (dpopPayload.htu !== reqUrl) throw new Error('DPoP htu mismatch')
    
    // 4. Verify Access Token Hash (ath)
    const { createHash } = await import('node:crypto')
    const expectedAth = createHash('sha256').update(token).digest('base64url')
    
    if (dpopPayload.ath !== expectedAth) {
      throw new Error('DPoP ath mismatch')
    }

    res.json({
      ok: true,
      message: 'DPoP Token and Proof are valid',
      session: payload,
      dpop: {
        jkt: await jose.calculateJwkThumbprint(header.jwk),
        iat: dpopPayload.iat
      }
    })
  } catch (err) {
    res.status(401).json({ ok: false, error: err instanceof Error ? err.message : 'DPoP verification failed' })
  }
})

app.get('/api/call-lex', async (req, res, next) => {
  try {
    const traceId = randomUUID()
    const did = getSessionDid(req)
    const name = String(req.query.name ?? 'anon')
    const flavor = String(req.query.flavor ?? 'vanilla')

    console.log('[' + traceId + '] [api] start /api/call-lex name=' + name + ' flavor=' + flavor)
    if (!did) {
      console.log('[' + traceId + '] [api] no ' + SESSION_COOKIE + ' cookie')
      res.status(401).json({ ok: false, error: 'Not authenticated', traceId })
      return
    }
    console.log('[' + traceId + '] [api] restoring oauth session for did=' + did)
    const session = await oauthClient.restore(did)
    console.log('[' + traceId + '] [api] restored oauth session did=' + session.did)
    const tokenInfo = await session.getTokenInfo('auto')
    const now = Math.floor(Date.now() / 1000)
    const oauthExp = tokenInfo.expiresAt ? Math.floor(tokenInfo.expiresAt.getTime() / 1000) : now + DERIVED_TOKEN_TTL_SECONDS
    const derivedExp = Math.min(now + DERIVED_TOKEN_TTL_SECONDS, oauthExp)
    const derivedToken = signAppAuthToken({
      iat: now,
      did: tokenInfo.sub,
      exp: derivedExp,
      iss: tokenInfo.iss,
      aud: tokenInfo.aud,
      scope: tokenInfo.scope,
      source: 'atproto-oauth',
    })
    console.log('[' + traceId + '] [api] derived token from oauth iss=' + tokenInfo.iss + ' aud=' + tokenInfo.aud + ' exp=' + derivedExp)

    const xrpcUrl = APP_ORIGIN + '/xrpc/com.example.echo?name=' + encodeURIComponent(name) + '&flavor=' + encodeURIComponent(flavor)
    console.log('[' + traceId + '] [api] calling xrpc url=' + xrpcUrl)

    const xrpcRes = await fetch(xrpcUrl, {
      headers: {
        authorization: 'Bearer ' + derivedToken,
        'x-trace-id': traceId,
      },
    })
    const body = await xrpcRes.json()
    console.log('[' + traceId + '] [api] xrpc status=' + xrpcRes.status)
    console.log('[' + traceId + '] [api] xrpc body=' + JSON.stringify(body))

    res.status(xrpcRes.status).json({
      ok: xrpcRes.ok,
      traceId,
      auth: {
        sessionDid: session.did,
        forwardedAuthorization: 'Bearer <oauth-derived-token>',
        oauthDerived: {
          iss: tokenInfo.iss,
          aud: tokenInfo.aud,
          scope: tokenInfo.scope,
          exp: derivedExp,
        },
      },
      xrpc: body,
    })
  } catch (err) {
    next(err)
  }
})

app.post('/api/verify-dpop-token', async (req, res, next) => {
  try {
    const traceId = randomUUID()
    const pdsUrl = String(req.body?.pdsUrl ?? '').trim().replace(/\/+$/, '')
    const accessToken = String(req.body?.accessToken ?? '').trim()
    const dpopJwt = String(req.body?.dpopJwt ?? '').trim()

    console.log('[' + traceId + '] [verify] start /api/verify-dpop-token pds=' + (pdsUrl || 'missing'))
    console.log('[' + traceId + '] [verify] token length=' + accessToken.length + ' start=' + accessToken.slice(0, 20) + '...')
    
    if (!pdsUrl || !accessToken || !dpopJwt) {
      console.log('[' + traceId + '] [verify] rejected: missing pdsUrl/accessToken/dpopJwt')
      res.status(400).json({ ok: false, error: 'pdsUrl, accessToken, and dpopJwt are required', traceId })
      return
    }

    const probeUrl = pdsUrl + '/xrpc/com.atproto.server.getSession'
    console.log('[' + traceId + '] [verify] calling probe url=' + probeUrl)

    const headers = {
      authorization: 'DPoP ' + accessToken,
      dpop: dpopJwt,
    }
    console.log('[' + traceId + '] [verify] headers: auth=' + headers.authorization.slice(0, 30) + '... dpop=' + headers.dpop.slice(0, 30) + '...')

    const probeRes = await fetch(probeUrl, {
      method: 'GET',
      headers,
    })

    const nonce = probeRes.headers.get('dpop-nonce')
    const text = await probeRes.text()
    console.log('[' + traceId + '] [verify] probe status=' + probeRes.status + ' nonce=' + (nonce ?? 'none'))
    console.log('[' + traceId + '] [verify] probe body=' + text)

    const valid = probeRes.ok
    res.status(valid ? 200 : 401).json({
      ok: valid,
      traceId,
      verification: {
        valid,
        status: probeRes.status,
        nonceRequired: Boolean(nonce),
        dpopNonce: nonce,
        probeUrl,
      },
      body: text,
    })
  } catch (err) {
    next(err)
  }
})

app.get('/api/probe-pds', async (req, res, next) => {
  try {
    const traceId = randomUUID()
    const did = getSessionDid(req)
    if (!did) {
      res.status(401).json({ ok: false, error: 'Not authenticated' })
      return
    }

    console.log('[' + traceId + '] [probe-pds] start for did=' + did)
    const session = await oauthClient.restore(did)
    
    // session.fetchHandler handles DPoP automatically using the server's private key
    const probeRes = await session.fetchHandler('/xrpc/com.atproto.server.getSession')
    const data = await probeRes.json()
    
    console.log('[' + traceId + '] [probe-pds] response status=' + probeRes.status)
    
    res.status(probeRes.status).json({
      ok: probeRes.ok,
      traceId,
      method: 'server-side session.fetch()',
      pdsResponse: data
    })
  } catch (err) {
    next(err)
  }
})

app.use('/xrpc/com.example.echo', async (req, res, next) => {
  const authHeader = req.header('authorization') ?? ''
  const traceId = req.header('x-trace-id') ?? 'no-trace'
  if (!authHeader.startsWith('Bearer ')) {
    console.log('[' + traceId + '] [xrpc] rejected: missing/invalid Authorization header format')
    res.status(401).json({ ok: false, error: 'Missing Authorization Bearer token' })
    return
  }

  const token = authHeader.replace(/^Bearer\s+/i, '').trim()
  const payload = verifyAppAuthToken(token)
  if (!payload) {
    console.log('[' + traceId + '] [xrpc] auth verify failed: invalid signature or expired token')
    res.status(401).json({ ok: false, error: 'Authorization token invalid' })
    return
  }
  if (payload.source !== 'atproto-oauth') {
    console.log('[' + traceId + '] [xrpc] auth verify failed: unexpected token source')
    res.status(401).json({ ok: false, error: 'Authorization token source invalid' })
    return
  }

  ;(req as express.Request & { authedDid?: string }).authedDid = payload.did
  console.log(
    '[' + traceId + '] [xrpc] auth verified independently did=' + payload.did + ' iss=' + payload.iss + ' aud=' + payload.aud + ' exp=' + payload.exp,
  )
  next()
})

app.use(xrpc.router)

app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const message = err instanceof Error ? err.message : 'Unknown error'
  const stack = err instanceof Error ? err.stack : undefined
  res.status(500).json({ ok: false, error: message, stack })
})

const server = app.listen(PORT, HOST, () => {
  console.log('server listening on ' + APP_ORIGIN)
  console.log('oauth start: ' + APP_ORIGIN + '/')
  console.log('xrpc test: ' + APP_ORIGIN + '/xrpc/com.example.echo?name=nandi')
})

server.on('error', (err) => {
  console.error('server failed to start:', err)
  process.exitCode = 1
})

await new Promise<void>((resolve) => {
  const shutdown = () => {
    server.close(() => resolve())
  }

  process.once('SIGINT', shutdown)
  process.once('SIGTERM', shutdown)
})
