import { BrowserOAuthClient } from '@atproto/oauth-client-browser'

// --- CONFIG ---
const PORT = 3010
const APP_ORIGIN = `http://127.0.0.1:${PORT}`
const CLIENT_ID = `http://localhost/?redirect_uri=${encodeURIComponent(APP_ORIGIN + '/')}&scope=atproto%20transition:generic`

const client = new BrowserOAuthClient({
  handleResolver: 'https://bsky.social/',
  clientMetadata: {
    client_id: CLIENT_ID,
    redirect_uris: [APP_ORIGIN + '/'],
    scope: 'atproto transition:generic',
    token_endpoint_auth_method: 'none',
  }
})

const logEl = document.getElementById('console') as HTMLPreElement
const log = (m: string, obj?: any) => {
  let line = m
  if (obj instanceof Error) {
    line = `${m}: ${obj.message}\n${obj.stack}`
  } else if (obj) {
    line = `${m} ${JSON.stringify(obj, null, 2)}`
  }
  logEl.textContent = `[${new Date().toLocaleTimeString()}] ${line}\n${logEl.textContent}`
}

async function init() {
  log('Initializing official library...')
  try {
    const result = await client.init()
    if (result?.session) {
      showApp(result.session)
    } else {
      log('No session found.')
    }
  } catch (err) {
    log('Init failed', err)
  }
}

function showApp(session: any) {
  (window as any).atprotoSession = session
  document.getElementById('login-panel')!.style.display = 'none'
  document.getElementById('app-panel')!.style.display = 'block'
  document.getElementById('user-did')!.textContent = session.did
  log('Session active for ' + session.did)
}

(window as any).startLogin = async () => {
  const handle = (document.getElementById('handle') as HTMLInputElement).value
  log('Starting login for ' + handle)
  await client.signIn(handle)
};

(window as any).verifyWithExternalServer = async () => {
  const session = (window as any).atprotoSession
  if (!session) return alert('Not logged in')

  log('Signing verification proof via library...')
  
  try {
    const pdsUrl = session.serverMetadata.issuer
    const did = session.did
    const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${did}`

    // THE CANONICAL WAY: Use the session's internal key to sign a proof
    const verifyRelay = async (nonce: string | null = null) => {
      const tokenSet = await (session as any).getTokenSet('auto')
      const key = (session as any).server.dpopKey
      
      // Determine the PDS URL (Resource Server). tokenSet.aud is usually the PDS.
      const pdsUrl = String(tokenSet.aud).replace(/\/+$/, '')
      const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${session.did}`

      log('Probing Resource Server (PDS): ' + pdsUrl)
      
      // Calculate Access Token Hash (ath)
      // WebCrypto subtle digest returns ArrayBuffer
      const accessTokenBytes = new TextEncoder().encode(tokenSet.access_token)
      const hashBuffer = await crypto.subtle.digest('SHA-256', accessTokenBytes)
      const hashArray = new Uint8Array(hashBuffer)
      
      // Base64url encode the hash
      const b64 = (arr: Uint8Array) => btoa(String.fromCharCode(...arr)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
      const ath = b64(hashArray)

      // Get canonical JWK for thumbprint consistency
      const pub = key.bareJwk
      const jwk = { crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y }
      const alg = key.algorithms.find((a: string) => a.startsWith('ES') || a.startsWith('RS')) || 'ES256'

      const dpopProof = await key.createJwt(
        { alg, typ: 'dpop+jwt', jwk },
        {
          iat: Math.floor(Date.now() / 1000),
          jti: crypto.randomUUID(),
          htm: 'GET',
          htu: probeUrl.split('?')[0].split('#')[0],
          ath,
          nonce
        }
      )

      const res = await fetch('/api/external-verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          accessToken: tokenSet.access_token,
          dpopProof,
          pdsUrl,
          did: session.did
        })
      })

      const data = await res.json()
      
      if (!res.ok && data.dpopNonce) {
        log('Challenge: Nonce received, retrying with library...')
        return verifyRelay(data.dpopNonce)
      }

      log('Backend Result:', data)
    }

    await verifyRelay()
  } catch (err) {
    log('Verification error', err)
  }
}

init()
