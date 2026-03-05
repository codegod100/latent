import { BrowserOAuthClient } from '@atproto/oauth-client-browser'

// --- CONFIG ---
const IS_LOCAL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
const HOSTNAME = window.location.hostname

// If on Cloudflare, we use the real URL. If local, we use the port.
const API_URL = IS_LOCAL ? `http://${HOSTNAME}:8787` : `https://latent-server.veronika-m-winters.workers.dev` 
const CLIENT_URL = window.location.origin
const CLIENT_ID = `${CLIENT_URL}/client-metadata.json`

const client = new BrowserOAuthClient({
  handleResolver: 'https://bsky.social/',
  clientMetadata: {
    client_id: CLIENT_ID,
    redirect_uris: [CLIENT_URL + '/'],
    scope: 'atproto transition:generic',
    token_endpoint_auth_method: 'none',
  }
})

const logEl = document.getElementById('console') as HTMLPreElement
const listEl = document.getElementById('message-list') as HTMLDivElement
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
    document.getElementById('loading-panel')!.style.display = 'none'
    
    if (result?.session) {
      showApp(result.session)
    } else {
      log('No session found.')
      document.getElementById('login-panel')!.style.display = 'block'
    }
    refreshMessages()
  } catch (err) {
    log('Init failed', err)
    document.getElementById('loading-panel')!.style.display = 'none'
    document.getElementById('login-panel')!.style.display = 'block'
  }
}

async function refreshMessages() {
  try {
    const res = await fetch(`${API_URL}/api/messages`)
    const messages = await res.json()
    if (messages.length === 0) {
      listEl.innerHTML = '<em>No messages yet.</em>'
      return
    }
    listEl.innerHTML = messages.map((m: any) => `
      <div class="msg-item">
        <span class="msg-author">@${m.handle}</span>: ${m.content}
        <div class="msg-date">${new Date(m.created_at).toLocaleString()}</div>
      </div>
    `).join('')
  } catch (e) {
    log('Failed to load messages from Worker', e)
  }
}

function showApp(session: any) {
  (window as any).atprotoSession = session
  document.getElementById('login-panel')!.style.display = 'none'
  document.getElementById('app-panel')!.style.display = 'block'
  
  session.getTokenSet().then(async (tokens: any) => {
    const pdsUrl = tokens.aud.replace(/\/+$/, '')
    const res = await fetch(`${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${session.did}`, {
      headers: { 'Authorization': `Bearer ${tokens.access_token}` }
    })
    const profile = await res.json()
    if (profile.handle) document.getElementById('user-handle')!.textContent = `@${profile.handle}`
  })

  log('Session active for ' + session.did)
}

document.getElementById('login-btn')!.onclick = async () => {
  const handle = (document.getElementById('handle') as HTMLInputElement).value
  log('Starting login for ' + handle)
  await client.signIn(handle)
}

document.getElementById('logout-btn')!.onclick = () => {
  localStorage.clear()
  location.href = '/'
}

document.getElementById('submit-btn')!.onclick = async () => {
  const session = (window as any).atprotoSession
  if (!session) return alert('Not logged in')

  const input = document.getElementById('message-input') as HTMLInputElement
  const content = input.value.trim()
  if (!content) return alert('Type something first')

  const btn = document.getElementById('submit-btn') as HTMLButtonElement
  btn.disabled = true
  log('Submitting identity-verified message to Worker...')

  try {
    const tokens = await session.getTokenSet()
    const pdsUrl = String(tokens.aud).replace(/\/+$/, '')
    const did = session.did
    const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${did}`

    const submit = async (nonce: string | null = null) => {
      const accessTokenBytes = new TextEncoder().encode(tokens.access_token)
      const hashBuffer = await crypto.subtle.digest('SHA-256', accessTokenBytes)
      const ath = btoa(String.fromCharCode(...new Uint8Array(hashBuffer))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')

      const key = session.server.dpopKey
      const alg = key.algorithms.find((a: string) => a.startsWith('ES') || a.startsWith('RS')) || 'ES256'
      const pub = key.bareJwk
      
      const dpopProof = await key.createJwt(
        { alg, typ: 'dpop+jwt', jwk: { crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y } },
        {
          iat: Math.floor(Date.now() / 1000),
          jti: crypto.randomUUID(),
          htm: 'GET',
          htu: probeUrl,
          ath,
          nonce
        }
      )

      const res = await fetch(`${API_URL}/api/submit-message`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ accessToken: tokens.access_token, dpopProof, pdsUrl, did, content })
      })

      const data = await res.json()

      if (!res.ok && data.dpopNonce) {
        log('Challenge: Nonce received from Worker, retrying...')
        return submit(data.dpopNonce)
      }

      if (res.ok) {
        log('Message stored in D1!', data)
        input.value = ''
        refreshMessages()
      } else {
        log('Worker submission failed', data)
      }
    }

    await submit()
  } catch (err) {
    log('Submission error', err)
  } finally {
    btn.disabled = false
  }
}

init()
