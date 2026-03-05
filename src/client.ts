import { BrowserOAuthClient } from '@atproto/oauth-client-browser'

// --- CONFIG ---
const IS_LOCAL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
const HOSTNAME = window.location.hostname

const SERVERS = [
  { id: 'main', name: 'General Server', url: IS_LOCAL ? `http://${HOSTNAME}:8787` : `https://latent-server.veronika-m-winters.workers.dev` },
  { id: 'alt', name: 'Alternate Reality', url: IS_LOCAL ? `http://${HOSTNAME}:8788` : `https://latent-server-alt.veronika-m-winters.workers.dev` }
]

let currentServer = SERVERS[0]

const CLIENT_URL = window.location.origin
const CLIENT_ID = IS_LOCAL 
  ? `http://localhost/?redirect_uri=${encodeURIComponent(CLIENT_URL + '/')}&scope=atproto%20transition:generic`
  : `${CLIENT_URL}/client-metadata.json`

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
      document.getElementById('login-panel')!.style.display = 'flex'
    }
    renderServerList()
    refreshMessages()
  } catch (err) {
    log('Init failed', err)
    document.getElementById('loading-panel')!.style.display = 'none'
    document.getElementById('login-panel')!.style.display = 'flex'
  }
}

function renderServerList() {
  const sidebar = document.getElementById('server-sidebar')!
  sidebar.innerHTML = SERVERS.map(s => `
    <div class="server-icon ${s.id === currentServer.id ? 'active' : ''}" 
         onclick="window.selectServer('${s.id}')" 
         title="${s.name}">
      ${s.name[0]}
    </div>
  `).join('')
}

(window as any).selectServer = (id: string) => {
  const server = SERVERS.find(s => s.id === id)
  if (server) {
    currentServer = server
    log(`Switched to server: ${server.name}`)
    document.getElementById('current-server-name')!.textContent = server.name
    renderServerList()
    refreshMessages()
  }
}

async function refreshMessages() {
  listEl.innerHTML = '<div style="padding:1rem;">Loading messages from ' + currentServer.name + '...</div>'
  try {
    const res = await fetch(`${currentServer.url}/api/messages`)
    const messages = await res.json()
    if (messages.length === 0) {
      listEl.innerHTML = '<div style="padding:1rem;"><em>No messages in this server yet.</em></div>'
      return
    }
    listEl.innerHTML = messages.map((m: any) => `
      <div class="msg-item">
        <div class="msg-header">
          <span class="msg-author">@${m.handle}</span>
          <span class="msg-date">${new Date(m.created_at).toLocaleString()}</span>
        </div>
        <div class="msg-content">${m.content}</div>
      </div>
    `).join('')
    listEl.scrollTop = listEl.scrollHeight
  } catch (e) {
    log(`Failed to load messages from ${currentServer.name}`, e)
    listEl.innerHTML = '<div style="padding:1rem; color:red;">Failed to connect to server.</div>'
  }
}

function showApp(session: any) {
  (window as any).atprotoSession = session
  document.getElementById('login-panel')!.style.display = 'none'
  document.getElementById('app-container')!.style.display = 'flex'
  document.getElementById('current-server-name')!.textContent = currentServer.name
  // Try to get handle for UI using proper DPoP
  session.getTokenSet().then(async (tokens: any) => {
    try {
      const pdsUrl = tokens.aud.replace(/\/+$/, '')
      const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${session.did}`

      const dpop = await session.createDPoPProof({
        method: 'GET',
        url: probeUrl
      })

      const res = await fetch(probeUrl, {
        headers: { 
          'Authorization': `DPoP ${tokens.access_token}`,
          'DPoP': dpop
        }
      })
      const profile = await res.json()
      if (profile.handle) document.getElementById('user-handle')!.textContent = `@${profile.handle}`
    } catch (e) {
      log('Failed to fetch profile for UI', e)
    }
  })

  log('Session active for ' + session.did)
}

(window as any).startLogin = async () => {
  const handle = (document.getElementById('handle') as HTMLInputElement).value
  log('Starting login for ' + handle)
  await client.signIn(handle)
};

(window as any).logout = () => {
  localStorage.clear()
  location.href = '/'
};

(window as any).submitMessage = async () => {
  const session = (window as any).atprotoSession
  if (!session) return alert('Not logged in')

  const input = document.getElementById('message-input') as HTMLInputElement
  const content = input.value.trim()
  if (!content) return

  input.value = ''
  log(`Submitting message to ${currentServer.name}...`)

  try {
    const tokens = await session.getTokenSet()
    const pdsUrl = String(tokens.aud).replace(/\/+$/, '')
    const did = session.did
    const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${did}`

    const submit = async (nonce: string | null = null) => {
      const accessTokenBytes = new TextEncoder().encode(tokens.access_token)
      const hashBuffer = await crypto.subtle.digest('SHA-256', accessTokenBytes)
      const ath = btoa(String.fromCharCode(...new Uint8Array(hashBuffer))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')

      const key = (session as any).server.dpopKey
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

      const res = await fetch(`${currentServer.url}/api/submit-message`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ accessToken: tokens.access_token, dpopProof, pdsUrl, did, content })
      })

      const data = await res.json()

      // Handle the "Soft Challenge" (Status was 200, but it's a nonce request)
      if (data.isChallenge && data.dpopNonce) {
        log('Nonce challenge received (handled silently)...')
        return submit(data.dpopNonce)
      }

      if (res.ok && data.ok) {
        log('Message stored in ' + currentServer.name)
        refreshMessages()
      } else {
        log('Submission failed', data)
      }
    }

    await submit()
  } catch (err) {
    log('Submission error', err)
  }
}

// Wire up Enter key
document.getElementById('message-input')!.onkeydown = (e) => {
  if (e.key === 'Enter') (window as any).submitMessage()
}

init()
