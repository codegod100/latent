import { BrowserOAuthClient } from '@atproto/oauth-client-browser'

// --- CONFIG ---
const IS_LOCAL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
const HOSTNAME = IS_LOCAL ? '127.0.0.1' : window.location.hostname

const SERVER_URLS = [
  IS_LOCAL ? `http://${HOSTNAME}:8787` : `https://latent-server.veronika-m-winters.workers.dev`,
  IS_LOCAL ? `http://${HOSTNAME}:8788` : `https://latent-server-alt.veronika-m-winters.workers.dev`
]

let SERVERS: any[] = []
let currentServer: any = null
let currentChannel: any = null
let currentUserHandle: string | null = null

const CLIENT_URL = IS_LOCAL ? `http://${HOSTNAME}:3010` : window.location.origin
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

const log = (m: string, obj?: any) => {
  let line = m
  if (obj instanceof Error) line = `${m}: ${obj.message}\n${obj.stack}`
  else if (obj) line = `${m} ${JSON.stringify(obj, null, 2)}`
  console.log(`[${new Date().toLocaleTimeString()}] ${line}`)
}

// --- CRYPTO HELPER ---
const getDpopProof = async (session: any, method: string, url: string, nonce: string | null = null) => {
  const tokens = await session.getTokenSet()
  const key = (session as any).server.dpopKey
  const pub = key.bareJwk
  const jwk = { crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y }
  const alg = key.algorithms.find((a: any) => a.startsWith('ES')) || 'ES256'

  const accessTokenBytes = new TextEncoder().encode(tokens.access_token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', accessTokenBytes)
  const ath = btoa(String.fromCharCode(...new Uint8Array(hashBuffer))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')

  return await key.createJwt(
    { alg, typ: 'dpop+jwt', jwk },
    {
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      htm: method,
      htu: url.split('?')[0].split('#')[0],
      ath,
      nonce
    }
  )
}

async function init() {
  try {
    SERVERS = await Promise.all(SERVER_URLS.map(async (url) => {
      try {
        const res = await fetch(`${url}/api/meta`)
        const meta = await res.json()
        return { ...meta, url, id: meta.id || url }
      } catch (e) {
        return { id: url, name: 'Offline Server', url, error: true, categories: [], channels: [] }
      }
    }))

    currentServer = SERVERS[0]

    const result = await client.init()
    document.getElementById('loading-panel')!.style.display = 'none'
    
    // PERMALINK: /<serverId>/<channelId>
    const pathParts = window.location.pathname.split('/').filter(Boolean)
    if (pathParts[0]) {
      const server = SERVERS.find(s => s.id === pathParts[0])
      if (server) {
        currentServer = server
        if (pathParts[1]) {
          const chan = server.channels.find((c: any) => c.id === pathParts[1])
          if (chan) currentChannel = chan
        }
      }
    }

    if (!currentChannel && currentServer.channels?.length > 0) {
      currentChannel = currentServer.channels[0]
    }

    if (result?.session) await showApp(result.session)
    else document.getElementById('login-panel')!.style.display = 'flex'
    
    renderAll()
  } catch (err) {
    log('Init failed', err)
  }
}

function renderAll() {
  renderServerList()
  renderChannelList()
  document.getElementById('current-server-name')!.textContent = currentServer.name
  document.getElementById('current-channel-name')!.textContent = currentChannel?.name || 'no-channel'
  refreshMessages()
  renderAdminUI()
}

function renderServerList() {
  const sidebar = document.getElementById('server-sidebar')!
  sidebar.innerHTML = SERVERS.map(s => `
    <div class="server-icon ${s.id === currentServer.id ? 'active' : ''}" 
         onclick="window.selectServer('${s.id}')" 
         title="${s.name}">${s.name[0]}</div>
  `).join('')
}

function renderChannelList() {
  const list = document.getElementById('channel-list')!
  if (!currentServer) return
  
  const categories = currentServer.categories || []
  const channels = currentServer.channels || []

  let html = ''
  
  // Uncategorized
  const uncategorized = channels.filter((c: any) => !c.category_id)
  uncategorized.forEach((c: any) => {
    html += `<div class="channel-item ${currentChannel?.id === c.id ? 'active' : ''}" onclick="window.selectChannel('${c.id}')">
      <span class="channel-hash">#</span> ${c.name}
      ${isAdmin() ? `<span class="delete-icon" onclick="event.stopPropagation();window.deleteChannel('${c.id}')">×</span>` : ''}
    </div>`
  })

  // Grouped by Category
  categories.forEach((cat: any) => {
    html += `<div class="category-item">
      <span class="category-arrow">▼</span> ${cat.name}
      ${isAdmin() ? `<span class="add-icon" onclick="event.stopPropagation();window.promptAddChannel('${cat.id}')">+</span>` : ''}
      ${isAdmin() ? `<span class="delete-icon" onclick="event.stopPropagation();window.deleteCategory('${cat.id}')">×</span>` : ''}
    </div>`
    const catChannels = channels.filter((c: any) => c.category_id === cat.id)
    catChannels.forEach((c: any) => {
      html += `<div class="channel-item ${currentChannel?.id === c.id ? 'active' : ''}" onclick="window.selectChannel('${c.id}')">
        <span class="channel-hash">#</span> ${c.name}
        ${isAdmin() ? `<span class="delete-icon" onclick="event.stopPropagation();window.deleteChannel('${c.id}')">×</span>` : ''}
      </div>`
    })
  })

  // Global actions for admin
  if (isAdmin()) {
    html += `<div class="category-item" onclick="window.addCategory()" style="cursor:pointer; margin-top:10px; color:#5865f2;">+ Add Category</div>`
  }

  list.innerHTML = html
}

(window as any).selectServer = (id: string) => {
  const server = SERVERS.find(s => s.id === id)
  if (server) {
    currentServer = server
    currentChannel = server.channels?.[0] || null
    window.history.pushState({}, '', `/${currentServer.id}${currentChannel ? '/' + currentChannel.id : ''}`)
    renderAll()
  }
}

(window as any).selectChannel = (id: string) => {
  const chan = currentServer.channels.find((c: any) => c.id === id)
  if (chan) {
    currentChannel = chan
    window.history.pushState({}, '', `/${currentServer.id}/${currentChannel.id}`)
    renderAll()
  }
}

async function refreshMessages() {
  const container = document.getElementById('message-list')!
  if (!currentChannel) {
    container.innerHTML = '<div style="padding:1rem;">Select a channel to start chatting.</div>'
    return
  }
  try {
    const res = await fetch(`${currentServer.url}/api/messages?channelId=${currentChannel.id}`)
    const messages = await res.json()
    container.innerHTML = messages.length === 0 ? '<div style="padding:1rem; color:#949ba4;"><em>No messages yet.</em></div>' :
      messages.map((m: any) => `
        <div class="msg-item">
          <div class="msg-header">
            <span class="msg-author">@${m.handle}</span>
            <span class="msg-date">${new Date(m.created_at).toLocaleString()}</span>
          </div>
          <div class="msg-content">${m.content}</div>
        </div>
      `).reverse().join('')
    container.scrollTop = container.scrollHeight
  } catch (e) {
    container.innerHTML = '<div style="padding:1rem; color:#f23f42;">Failed to connect to server.</div>'
  }
}

async function showApp(session: any) {
  (window as any).atprotoSession = session
  document.getElementById('login-panel')!.style.display = 'none'
  document.getElementById('app-container')!.style.display = 'flex'
  
  const fetchProfile = async (nonce: string | null = null) => {
    try {
      const tokens = await session.getTokenSet()
      const pdsUrl = tokens.aud.replace(/\/+$/, '')
      const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${session.did}`
      
      const dpop = await getDpopProof(session, 'GET', probeUrl, nonce)
      const res = await fetch(probeUrl, { headers: { 'Authorization': `DPoP ${tokens.access_token}`, 'DPoP': dpop } })
      
      if (res.status === 401) {
        const nextNonce = res.headers.get('dpop-nonce')
        if (nextNonce && !nonce) return fetchProfile(nextNonce)
      }

      const profile = await res.json()
      if (profile.handle) {
        currentUserHandle = profile.handle
        document.getElementById('user-handle')!.textContent = `@${profile.handle}`
        renderAdminUI() 
      }
    } catch (e) { log('Profile fetch failed', e) }
  }
  await fetchProfile()
}

const isAdmin = () => currentUserHandle && currentServer.adminHandle === currentUserHandle

function renderAdminUI() {
  const adminBtn = document.getElementById('admin-tools')!
  adminBtn.style.display = isAdmin() ? 'block' : 'none'
}

(window as any).toggleAdminMenu = () => {
  const menu = document.getElementById('admin-menu')!
  menu.style.display = menu.style.display === 'none' ? 'block' : 'none'
  if (menu.style.display === 'block') {
    (document.getElementById('new-server-name') as HTMLInputElement).value = currentServer.name
  }
}

// --- ADMIN ACTIONS ---
async function adminFetch(endpoint: string, method: string, body: any) {
  const session = (window as any).atprotoSession
  const tokens = await session.getTokenSet()
  const pdsUrl = String(tokens.aud).replace(/\/+$/, '')
  const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${session.did}`
  
  const submit = async (nonce: string | null = null) => {
    const dpop = await getDpopProof(session, 'GET', probeUrl, nonce)
    const res = await fetch(`${currentServer.url}${endpoint}`, {
      method,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...body, accessToken: tokens.access_token, dpopProof: dpop, pdsUrl, did: session.did })
    })
    const data = await res.json()
    if (data.isChallenge) return submit(data.dpopNonce)
    return { ok: res.ok, data }
  }
  return await submit()
}

(window as any).saveServerConfig = async () => {
  const name = (document.getElementById('new-server-name') as HTMLInputElement).value.trim()
  const res = await adminFetch('/api/meta', 'POST', { name })
  if (res.ok) {
    currentServer.name = name
    renderAll()
    document.getElementById('admin-menu')!.style.display = 'none'
  }
};

(window as any).addCategory = async () => {
  const name = prompt('Category Name:')
  if (!name) return
  const res = await adminFetch('/api/categories', 'POST', { name })
  if (res.ok) {
    currentServer.categories.push({ id: res.data.id, name })
    renderChannelList()
  }
};

(window as any).deleteCategory = async (id: string) => {
  if (!confirm('Delete category?')) return
  const res = await adminFetch(`/api/categories/${id}`, 'DELETE', {})
  if (res.ok) {
    currentServer.categories = currentServer.categories.filter((c: any) => c.id !== id)
    renderChannelList()
  }
};

(window as any).promptAddChannel = async (catId: string | null = null) => {
  const name = prompt('Channel Name:')
  if (!name) return
  const res = await adminFetch('/api/channels', 'POST', { name, category_id: catId })
  if (res.ok) {
    currentServer.channels.push({ id: res.data.id, name, category_id: catId })
    renderChannelList()
  }
};

(window as any).deleteChannel = async (id: string) => {
  if (!confirm('Delete channel?')) return
  const res = await adminFetch(`/api/channels/${id}`, 'DELETE', {})
  if (res.ok) {
    currentServer.channels = currentServer.channels.filter((c: any) => c.id !== id)
    if (currentChannel?.id === id) currentChannel = currentServer.channels[0] || null
    renderAll()
  }
};

(window as any).logout = () => { localStorage.clear(); location.href = '/' };

(window as any).submitMessage = async () => {
  const session = (window as any).atprotoSession
  if (!session || !currentChannel) return
  const input = document.getElementById('message-input') as HTMLInputElement
  const content = input.value.trim()
  if (!content) return
  input.value = ''
  
  const tokens = await session.getTokenSet()
  const pdsUrl = String(tokens.aud).replace(/\/+$/, '')
  const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${session.did}`

  const submit = async (nonce: string | null = null) => {
    const dpop = await getDpopProof(session, 'GET', probeUrl, nonce)
    const res = await fetch(`${currentServer.url}/api/submit-message`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ accessToken: tokens.access_token, dpopProof: dpop, pdsUrl, did: session.did, content, channelId: currentChannel.id })
    })
    const data = await res.json()
    if (data.isChallenge) return submit(data.dpopNonce)
    if (res.ok) refreshMessages()
  }
  await submit()
}

document.getElementById('message-input')!.onkeydown = (e) => { if (e.key === 'Enter') (window as any).submitMessage() }

init()
