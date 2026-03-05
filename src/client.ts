import { BrowserOAuthClient } from '@atproto/oauth-client-browser'

// --- CONFIG ---
const IS_LOCAL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
const HOSTNAME = IS_LOCAL ? '127.0.0.1' : window.location.hostname

const DEFAULT_SERVER_URLS = [
  IS_LOCAL ? `http://${HOSTNAME}:8787` : `https://latent-server.veronika-m-winters.workers.dev`,
  IS_LOCAL ? `http://${HOSTNAME}:8788` : `https://latent-server-alt.veronika-m-winters.workers.dev`,
  `https://latent-docker-backend.fly.dev`
]

let SERVER_URLS: string[] = []
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

  const payload: any = {
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    htm: method,
    htu: url.split('?')[0].split('#')[0],
    ath
  }
  // CRITICAL: Only include nonce if it is a non-null string
  if (nonce) payload.nonce = nonce

  return await key.createJwt({ alg, typ: 'dpop+jwt', jwk }, payload)
}

// --- PDS FETCHER (Handles Nonce Retries) ---
async function pdsFetch(session: any, url: string, init: RequestInit = {}) {
  const tokens = await session.getTokenSet()
  
  const perform = async (nonce: string | null = null): Promise<Response> => {
    const proof = await getDpopProof(session, init.method || 'GET', url, nonce)
    const res = await fetch(url, {
      ...init,
      headers: {
        ...init.headers,
        'Authorization': `DPoP ${tokens.access_token}`,
        'DPoP': proof
      }
    })
    
    if (res.status === 401) {
      const newNonce = res.headers.get('dpop-nonce')
      if (newNonce && nonce !== newNonce) {
        log('PDS Nonce challenge, retrying...')
        return perform(newNonce)
      }
    }
    return res
  }
  
  return perform()
}

async function init() {
  try {
    const result = await client.init()
    document.getElementById('loading-panel')!.style.display = 'none'
    
    if (result?.session) {
      await showApp(result.session)
    } else {
      SERVER_URLS = DEFAULT_SERVER_URLS
      await hydrateServers()
      log('No session found. Using default servers.')
      document.getElementById('login-panel')!.style.display = 'flex'
    }
    
    renderAll()
  } catch (err) {
    log('Init failed', err)
  }
}

async function hydrateServers() {
  SERVERS = await Promise.all(SERVER_URLS.map(async (url) => {
    try {
      const res = await fetch(`${url}/api/meta`)
      const meta = await res.json()
      return { ...meta, url, id: meta.id }
    } catch (e) {
      return { id: url, name: 'Offline Server', url, error: true, categories: [], channels: [] }
    }
  }))

  const pathParts = window.location.pathname.split('/').filter(Boolean)
  if (pathParts[0]) {
    const server = SERVERS.find(s => s.id === pathParts[0])
    if (server) currentServer = server
  }
  if (!currentServer) currentServer = SERVERS[0]

  if (currentServer && !currentServer.error) {
    if (pathParts[1]) {
      const chan = currentServer.channels?.find((c: any) => c.id === pathParts[1])
      if (chan) currentChannel = chan
    }
    if (!currentChannel && currentServer.channels?.length > 0) {
      currentChannel = currentServer.channels[0]
    }
  }
}

async function syncServersFromPds(session: any) {
  log('Syncing server list from PDS...')
  try {
    const tokens = await session.getTokenSet()
    const pdsUrl = tokens.aud.replace(/\/+$/, '')
    const listUrl = `${pdsUrl}/xrpc/com.atproto.repo.listRecords?repo=${session.did}&collection=org.latha.latent.server`
    
    const res = await pdsFetch(session, listUrl)
    const data = await res.json()
    
    if (data.records?.length > 0) {
      SERVER_URLS = data.records.map((r: any) => r.value.url)
      log(`Found ${SERVER_URLS.length} servers in PDS.`)
    } else {
      SERVER_URLS = DEFAULT_SERVER_URLS
      log('No servers found in PDS. Using defaults.')
    }
  } catch (e) {
    log('Failed to sync from PDS, using defaults', e)
    SERVER_URLS = DEFAULT_SERVER_URLS
  }
  await hydrateServers()
}

function renderAll() {
  renderServerList()
  if (currentServer) {
    renderChannelList()
    document.getElementById('current-server-name')!.textContent = currentServer.name
    document.getElementById('current-channel-name')!.textContent = currentChannel?.name || 'no-channel'
    refreshMessages()
    renderAdminUI()
  }
}

function renderServerList() {
  const sidebar = document.getElementById('server-sidebar')!
  let html = SERVERS.map(s => `
    <div class="server-icon ${s.id === currentServer?.id ? 'active' : ''}" 
         onclick="window.selectServer('${s.id}')" 
         title="${s.name}">${s.name[0]}</div>
  `).join('')
  
  html += `<div class="server-icon add-server" onclick="window.toggleClientSettings()" title="Server Settings">+</div>`
  sidebar.innerHTML = html
}

function renderChannelList() {
  const list = document.getElementById('channel-list')!
  if (!currentServer || currentServer.error) {
    list.innerHTML = '<div style="padding:1rem; color:#f23f42;">Server Offline</div>'
    return
  }
  
  const categories = currentServer.categories || []
  const channels = currentServer.channels || []

  let html = ''
  const uncategorized = channels.filter((c: any) => !c.category_id)
  uncategorized.forEach((c: any) => {
    html += `<div class="channel-item ${currentChannel?.id === c.id ? 'active' : ''}" onclick="window.selectChannel('${c.id}')">
      <span class="channel-hash">#</span> ${c.name}
      ${isAdmin() ? `<span class="delete-icon" onclick="event.stopPropagation();window.deleteChannel('${c.id}')">×</span>` : ''}
    </div>`
  })

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

  if (isAdmin()) {
    html += `<div class="category-item" onclick="window.addCategory()" style="cursor:pointer; margin-top:10px; color:#5865f2;">+ Add Category</div>`
  }

  list.innerHTML = html
}

// --- CLIENT SETTINGS ---
(window as any).toggleClientSettings = () => {
  const modal = document.getElementById('client-settings-modal')!
  modal.style.display = modal.style.display === 'none' ? 'flex' : 'none'
  if (modal.style.display === 'flex') {
    (document.getElementById('server-urls-input') as HTMLTextAreaElement).value = SERVER_URLS.join('\n')
  }
};

(window as any).saveClientSettings = async () => {
  const session = (window as any).atprotoSession
  const input = (document.getElementById('server-urls-input') as HTMLTextAreaElement).value
  const newUrls = input.split('\n').map(u => u.trim()).filter(Boolean)
  
  if (!session) {
    localStorage.setItem('atproto_servers', JSON.stringify(newUrls))
    return location.href = '/'
  }

  log('Persisting server list to PDS...')
  try {
    const tokens = await session.getTokenSet()
    const pdsUrl = tokens.aud.replace(/\/+$/, '')
    
    // 1. Delete old records
    const listRes = await pdsFetch(session, `${pdsUrl}/xrpc/com.atproto.repo.listRecords?repo=${session.did}&collection=org.latha.latent.server`)
    const existing = await listRes.json()
    
    for (const record of (existing.records || [])) {
      const rkey = record.uri.split('/').pop()
      await pdsFetch(session, `${pdsUrl}/xrpc/com.atproto.repo.deleteRecord`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo: session.did, collection: 'org.latha.latent.server', rkey })
      })
    }

    // 2. Add new records
    for (const url of newUrls) {
      log(`Adding server: ${url}`)
      const res = await pdsFetch(session, `${pdsUrl}/xrpc/com.atproto.repo.createRecord`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo: session.did,
          collection: 'org.latha.latent.server',
          record: { $type: 'org.latha.latent.server', url, createdAt: new Date().toISOString() }
        })
      })
      if (!res.ok) throw new Error('PDS add failed')
    }

    log('Server list synced to PDS!')
    location.href = '/'
  } catch (e) {
    log('Failed to save to PDS', e)
    alert('Failed to save to PDS. Check console.')
  }
};

(window as any).selectServer = (id: string) => {
  const server = SERVERS.find(s => s.id === id)
  if (server) {
    currentServer = server
    currentChannel = server.channels?.[0] || null
    window.history.pushState({}, '', `/${currentServer.id}${currentChannel ? '/' + currentChannel.id : ''}`)
    renderAll()
  }
};

(window as any).selectChannel = (id: string) => {
  const chan = currentServer.channels.find((c: any) => c.id === id)
  if (chan) {
    currentChannel = chan
    window.history.pushState({}, '', `/${currentServer.id}/${currentChannel.id}`)
    renderAll()
  }
};

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
  
  const fetchProfile = async () => {
    try {
      const tokens = await session.getTokenSet()
      const pdsUrl = tokens.aud.replace(/\/+$/, '')
      const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${session.did}`
      
      const res = await pdsFetch(session, probeUrl)
      const profile = await res.json()
      if (profile.handle) {
        currentUserHandle = profile.handle
        document.getElementById('user-handle')!.textContent = `@${profile.handle}`
        await syncServersFromPds(session)
        renderAdminUI() 
      }
    } catch (e) { log('Profile fetch failed', e) }
  }
  await fetchProfile()
}

const isAdmin = () => currentUserHandle && currentServer?.adminHandle === currentUserHandle

function renderAdminUI() {
  const adminBtn = document.getElementById('admin-tools')!
  adminBtn.style.display = isAdmin() ? 'block' : 'none'
}

(window as any).startLogin = async () => {
  const handle = (document.getElementById('handle') as HTMLInputElement).value
  log('Starting login for ' + handle)
  await client.signIn(handle)
};

(window as any).logout = () => { localStorage.clear(); location.href = '/' };

(window as any).toggleAdminMenu = () => {
  const menu = document.getElementById('admin-menu')!
  menu.style.display = menu.style.display === 'none' ? 'flex' : 'none'
  if (menu.style.display === 'flex') {
    (document.getElementById('new-server-name') as HTMLInputElement).value = currentServer.name
  }
};

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
