import { BrowserOAuthClient } from '@atproto/oauth-client-browser'

// --- CONFIG ---
const IS_LOCAL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
const HOSTNAME = IS_LOCAL ? '127.0.0.1' : window.location.hostname

const DEFAULT_SERVER_URLS = [
  IS_LOCAL ? `http://${HOSTNAME}:8789` : `https://latent-docker-backend.fly.dev`
]

let SERVER_URLS: string[] = []
let SERVERS: any[] = []
let serverSessions: Map<string, { token: string, expires: string }> = new Map()
let currentServer: any = null
let currentChannel: any = null
let currentUserHandle: string | null = null
let currentUserDid: string | null = null
let currentMessages: any[] = []
let replyToMessage: any = null
let ws: WebSocket | null = null
let currentWsUrl: string | null = null
let isLoadingOlder = false
let hasMoreMessages = true
let searchTimeout: any = null

const client = new BrowserOAuthClient({
  handleResolver: 'https://bsky.social/',
  clientMetadata: { 
    client_id: IS_LOCAL ? `http://localhost/?redirect_uri=${encodeURIComponent((IS_LOCAL ? `http://${HOSTNAME}:3010` : 'https://latent.latha.org') + '/')}&scope=atproto%20transition:generic` : `https://latent.latha.org/client-metadata.json`,
    redirect_uris: [(IS_LOCAL ? `http://${HOSTNAME}:3010` : 'https://latent.latha.org') + '/'],
    scope: 'atproto transition:generic',
    token_endpoint_auth_method: 'none'
  }
})

// --- UTILS ---
const log = (m: string, obj?: any) => {
  let line = m
  if (obj instanceof Error) line = `${m}: ${obj.message}\n${obj.stack}`
  else if (obj) line = `${m} ${JSON.stringify(obj, null, 2)}`
  console.log(`[${new Date().toLocaleTimeString()}] ${line}`)
}

const loadMsg = (msg: string) => {
  const el = document.getElementById('load-msg'); if (el) el.textContent = msg
}

function isAdmin() { return currentUserHandle && currentServer?.adminHandle === currentUserHandle }
(window as any).isAdmin = isAdmin;

function renderAdminUI() { const btn = document.getElementById('admin-tools'); if (btn) btn.style.display = isAdmin() ? 'block' : 'none' }
(window as any).renderAdminUI = renderAdminUI;

function setLoading(selector: string, isLoading: boolean, text: string | null = null) {
  const el = document.querySelector(selector) as HTMLElement
  if (!el) return
  if (isLoading) {
    el.classList.add('loading-overlay')
    if (el instanceof HTMLButtonElement) { el.disabled = true; if (text) { (el as any)._oldText = el.innerHTML; el.innerHTML = `<span class="inline-spinner"></span>${text}` } }
  } else {
    el.classList.remove('loading-overlay')
    if (el instanceof HTMLButtonElement) { el.disabled = false; if ((el as any)._oldText) el.innerHTML = (el as any)._oldText }
  }
}

async function fetchWithTimeout(resource: string, options: any = {}) {
  const { timeout = 5000 } = options;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  const response = await fetch(resource, { ...options, signal: controller.signal });
  clearTimeout(id);
  return response;
}

// --- REAL-TIME (WebSocket) ---
function setupWebSocket() {
  if (!currentServer || !currentChannel || currentServer.error) return;
  if (!currentServer.features?.ws) return;
  const protocol = currentServer.url.startsWith('https') ? 'wss' : 'ws';
  const wsUrl = `${currentServer.url.replace(/^https?/, protocol)}/api/ws?channelId=${currentChannel.id}`;
  if (ws && currentWsUrl === wsUrl && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
  if (ws) { ws.onclose = null; ws.close(); ws = null }
  log(`Connecting to WebSocket: ${wsUrl}`); currentWsUrl = wsUrl; ws = new WebSocket(wsUrl);
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'new_message') {
        if (!currentMessages.some(m => m.id === data.message.id)) { currentMessages.unshift(data.message); renderMessages() }
      } else if (data.type === 'edit_message') {
        const idx = currentMessages.findIndex(m => m.id === data.message.id); if (idx !== -1) { currentMessages[idx] = data.message; renderMessages() }
      } else if (data.type === 'reaction_update') {
        const idx = currentMessages.findIndex(m => m.id === data.messageId); if (idx !== -1) { currentMessages[idx].reactions = data.reactions; renderMessages() }
      }
    } catch (e) { log('WS Message error', e) }
  };
  ws.onclose = () => { if (currentWsUrl === wsUrl) { log('WebSocket closed. Reconnecting in 3s...'); setTimeout(setupWebSocket, 3000) } };
  ws.onerror = (e) => { log('WebSocket error', e); };
}

// --- AUTH & PDS ---
const getDpopProof = async (session: any, method: string, url: string, nonce: string | null = null) => {
  const tokens = await session.getTokenSet(); const key = (session as any).server.dpopKey; const pub = key.bareJwk
  const jwk = { crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y }; const alg = key.algorithms.find((a: any) => a.startsWith('ES')) || 'ES256'
  const accessTokenBytes = new TextEncoder().encode(tokens.access_token); const hashBuffer = await crypto.subtle.digest('SHA-256', accessTokenBytes)
  const ath = btoa(String.fromCharCode(...new Uint8Array(hashBuffer))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
  const payload: any = { iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID(), htm: method, htu: url.split('?')[0].split('#')[0], ath }
  if (nonce) payload.nonce = nonce
  return await key.createJwt({ alg, typ: 'dpop+jwt', jwk }, payload)
}

async function pdsFetch(session: any, url: string, init: RequestInit = {}) {
  const tokens = await session.getTokenSet()
  const perform = async (nonce: string | null = null): Promise<Response> => {
    const proof = await getDpopProof(session, init.method || 'GET', url, nonce)
    const res = await fetch(url, { ...init, headers: { ...init.headers, 'Authorization': `DPoP ${tokens.access_token}`, 'DPoP': proof } })
    if (res.status === 401) { const newNonce = res.headers.get('dpop-nonce'); if (newNonce && nonce !== newNonce) return perform(newNonce) }
    return res
  }
  return perform()
}

async function authenticateWithServer(server: any) {
  const session = (window as any).atprotoSession; if (!session) return;
  const tokens = await session.getTokenSet(); const pdsUrl = tokens.aud.replace(/\/+$/, ''); const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${session.did}`;
  const submit = async (nonce: string | null = null) => {
    const dpop = await getDpopProof(session, 'GET', probeUrl, nonce);
    const res = await fetch(`${server.url}/api/auth`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ accessToken: tokens.access_token, dpopProof: dpop, pdsUrl, did: session.did }) });
    const data = await res.json(); if (data.isChallenge) return submit(data.dpopNonce);
    if (res.ok) { serverSessions.set(server.url, { token: data.token, expires: data.expiresAt }); log(`Authenticated with ${server.host}`) }
  };
  await submit();
}

// --- MESSAGE LOADING ---
async function refreshMessages(beforeId: string | null = null) {
  const container = document.getElementById('message-list')!
  if (!currentChannel || !currentServer || currentServer.error) { container.innerHTML = '<div style="padding:1rem;">Select a channel.</div>'; return }
  
  if (beforeId) {
    if (isLoadingOlder || !hasMoreMessages) return
    isLoadingOlder = true
  } else {
    container.innerHTML = `<div class="loading-container"><div class="big-spinner"></div><div>Loading...</div></div>`
    currentMessages = []; hasMoreMessages = true
  }

  try {
    const limit = 50
    const url = `${currentServer.url}/api/messages?channelId=${currentChannel.id}&limit=${limit}${beforeId ? '&before=' + beforeId : ''}`
    const res = await fetchWithTimeout(url, { timeout: 5000 })
    const data = await res.json()
    
    if (data.length < limit) hasMoreMessages = false
    
    if (beforeId) {
      const oldScrollHeight = container.scrollHeight
      currentMessages = [...currentMessages, ...data]
      renderMessages(false)
      container.scrollTop = container.scrollHeight - oldScrollHeight
      isLoadingOlder = false
    } else {
      currentMessages = data
      renderMessages(true)
      setupWebSocket()
    }
  } catch (e) { if (!beforeId) container.innerHTML = '<div style="padding:1rem; color:#f23f42;">Offline</div>' }
}

function renderMessages(shouldScrollBottom = true) {
  const container = document.getElementById('message-list')!
  if (currentMessages.length === 0) { container.innerHTML = '<div style="padding:1rem; color:#949ba4;"><em>No messages.</em></div>'; return }
  
  container.innerHTML = (hasMoreMessages ? '<div id="load-more-indicator" style="text-align:center; padding:10px; color:var(--subtext0); font-size:12px;">Scroll up to load more</div>' : '') + 
    currentMessages.slice().reverse().map((m: any) => {
    const reactionsByEmoji = (m.reactions || []).reduce((acc: any, r: any) => { if (!acc[r.emoji]) acc[r.emoji] = []; acc[r.emoji].push(r.handle); return acc; }, {});
    const myReactions = (m.reactions || []).filter((r: any) => r.did === currentUserDid).map((r: any) => r.emoji);
    const reactionHtml = Object.entries(reactionsByEmoji).map(([emoji, handles]: [string, any]) => `<div class="reaction-chip ${myReactions.includes(emoji) ? 'active' : ''}" onclick="window.toggleReaction('${m.id}', '${emoji}')" title="${handles.join(', ')}"><span>${emoji}</span><span class="reaction-count">${handles.length}</span></div>`).join('');
    const parentMsg = m.parent; 

    return `
      <div class="msg-item" id="msg-${m.id}">
        ${parentMsg ? `<div class="msg-reply-to" onclick="window.jumpToMessage('${parentMsg.id}')">
          <span style="opacity:0.6">@${parentMsg.handle}:</span> ${parentMsg.content.substring(0, 60)}${parentMsg.content.length > 60 ? '...' : ''}
        </div>` : ''}
        <div class="msg-actions">
          <div class="action-btn" onclick="window.replyTo('${m.id}')" title="Reply">↩</div>
          <div class="action-btn" onclick="window.toggleReaction('${m.id}', '👍')" title="Thumbs Up">👍</div>
          <div class="action-btn" onclick="window.toggleReaction('${m.id}', '❤️')" title="Love">❤️</div>
          ${m.did === currentUserDid ? `<div class="action-btn" onclick="window.enterEditMode('${m.id}')" title="Edit">✎</div>` : ''}
        </div>
        <div class="msg-header">
          <span class="msg-author">@${m.handle}</span>
          <span class="msg-date">${new Date(m.created_at).toLocaleString()}</span>
        </div>
        <div class="msg-content" id="msg-content-${m.id}">${linkify(m.content)}</div>
        <div class="reactions-list">${reactionHtml}</div>
      </div>
    `
  }).join('')
  
  if (shouldScrollBottom) container.scrollTop = container.scrollHeight
}

// --- SEARCH & NAVIGATION ---
(window as any).jumpToMessage = async (id: string) => {
  const existingEl = document.getElementById(`msg-${id}`)
  if (existingEl) {
    existingEl.scrollIntoView({ behavior: 'smooth', block: 'center' })
    existingEl.classList.add('flash-highlight')
    setTimeout(() => existingEl.classList.remove('flash-highlight'), 2000)
    return
  }

  const container = document.getElementById('message-list')!
  container.innerHTML = `<div class="loading-container"><div class="big-spinner"></div><div>Jumping to message...</div></div>`
  try {
    const res = await fetch(`${currentServer.url}/api/message-context?channelId=${currentChannel.id}&id=${id}`)
    currentMessages = await res.json()
    hasMoreMessages = true
    renderMessages(false)
    const targetEl = document.getElementById(`msg-${id}`)
    if (targetEl) {
      targetEl.scrollIntoView({ block: 'center' })
      targetEl.classList.add('flash-highlight')
      setTimeout(() => targetEl.classList.remove('flash-highlight'), 2000)
    }
  } catch (e) { log('Jump failed', e) }
};

(window as any).performSearch = async (query: string) => {
  const resultsEl = document.getElementById('search-results')!
  if (!query || query.length < 2) { resultsEl.style.display = 'none'; return }
  resultsEl.style.display = 'block'
  resultsEl.innerHTML = '<div style="padding:10px; color:var(--subtext0); font-size:12px;">Searching...</div>'
  try {
    const res = await fetch(`${currentServer.url}/api/search?channelId=${currentChannel.id}&q=${encodeURIComponent(query)}`)
    const results = await res.json()
    if (results.length === 0) { resultsEl.innerHTML = '<div style="padding:10px; color:var(--subtext0); font-size:12px;">No results</div>'; return }
    resultsEl.innerHTML = results.map((m: any) => `
      <div class="search-result-item" onclick="window.jumpToMessage('${m.id}'); document.getElementById('search-results').style.display='none'">
        <div class="search-result-header"><span>@${m.handle}</span><span>${new Date(m.created_at).toLocaleDateString()}</span></div>
        <div class="search-result-content">${m.content.substring(0, 80)}${m.content.length > 80 ? '...' : ''}</div>
      </div>
    `).join('')
  } catch (e) { resultsEl.innerHTML = '<div style="padding:10px; color:var(--red); font-size:12px;">Search failed</div>' }
};

// --- ACTIONS ---
async function serverMutation(server: any, endpoint: string, body: any) {
  const session = (window as any).atprotoSession; if (!session) return;
  const tokens = await session.getTokenSet(); const pdsUrl = tokens.aud.replace(/\/+$/, ''); const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${session.did}`;
  const submit = async (nonce: string | null = null) => {
    const dpop = await getDpopProof(session, 'GET', probeUrl, nonce); const headers: any = { 'Content-Type': 'application/json' };
    const s = serverSessions.get(server.url); if (s && new Date(s.expires) > new Date()) headers['Authorization'] = `Bearer ${s.token}`;
    const res = await fetch(`${server.url}${endpoint}`, { method: 'POST', headers, body: JSON.stringify({ ...body, accessToken: tokens.access_token, dpopProof: dpop, pdsUrl, did: session.did }) });
    const data = await res.json(); if (data.isChallenge) return submit(data.dpopNonce);
    return { ok: res.ok, data };
  };
  return await submit();
}

(window as any).toggleReaction = async (messageId: string, emoji: string) => {
  const msg = currentMessages.find(m => m.id === messageId); if (!msg) return
  const isRemoving = (msg.reactions || []).some((r: any) => r.did === currentUserDid && r.emoji === emoji)
  await serverMutation(currentServer, isRemoving ? '/api/unreact' : '/api/react', { messageId, emoji });
};

(window as any).submitMessage = async () => {
  const input = document.getElementById('message-input') as HTMLInputElement; const content = input.value.trim(); if (!content) return
  const parentId = replyToMessage?.id || null; setLoading('#input-area', true); input.value = ''; (window as any).cancelReply();
  const res = await serverMutation(currentServer, '/api/submit-message', { content, channelId: currentChannel.id, parentId });
  setLoading('#input-area', false); if (res?.ok && !currentServer.features?.ws) refreshMessages(); else if (!res?.ok) alert('Failed to send.');
};

(window as any).saveEdit = async (id: string) => {
  const input = document.getElementById(`edit-input-${id}`) as HTMLInputElement; const content = input.value.trim(); if (!content) return
  setLoading(`#edit-save-${id}`, true, '...');
  const res = await serverMutation(currentServer, '/api/edit-message', { id, content });
  setLoading(`#edit-save-${id}`, false); if (res?.ok && !currentServer.features?.ws) refreshMessages();
};

// --- SYSTEM ---
async function init() {
  try {
    const result = await client.init()
    if (result?.session) {
      const returnPath = sessionStorage.getItem('latent_return_path')
      if (returnPath && returnPath !== '/' && window.location.pathname === '/') { window.history.replaceState({}, '', returnPath); sessionStorage.removeItem('latent_return_path') }
      await showApp(result.session)
    } else {
      loadMsg('Hydrating servers...'); const storedUrls = localStorage.getItem('atproto_servers');
      SERVER_URLS = storedUrls ? JSON.parse(storedUrls) : DEFAULT_SERVER_URLS; await hydrateServers();
      document.getElementById('loading-panel')!.style.display = 'none'; document.getElementById('login-panel')!.style.display = 'flex'
    }
    renderAll()
  } catch (err) { log('Init failed', err) }
}

async function hydrateServers() {
  const pathParts = window.location.pathname.split('/').filter(Boolean); const targetHost = pathParts[0]
  if (targetHost && !SERVER_URLS.some(u => new URL(u).host === targetHost)) {
    try {
      const proto = targetHost.includes('127.0.0.1') ? 'http' : 'https'; const discoverUrl = `${proto}://${targetHost}`
      const res = await fetchWithTimeout(`${discoverUrl}/api/meta`, { timeout: 10000 });
      if (res.ok) { const meta = await res.json(); if (confirm(`Join "${meta.name}" (${targetHost})?`)) { SERVER_URLS.push(discoverUrl); if ((window as any).atprotoSession) await (window as any).saveClientSettingsDirect(SERVER_URLS); else localStorage.setItem('atproto_servers', JSON.stringify(SERVER_URLS)) } }
    } catch (e) { log(`Discovery failed for ${targetHost}`, e) }
  }
  SERVERS = await Promise.all(SERVER_URLS.map(async (url) => {
    try { 
      const res = await fetchWithTimeout(`${url}/api/meta`, { timeout: 10000 }); 
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const meta = await res.json(); const host = new URL(url).host; return { ...meta, url, host, id: meta.id || host } 
    }
    catch (e) { const host = new URL(url).host; log(`Server ${host} is offline`, e); return { id: host, name: 'Offline Server', url, host, error: true, categories: [], channels: [] } }
  }))
  if (targetHost) currentServer = SERVERS.find(s => s.host === targetHost)
  if (!currentServer) currentServer = SERVERS[0]
  if (currentServer && !currentServer.error) {
    if (pathParts[1]) { const decodedName = decodeURIComponent(pathParts[1]); currentChannel = currentServer.channels?.find((c: any) => c.name === decodedName) }
    if (!currentChannel && currentServer.channels?.length > 0) currentChannel = currentServer.channels[0]
  }
}

async function syncServersFromPds(session: any) {
  loadMsg('Syncing servers from PDS...')
  try {
    const tokens = await session.getTokenSet(); const pdsUrl = tokens.aud.replace(/\/+$/, '')
    const res = await pdsFetch(session, `${pdsUrl}/xrpc/com.atproto.repo.listRecords?repo=${session.did}&collection=org.latha.latent.server`)
    const data = await res.json(); let pdsUrls = data.records?.map((r: any) => r.value.url) || []
    SERVER_URLS = Array.from(new Set([...pdsUrls, ...SERVER_URLS, ...DEFAULT_SERVER_URLS])); if (pdsUrls.length !== SERVER_URLS.length) await window.saveClientSettingsDirect(SERVER_URLS)
  } catch (e) { SERVER_URLS = DEFAULT_SERVER_URLS }
  await hydrateServers(); for (const s of SERVERS) if (!s.error) authenticateWithServer(s);
}

function renderAll() {
  renderServerList()
  if (currentServer) {
    renderChannelList(); const nameEl = document.getElementById('current-server-name'); if (nameEl) nameEl.textContent = currentServer.name || 'Unknown'
    const chanEl = document.getElementById('current-channel-name'); if (chanEl) chanEl.textContent = currentChannel?.name || 'no-channel'
    refreshMessages(); renderAdminUI()
  }
}

function renderServerList() {
  const sidebar = document.getElementById('server-sidebar')!; sidebar.innerHTML = SERVERS.map(s => {
    const initial = (s.name && s.name[0]) || '?'; const statusClass = s.error ? 'offline' : ''; const activeClass = s.host === currentServer?.host ? 'active' : ''
    return `<div class="server-icon ${activeClass} ${statusClass}" onclick="window.selectServer('${s.host}')" title="${s.name || 'Offline'}">${initial}</div>`
  }).join('') + `<div class="server-icon add-server" onclick="window.toggleClientSettings()" title="Settings">+</div>`
}

function renderChannelList() {
  const list = document.getElementById('channel-list')!; if (!currentServer || currentServer.error) { list.innerHTML = '<div style="padding:1rem; color:#f23f42;">Server Offline</div>'; return }
  const categories = currentServer.categories || []; const channels = currentServer.channels || []; let html = ''
  channels.filter((c: any) => !c.category_id).forEach((c: any) => { html += `<div class="channel-item ${currentChannel?.id === c.id ? 'active' : ''}" onclick="window.selectChannel('${c.id}')"><span class="channel-hash">#</span> ${c.name}${isAdmin() ? `<span class="delete-icon" onclick="event.stopPropagation();window.deleteChannel('${c.id}')">×</span>` : ''}</div>` })
  categories.forEach((cat: any) => {
    html += `<div class="category-item"><span class="category-arrow">▼</span> ${cat.name}${isAdmin() ? `<span class="add-icon" onclick="event.stopPropagation();window.promptAddChannel('${cat.id}')">+</span><span class="delete-icon" onclick="event.stopPropagation();window.deleteCategory('${cat.id}')">×</span>` : ''}</div>`
    channels.filter((c: any) => c.category_id === cat.id).forEach((c: any) => { html += `<div class="channel-item ${currentChannel?.id === c.id ? 'active' : ''}" onclick="window.selectChannel('${c.id}')"><span class="channel-hash">#</span> ${c.name}${isAdmin() ? `<span class="delete-icon" onclick="event.stopPropagation();window.deleteChannel('${c.id}')">×</span>` : ''}</div>` })
  })
  if (isAdmin()) html += `<div class="category-item" onclick="window.addCategory()" style="cursor:pointer; margin-top:10px; color:#5865f2;">+ Add Category</div>`
  list.innerHTML = html
}

function linkify(text: string) { return text.replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank" rel="noopener noreferrer" style="color: var(--blue); text-decoration: underline;">$1</a>') }

// --- UI HELPERS ---
(window as any).replyTo = (id: string) => { const msg = currentMessages.find(m => m.id === id); if (!msg) return; replyToMessage = msg; document.getElementById('app-container')!.classList.add('is-replying'); document.getElementById('reply-bar')!.style.display = 'flex'; document.getElementById('reply-text')!.textContent = `Replying to @${msg.handle}`; document.getElementById('message-input')!.focus() };
(window as any).cancelReply = () => { replyToMessage = null; document.getElementById('app-container')!.classList.remove('is-replying'); document.getElementById('reply-bar')!.style.display = 'none' };
(window as any).toggleMenu = (open: boolean) => { const container = document.getElementById('app-container')!; if (container) { if (open) container.classList.add('menu-open'); else container.classList.remove('menu-open') } };
(window as any).selectServer = (host: string) => { const server = SERVERS.find(s => s.host === host); if (server) { currentServer = server; currentChannel = server.channels?.[0] || null; window.history.pushState({}, '', `/${currentServer.host}${currentChannel ? '/' + encodeURIComponent(currentChannel.name) : ''}`); renderAll(); if (window.innerWidth <= 768) (window as any).toggleMenu(true) } };
(window as any).selectChannel = (id: string) => { const chan = currentServer.channels.find((c: any) => c.id === id); if (chan) { currentChannel = chan; window.history.pushState({}, '', `/${currentServer.host}/${encodeURIComponent(currentChannel.name)}`); renderAll(); if (window.innerWidth <= 768) (window as any).toggleMenu(false) } };
(window as any).enterEditMode = (id: string) => { const contentEl = document.getElementById(`msg-content-${id}`)!; const original = contentEl.textContent!; contentEl.innerHTML = `<input type="text" id="edit-input-${id}" class="edit-input" value="${original.replace(/"/g, '&quot;')}" /><div class="edit-actions"><button onclick="window.saveEdit('${id}')" class="edit-save" id="edit-save-${id}">Save</button><button onclick="window.cancelEdit('${id}', '${original.replace(/'/g, "\\'")}')" class="edit-cancel">Cancel</button></div>`; document.getElementById(`edit-input-${id}`)?.focus() };
(window as any).cancelEdit = (id: string, original: string) => { document.getElementById(`msg-content-${id}`)!.textContent = original };
(window as any).toggleClientSettings = () => { const modal = document.getElementById('client-settings-modal')!; modal.style.display = modal.style.display === 'none' ? 'flex' : 'none'; if (modal.style.display === 'flex') (document.getElementById('server-urls-input') as HTMLTextAreaElement).value = SERVER_URLS.join('\n') };
(window as any).saveClientSettingsDirect = async (newUrls: string[]) => {
  const session = (window as any).atprotoSession; if (!session) { localStorage.setItem('atproto_servers', JSON.stringify(newUrls)); return }
  try {
    const tokens = await session.getTokenSet(); const pdsUrl = tokens.aud.replace(/\/+$/, ''); const listRes = await pdsFetch(session, `${pdsUrl}/xrpc/com.atproto.repo.listRecords?repo=${session.did}&collection=org.latha.latent.server`)
    const existing = await listRes.json(); for (const record of (existing.records || [])) { await pdsFetch(session, `${pdsUrl}/xrpc/com.atproto.repo.deleteRecord`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ repo: session.did, collection: 'org.latha.latent.server', rkey: record.uri.split('/').pop() }) }) }
    for (const url of newUrls) { await pdsFetch(session, `${pdsUrl}/xrpc/com.atproto.repo.createRecord`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ repo: session.did, collection: 'org.latha.latent.server', record: { $type: 'org.latha.latent.server', url, createdAt: new Date().toISOString() } }) }) }
  } catch (e) { log('PDS save failed', e) }
};
(window as any).saveClientSettings = async () => { setLoading('#client-settings-modal .admin-save-btn', true, 'Syncing...'); const input = (document.getElementById('server-urls-input') as HTMLTextAreaElement).value; const newUrls = input.split('\n').map(u => u.trim()).filter(Boolean); await (window as any).saveClientSettingsDirect(newUrls); location.href = '/' };
async function showApp(session: any) { (window as any).atprotoSession = session; currentUserDid = session.did; const fetchProfile = async () => { try { const tokens = await session.getTokenSet(); const pdsUrl = tokens.aud.replace(/\/+$/, ''); const probeUrl = `${pdsUrl}/xrpc/app.bsky.actor.getProfile?actor=${session.did}`; const res = await pdsFetch(session, probeUrl); const profile = await res.json(); if (profile.handle) { currentUserHandle = profile.handle; document.getElementById('user-handle')!.textContent = `@${profile.handle}`; await syncServersFromPds(session); renderAdminUI() } } catch (e) { log('Profile failed', e) } }; await fetchProfile(); document.getElementById('loading-panel')!.style.display = 'none'; document.getElementById('app-container')!.style.display = 'flex' }
(window as any).startLogin = async () => { const handle = (document.getElementById('handle') as HTMLInputElement).value; if (window.location.pathname !== '/') sessionStorage.setItem('latent_return_path', window.location.pathname); await client.signIn(handle) };
(window as any).logout = () => { localStorage.clear(); location.href = '/' };
(window as any).toggleAdminMenu = () => { const menu = document.getElementById('admin-menu')!; menu.style.display = menu.style.display === 'none' ? 'flex' : 'none'; if (menu.style.display === 'flex') (document.getElementById('new-server-name') as HTMLInputElement).value = currentServer?.name || '' };
(window as any).saveServerConfig = async () => { const name = (document.getElementById('new-server-name') as HTMLInputElement).value.trim(); setLoading('#admin-menu .admin-save-btn', true, 'Saving...'); const res = await serverMutation(currentServer, '/api/meta', { name }); setLoading('#admin-menu .admin-save-btn', false); if (res?.ok) { currentServer.name = name; const serverIdx = SERVERS.findIndex(s => s.id === currentServer.id); if (serverIdx !== -1) SERVERS[serverIdx].name = name; renderAll(); document.getElementById('admin-menu')!.style.display = 'none' } };
(window as any).addCategory = async () => { const name = prompt('Category Name:'); if (name && (await serverMutation(currentServer, '/api/categories', { name })).ok) location.reload() };
(window as any).deleteCategory = async (id: string) => { if (confirm('Delete category?') && (await serverMutation(currentServer, `/api/categories/${id}`, { method: 'DELETE' })).ok) location.reload() };
(window as any).promptAddChannel = async (catId: string | null = null) => { const name = prompt('Channel Name:'); if (name && (await serverMutation(currentServer, '/api/channels', { name, category_id: catId })).ok) location.reload() };
(window as any).deleteChannel = async (id: string) => { if (confirm('Delete channel?') && (await serverMutation(currentServer, `/api/channels/${id}`, { method: 'DELETE' })).ok) location.reload() };

const msgList = document.getElementById('message-list');
if (msgList) {
  msgList.onscroll = () => {
    if (msgList.scrollTop < 10 && currentMessages.length > 0 && hasMoreMessages && !isLoadingOlder) {
      refreshMessages(currentMessages[currentMessages.length - 1].id);
    }
  };
}

const inputEl = document.getElementById('message-input');
if (inputEl) { inputEl.onkeydown = (e) => { if (e.key === 'Enter') (window as any).submitMessage() }; }

const sInput = document.getElementById('search-input');
if (sInput) {
  sInput.oninput = (e: any) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => (window as any).performSearch(e.target.value), 300);
  };
}

init()
