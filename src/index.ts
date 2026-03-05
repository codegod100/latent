import express from 'express'
import Database from 'better-sqlite3'
import * as path from 'node:path'

const PORT = 3010
const APP_ORIGIN = `http://127.0.0.1:${PORT}`
const REDIRECT_URI = `${APP_ORIGIN}/`
const CLIENT_ID = `http://localhost/?redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=atproto%20transition:generic`

// 1. DATABASE SETUP
const db = new Database('data.db')
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    handle TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`)

const app = express()
app.use(express.json())
app.use('/public', express.static('public'))

// 2. STATELESS METADATA
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

// 3. SECURE MESSAGE SUBMISSION (Verification + Storage)
app.post('/api/submit-message', async (req, res) => {
  const { accessToken, dpopProof, pdsUrl, did, content } = req.body
  
  if (!content || String(content).trim().length === 0) {
    return res.status(400).json({ error: 'Message content is required' })
  }

  try {
    // A. Verify identity with PDS first
    const probeUrl = `${String(pdsUrl).replace(/\/+$/, '')}/xrpc/app.bsky.actor.getProfile?actor=${did}`
    console.log('[external-server] Verifying identity for message storage: ' + probeUrl)
    
    const pdsRes = await fetch(probeUrl, {
      headers: { 'Authorization': `DPoP ${accessToken}`, 'DPoP': dpopProof }
    })
    
    const dpopNonce = pdsRes.headers.get('dpop-nonce')
    
    if (!pdsRes.ok) {
      const errorData = await pdsRes.json()
      return res.status(pdsRes.status).json({ 
        verified: false, 
        error: 'Identity verification failed', 
        pdsResponse: errorData,
        dpopNonce 
      })
    }

    // B. Identity confirmed, get the handle
    const profile = await pdsRes.json()
    const handle = profile.handle || 'unknown'

    // C. Store in SQLite
    const stmt = db.prepare('INSERT INTO messages (did, handle, content) VALUES (?, ?, ?)')
    const info = stmt.run(did, handle, content)

    console.log(`[external-server] Message stored for @${handle} (id: ${info.lastInsertRowid})`)

    res.json({
      verified: true,
      message_id: info.lastInsertRowid,
      author: handle,
      content
    })
  } catch (err) {
    res.status(500).json({ error: String(err) })
  }
})

// Get recent messages
app.get('/api/messages', (req, res) => {
  const messages = db.prepare('SELECT * FROM messages ORDER BY created_at DESC LIMIT 50').all()
  res.json(messages)
})

// 4. THE MAIN PAGE
app.get('/', (req, res) => {
  res.send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Identity-Verified Storage</title>
  <style>
    body { font-family: system-ui; max-width: 800px; margin: 2rem auto; line-height: 1.5; padding: 0 1rem; }
    .panel { border: 1px solid #ccc; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem; background: #fdfdfd; }
    button { padding: 0.6rem 1.2rem; cursor: pointer; background: #007bff; color: white; border: none; border-radius: 4px; font-weight: bold; }
    button:disabled { background: #ccc; cursor: not-allowed; }
    pre { background: #111; color: #0f0; padding: 1rem; border-radius: 6px; overflow: auto; max-height: 200px; font-size: 0.85rem; }
    input { padding: 0.6rem; width: 100%; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 1rem; }
    .msg-item { border-bottom: 1px solid #eee; padding: 0.5rem 0; }
    .msg-author { font-weight: bold; color: #007bff; }
    .msg-date { color: #666; font-size: 0.8rem; }
  </style>
</head>
<body>
  <h1>ATProto Verified Storage</h1>
  <p>Messages are stored in a local SQLite database ONLY after your identity is verified via DPoP.</p>

  <div id="loading-panel" class="panel" style="text-align: center; padding: 2rem;">
    <div class="spinner"></div>
    <p>Checking session...</p>
  </div>

  <div id="login-panel" class="panel" style="display:none">
    <label style="display:block; font-weight:bold; margin-bottom:0.5rem;">Handle</label>
    <div style="display:flex; gap:0.5rem;">
      <input id="handle" value="nandi.latha.org" placeholder="handle.bsky.social">
      <button onclick="startLogin()" style="white-space:nowrap;">Login via PDS</button>
    </div>
  </div>

  <div id="app-panel" class="panel" style="display:none">
    <h3>Hello, <span id="user-handle" style="color:#007bff"></span></h3>
    <div style="margin-top: 1rem; display:flex; flex-direction:column; gap:0.5rem;">
      <label style="font-weight:bold;">New Message</label>
      <input id="message-input" placeholder="Type something to store on the server...">
      <button id="submit-btn" style="background: #28a745; width:fit-content;">Submit Message</button>
    </div>
    <br>
    <button onclick="localStorage.clear();location.href='/'" style="background:#666; font-size:0.8rem; padding:0.4rem 0.8rem;">Logout</button>
  </div>

  <div class="panel">
    <h3>Global Message Board</h3>
    <div id="message-list">Loading messages...</div>
  </div>

  <h3>System Log</h3>
  <pre id="console">Loading bundle...</pre>

  <style>
    .spinner {
      border: 4px solid #f3f3f3;
      border-top: 4px solid #007bff;
      border-radius: 50%;
      width: 30px;
      height: 30px;
      animation: spin 1s linear infinite;
      display: inline-block;
      vertical-align: middle;
      margin-right: 10px;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
  </style>
  <script src="/public/bundle.js"></script>
</body>
</html>
  `)
})

app.listen(PORT, '127.0.0.1', () => console.log(`Server listening on ${APP_ORIGIN}`))
