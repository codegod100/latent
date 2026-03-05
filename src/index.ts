import express from 'express'

const PORT = 3010
const APP_ORIGIN = `http://127.0.0.1:${PORT}`
const REDIRECT_URI = `${APP_ORIGIN}/`

const app = express()
app.use(express.json())

// Serve the bundled frontend
app.use('/public', express.static('public'))

// 1. DYNAMIC METADATA (Required for various loopback origins)
app.get('/client-metadata.json', (req, res) => {
  const origin = req.get('origin') || `http://${req.get('host')}`
  const redirectUri = `${origin}/`
  const clientId = `${origin}/client-metadata.json`

  res.json({
    client_id: clientId,
    client_name: 'Isolated ATProto Client',
    application_type: 'web',
    token_endpoint_auth_method: 'none',
    dpop_bound_access_tokens: true,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: [redirectUri],
    scope: 'atproto transition:generic'
  })
})

// 2. CATCH-ALL ROUTE (Serves index.html for all paths to support SPA routing/permalinks)
app.get('*', (req, res) => {
  // If it looks like an API call that missed, 404 it
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' })
  }
  
  res.send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>ATProto Multi-Server Chat</title>
  <style>
    body { margin: 0; padding: 0; font-family: system-ui, -apple-system, sans-serif; background: #313338; color: #dbdee1; height: 100vh; overflow: hidden; }
    #app-container { display: none; height: 100vh; width: 100vw; }
    #server-sidebar { width: 72px; background: #1e1f22; display: flex; flex-direction: column; align-items: center; padding-top: 12px; gap: 8px; flex-shrink: 0; }
    .server-icon { width: 48px; height: 48px; border-radius: 50%; background: #313338; color: #dbdee1; display: flex; align-items: center; justify-content: center; font-weight: bold; cursor: pointer; transition: all 0.2s; position: relative; }
    .server-icon:hover { border-radius: 16px; background: #5865f2; color: white; }
    .server-icon.active { border-radius: 16px; background: #5865f2; color: white; }
    .server-icon.active::before { content: ""; position: absolute; left: -12px; height: 40px; width: 4px; background: white; border-radius: 0 4px 4px 0; }
    #chat-area { flex-grow: 1; display: flex; flex-direction: column; background: #313338; }
    #chat-header { height: 48px; padding: 0 16px; display: flex; align-items: center; border-bottom: 1px solid #262729; font-weight: bold; }
    #message-list { flex-grow: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column-reverse; gap: 16px; }
    #input-area { padding: 0 16px 24px 16px; }
    #message-input { width: 100%; padding: 11px; background: #383a40; border: none; border-radius: 8px; color: #dbdee1; font-size: 1rem; box-sizing: border-box; }
    .msg-item { display: flex; flex-direction: column; gap: 4px; }
    .msg-header { display: flex; align-items: baseline; gap: 8px; }
    .msg-author { color: #f2f3f5; font-weight: 600; font-size: 1rem; }
    .msg-date { color: #949ba4; font-size: 0.75rem; }
    .msg-content { color: #dbdee1; line-height: 1.375; }
    #login-panel { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; background: #313338; z-index: 100; }
    .login-card { background: #313338; padding: 32px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.2); width: 100%; max-width: 400px; text-align: center; }
    .login-input { width: 100%; padding: 10px; margin: 20px 0; background: #1e1f22; border: 1px solid #1e1f22; border-radius: 3px; color: white; box-sizing: border-box; }
    .login-btn { width: 100%; padding: 10px; background: #5865f2; color: white; border: none; border-radius: 3px; cursor: pointer; font-weight: bold; }
    #console-toggle { position: absolute; bottom: 80px; right: 20px; background: rgba(0,0,0,0.5); padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 12px; }
    #console { position: absolute; bottom: 100px; right: 20px; width: 300px; max-height: 400px; background: #1e1f22; color: #23a559; padding: 10px; font-family: monospace; font-size: 11px; overflow: auto; border-radius: 8px; display: none; pointer-events: none; }
    #user-info { margin-left: auto; display: flex; align-items: center; gap: 12px; }
    #user-handle { font-size: 0.85rem; color: #b5bac1; }
    #logout-btn { background: none; border: none; color: #dbdee1; cursor: pointer; padding: 4px 8px; font-size: 0.85rem; }
    #loading-panel { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; background: #313338; z-index: 200; }
    .spinner { border: 4px solid #4e5058; border-top: 4px solid #5865f2; border-radius: 50%; width: 32px; height: 32px; animation: spin 1s linear infinite; margin-bottom: 12px; }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div id="loading-panel">
    <div class="spinner"></div>
    <div>Syncing with ATProto...</div>
  </div>
  <div id="login-panel" style="display:none">
    <div class="login-card">
      <h2>Welcome back!</h2>
      <p style="color: #b5bac1;">Log in with your ATProto handle to join the chat.</p>
      <input id="handle" class="login-input" value="nandi.latha.org" placeholder="your-handle.bsky.social">
      <button onclick="startLogin()" class="login-btn">Log In</button>
    </div>
  </div>
  <div id="app-container">
    <div id="server-sidebar"></div>
    <div id="chat-area">
      <div id="chat-header">
        <span style="color:#80848e; margin-right: 8px;">#</span>
        <span id="current-server-name">General</span>
        <div id="user-info">
          <span id="user-handle">...</span>
          <button id="logout-btn" onclick="logout()">Logout</button>
        </div>
      </div>
      <div id="message-list"></div>
      <div id="input-area">
        <input id="message-input" placeholder="Message #General">
      </div>
    </div>
  </div>
  <div id="console-toggle" onclick="const c=document.getElementById('console'); c.style.display=c.style.display==='none'?'block':'none'">Toggle System Log</div>
  <pre id="console">Initializing system...</pre>
  <script src="/public/bundle.js?v=${Date.now()}"></script>
</body>
</html>
  `)
})

app.listen(PORT, '127.0.0.1', () => console.log(`Local dev server running at http://127.0.0.1:${PORT}`))
