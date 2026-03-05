import { ulid } from 'ulid';
import { Storage } from './storage';

export async function handleRequest(request: Request, storage: Storage, configSeed: { adminHandle: string, defaultName: string }): Promise<Response> {
  const url = new URL(request.url);
  const headers = new Headers({
    'Access-Control-Allow-Origin': '*', 
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, DPoP',
  });

  if (request.method === 'OPTIONS') return new Response(null, { headers });

  // 1. SYNC CONFIG
  const serverId = (await storage.getConfig('server_id')) || (await (async () => {
    const id = ulid();
    await storage.setConfig('server_id', id);
    return id;
  })());
  const serverName = (await storage.getConfig('server_name')) || (await (async () => {
    await storage.setConfig('server_name', configSeed.defaultName);
    return configSeed.defaultName;
  })());
  const adminHandle = (await storage.getConfig('admin_handle')) || (await (async () => {
    await storage.setConfig('admin_handle', configSeed.adminHandle);
    return configSeed.adminHandle;
  })());

  // 2. ENSURE DEFAULT CHANNEL
  const channels = await storage.listChannels();
  if (channels.length === 0) {
    await storage.addChannel(ulid(), null, 'general', 'General discussion', 0);
  }

  // 3. IDENTITY NOTARY (Verifies DID + Handle via PDS)
  const verifyIdentity = async (body: any) => {
    const { accessToken, dpopProof, pdsUrl, did } = body;
    const probeUrl = `${String(pdsUrl).replace(/\/+$/, '')}/xrpc/app.bsky.actor.getProfile?actor=${did}`;
    
    const pdsRes = await fetch(probeUrl, { 
      headers: { 'Authorization': `DPoP ${accessToken}`, 'DPoP': dpopProof } 
    });
    const dpopNonce = pdsRes.headers.get('dpop-nonce');
    
    if (!pdsRes.ok) {
      throw { 
        status: pdsRes.status, 
        isChallenge: pdsRes.status === 401 && !!dpopNonce,
        dpopNonce, 
        error: 'Identity verification failed' 
      };
    }
    
    return await pdsRes.json() as any;
  };

  const verifyAdmin = async (body: any) => {
    const profile = await verifyIdentity(body);
    if (profile.handle !== adminHandle) {
      throw { status: 403, error: 'Admin only' };
    }
    return profile;
  };

  // 4. ROUTING
  try {
    // --- LANDING PAGE ---
    if (url.pathname === '/') {
      return new Response(`
        <!doctype html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>ATProto Backend</title>
          <style>
            body { font-family: system-ui, sans-serif; max-width: 600px; margin: 2rem auto; line-height: 1.6; padding: 0 1rem; background: #1e1e2e; color: #cdd6f4; }
            h1 { color: #89b4fa; border-bottom: 1px solid #313244; padding-bottom: 0.5rem; }
            strong { color: #f5e0dc; }
            .info-box { background: #313244; padding: 1.5rem; border-radius: 8px; border-left: 4px solid #b4befe; margin: 1.5rem 0; }
            code { background: #181825; padding: 0.2rem 0.4rem; border-radius: 4px; color: #a6e3a1; font-family: monospace; }
            a { color: #89b4fa; text-decoration: none; }
          </style>
        </head>
        <body>
          <h1>ATProto Verified Backend: ${serverName}</h1>
          <div class="info-box">
            <strong>Server ID:</strong> <code>${serverId}</code><br>
            <strong>Admin:</strong> <code>@${adminHandle}</code>
          </div>
          <p>Status: <strong>Active (latent-core)</strong></p>
        </body>
        </html>
      `, { headers: { ...Object.fromEntries(headers), 'Content-Type': 'text/html' } });
    }

    // --- API: META ---
    if (url.pathname === '/api/meta') {
      if (request.method === 'GET') {
        const categories = await storage.listCategories();
        const chanList = await storage.listChannels();
        return new Response(JSON.stringify({ id: serverId, name: serverName, adminHandle, categories, channels: chanList }), 
          { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
      }
      if (request.method === 'POST') {
        const body = await request.json() as any;
        await verifyAdmin(body);
        await storage.setConfig('server_name', body.name);
        return new Response(JSON.stringify({ ok: true }), { headers });
      }
    }

    // --- API: CATEGORIES ---
    if (url.pathname === '/api/categories' && request.method === 'POST') {
      const body = await request.json() as any;
      await verifyAdmin(body);
      const id = ulid();
      await storage.addCategory(id, body.name, body.sort_order || 0);
      return new Response(JSON.stringify({ ok: true, id }), { headers });
    }
    if (url.pathname.startsWith('/api/categories/') && request.method === 'DELETE') {
      const id = url.pathname.split('/').pop()!;
      const body = await request.json() as any;
      await verifyAdmin(body);
      await storage.deleteCategory(id);
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

    // --- API: CHANNELS ---
    if (url.pathname === '/api/channels' && request.method === 'POST') {
      const body = await request.json() as any;
      await verifyAdmin(body);
      const id = ulid();
      await storage.addChannel(id, body.category_id || null, body.name, body.description || '', body.sort_order || 0);
      return new Response(JSON.stringify({ ok: true, id }), { headers });
    }
    if (url.pathname.startsWith('/api/channels/') && request.method === 'DELETE') {
      const id = url.pathname.split('/').pop()!;
      const body = await request.json() as any;
      await verifyAdmin(body);
      await storage.deleteChannel(id);
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

    // --- API: MESSAGES ---
    if (url.pathname === '/api/messages' && request.method === 'GET') {
      const channelId = url.searchParams.get('channelId');
      const messages = await storage.listMessages(channelId);
      return new Response(JSON.stringify(messages), { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
    }

    if (url.pathname === '/api/submit-message' && request.method === 'POST') {
      const body = await request.json() as any;
      const profile = await verifyIdentity(body);
      const { did, content, channelId } = body;
      const msgId = ulid();
      await storage.addMessage(msgId, did, profile.handle, content, channelId || null);
      return new Response(JSON.stringify({ ok: true, id: msgId }), { headers });
    }

    if (url.pathname === '/api/edit-message' && request.method === 'POST') {
      const body = await request.json() as any;
      const profile = await verifyIdentity(body);
      const { id, content, did } = body;
      
      // Authorization check happens in updateMessage (WHERE did = ?)
      const success = await storage.updateMessage(id, did, content);
      if (!success) throw { status: 403, error: 'Unauthorized or message not found' };
      
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

  } catch (err: any) {
    const status = err.status === 401 ? 200 : (err.status || 500);
    return new Response(JSON.stringify(err), { status, headers });
  }

  return new Response('Not Found', { status: 404, headers });
}
