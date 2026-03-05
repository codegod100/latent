import { ulid } from 'ulid';
import { Storage } from './storage';

export interface Notifier {
  broadcast(channelId: string | null, message: any): Promise<void>;
}

// In-memory cache for verified identities to speed up repeated requests
const identityCache = new Map<string, { profile: any, expires: number }>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

export async function handleRequest(
  request: Request, 
  storage: Storage, 
  configSeed: { adminHandle: string, defaultName: string },
  notifier?: Notifier
): Promise<Response> {
  const url = new URL(request.url);
  const headers = new Headers({
    'Access-Control-Allow-Origin': '*', 
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, DPoP',
  });

  if (request.method === 'OPTIONS') return new Response(null, { headers });

  try {
    await storage.ensureTables();

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

    const channels = await storage.listChannels();
    if (channels.length === 0) {
      await storage.addChannel(ulid(), null, 'general', 'General discussion', 0);
    }

    // --- OPTIMIZED IDENTITY VERIFIER ---
    const verifyIdentity = async (body: any) => {
      const { accessToken, dpopProof, pdsUrl, did } = body;
      
      // Check Cache First
      const cacheKey = `${did}:${accessToken}`;
      const cached = identityCache.get(cacheKey);
      if (cached && cached.expires > Date.now()) {
        return cached.profile;
      }

      const probeUrl = `${String(pdsUrl).replace(/\/+$/, '')}/xrpc/app.bsky.actor.getProfile?actor=${did}`;
      const pdsRes = await fetch(probeUrl, { headers: { 'Authorization': `DPoP ${accessToken}`, 'DPoP': dpopProof } });
      const dpopNonce = pdsRes.headers.get('dpop-nonce');
      
      if (!pdsRes.ok) {
        throw { status: pdsRes.status, isChallenge: pdsRes.status === 401 && !!dpopNonce, dpopNonce, error: 'Identity verification failed' };
      }
      
      const profile = await pdsRes.json() as any;
      
      // Store in Cache
      identityCache.set(cacheKey, { profile, expires: Date.now() + CACHE_TTL });
      return profile;
    };

    const verifyAdmin = async (body: any) => {
      const profile = await verifyIdentity(body);
      if (profile.handle !== adminHandle) throw { status: 403, error: 'Admin only' };
      return profile;
    };

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
            .info-box { background: #313244; padding: 1.5rem; border-radius: 8px; border-left: 4px solid #b4befe; margin: 1.5rem 0; }
            code { background: #181825; padding: 0.2rem 0.4rem; border-radius: 4px; color: #a6e3a1; font-family: monospace; }
          </style>
        </head>
        <body>
          <h1>ATProto Verified Backend: ${serverName}</h1>
          <div class="info-box">
            <strong>Server ID:</strong> <code>${serverId}</code><br>
            <strong>Admin:</strong> <code>@${adminHandle}</code>
          </div>
          <p>Status: <strong>Active (Optimized Logic)</strong></p>
        </body>
        </html>
      `, { headers: { ...Object.fromEntries(headers), 'Content-Type': 'text/html' } });
    }

    if (url.pathname === '/api/ws') {
      if (request.headers.get('Upgrade') !== 'websocket') return new Response('Expected WebSocket upgrade', { status: 400 });
      if (!notifier) return new Response('WebSockets not supported on this node', { status: 501 });
      return new Response(null, { status: 101, headers: { 'Upgrade': 'websocket', 'Connection': 'Upgrade' } });
    }

    if (url.pathname === '/api/meta') {
      if (request.method === 'GET') {
        const categories = await storage.listCategories();
        const chanList = await storage.listChannels();
        return new Response(JSON.stringify({ id: serverId, name: serverName, adminHandle, categories, channels: chanList, features: { ws: !!notifier } }), 
          { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
      }
      if (request.method === 'POST') {
        const body = await request.json() as any;
        await verifyAdmin(body);
        await storage.setConfig('server_name', body.name);
        return new Response(JSON.stringify({ ok: true }), { headers });
      }
    }

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
      const msg = { id: msgId, did, handle: profile.handle, content, channel_id: channelId || null, created_at: new Date().toISOString() };
      
      await storage.addMessage(msg.id, msg.did, msg.handle, msg.content, msg.channel_id);
      if (notifier) await notifier.broadcast(msg.channel_id, { type: 'new_message', message: msg });
      
      return new Response(JSON.stringify({ ok: true, id: msgId }), { headers });
    }

    if (url.pathname === '/api/edit-message' && request.method === 'POST') {
      const body = await request.json() as any;
      const profile = await verifyIdentity(body);
      const { id, content, did } = body;
      const success = await storage.updateMessage(id, did, content);
      if (!success) throw { status: 403, error: 'Unauthorized or message not found' };
      const msg = await storage.getMessage(id);
      if (notifier && msg) await notifier.broadcast(msg.channel_id, { type: 'edit_message', message: msg });
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

    return new Response('Not Found', { status: 404, headers });

  } catch (err: any) {
    const status = err.status === 401 ? 200 : (err.status || 500);
    const errorBody = err instanceof Error ? { error: err.message, stack: err.stack } : err;
    return new Response(JSON.stringify(errorBody), { 
      status, 
      headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json' } 
    });
  }
}
