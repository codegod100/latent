import { ulid } from 'ulid';
import { Storage } from './storage';

export interface Notifier {
  broadcast(channelId: string | null, message: any): Promise<void>;
}

const identityCache = new Map<string, { profile: any, expires: number }>();
const CACHE_TTL = 5 * 60 * 1000;

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
    // 0. BOOTSTRAP
    await storage.ensureTables();

    // 1. SYNC CONFIG
    let serverId = await storage.getConfig('server_id');
    if (!serverId) { serverId = ulid(); await storage.setConfig('server_id', serverId); }
    
    // Always sync name and admin handle from seed to allow easy configuration updates
    await storage.setConfig('server_name', configSeed.defaultName);
    const serverName = configSeed.defaultName;
    
    await storage.setConfig('admin_handle', configSeed.adminHandle);
    const adminHandle = configSeed.adminHandle;

    // 2. ENSURE DEFAULT CHANNEL
    const channels = await storage.listChannels();
    if (channels.length === 0) {
      await storage.addChannel(ulid(), null, 'general', 'General discussion', 0);
    }

    // 3. HELPERS
    const verifyIdentity = async (body: any) => {
      // Check for Session Token first (Bearer)
      const authHeader = request.headers.get('Authorization');
      if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        const session = await storage.getSession(token);
        if (session) {
          return { did: session.did, handle: session.handle };
        }
      }

      // Fallback to ATProto verification
      const { accessToken, dpopProof, pdsUrl, did } = body;
      const cacheKey = `${did}:${accessToken}`;
      const cached = identityCache.get(cacheKey);
      if (cached && cached.expires > Date.now()) return cached.profile;

      const probeUrl = `${String(pdsUrl).replace(/\/+$/, '')}/xrpc/app.bsky.actor.getProfile?actor=${did}`;
      const pdsRes = await fetch(probeUrl, { headers: { 'Authorization': `DPoP ${accessToken}`, 'DPoP': dpopProof } });
      const dpopNonce = pdsRes.headers.get('dpop-nonce');
      if (!pdsRes.ok) throw { status: pdsRes.status, isChallenge: pdsRes.status === 401 && !!dpopNonce, dpopNonce, error: 'Identity verification failed' };
      const profile = await pdsRes.json() as any;
      const result = { did: profile.did || did, handle: profile.handle };
      identityCache.set(cacheKey, { profile: result, expires: Date.now() + CACHE_TTL });
      return result;
    };

    const verifyAdmin = async (body: any) => {
      const profile = await verifyIdentity(body);
      if (profile.handle !== adminHandle) throw { status: 403, error: 'Admin only' };
      return profile;
    };

    // 4. ROUTING
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
          </style>
        </head>
        <body>
          <h1>ATProto Verified Backend: ${serverName}</h1>
          <div class="info-box">
            <strong>Server ID:</strong> <code>${serverId}</code><br>
            <strong>Admin:</strong> <code>@${adminHandle}</code>
          </div>
          <p>Status: <strong>Active</strong></p>
        </body>
        </html>
      `, { headers: { ...Object.fromEntries(headers), 'Content-Type': 'text/html' } });
    }

    if (url.pathname === '/api/ws') {
      if (request.headers.get('Upgrade') !== 'websocket') return new Response('Expected WebSocket upgrade', { status: 400 });
      if (!notifier) return new Response('WebSockets not supported', { status: 501 });
      return new Response(null, { status: 101, headers: { 'Upgrade': 'websocket', 'Connection': 'Upgrade' } });
    }

    if (url.pathname === '/api/auth' && request.method === 'POST') {
      const body = await request.json() as any;
      const profile = await verifyIdentity(body);
      const token = ulid();
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      await storage.createSession(token, profile.did, profile.handle, expiresAt);
      return new Response(JSON.stringify({ token, expiresAt }), { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json' } });
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
        await verifyAdmin(body); await storage.setConfig('server_name', body.name);
        return new Response(JSON.stringify({ ok: true }), { headers });
      }
    }

    if (url.pathname === '/api/categories' && request.method === 'POST') {
      const body = await request.json() as any;
      await verifyAdmin(body); const id = ulid(); await storage.addCategory(id, body.name, body.sort_order || 0);
      return new Response(JSON.stringify({ ok: true, id }), { headers });
    }
    if (url.pathname.startsWith('/api/categories/') && request.method === 'DELETE') {
      const id = url.pathname.split('/').pop()!;
      const body = await request.json() as any;
      await verifyAdmin(body); await storage.deleteCategory(id);
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

    if (url.pathname === '/api/channels' && request.method === 'POST') {
      const body = await request.json() as any;
      await verifyAdmin(body); const id = ulid(); await storage.addChannel(id, body.category_id || null, body.name, body.description || '', body.sort_order || 0);
      return new Response(JSON.stringify({ ok: true, id }), { headers });
    }
    if (url.pathname.startsWith('/api/channels/') && request.method === 'DELETE') {
      const id = url.pathname.split('/').pop()!;
      const body = await request.json() as any;
      await verifyAdmin(body); await storage.deleteChannel(id);
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

    // --- MESSAGES ---
    if (url.pathname === '/api/messages' && request.method === 'GET') {
      const channelId = url.searchParams.get('channelId');
      const beforeId = url.searchParams.get('before');
      const limit = parseInt(url.searchParams.get('limit') || '50');
      
      const messages = await storage.listMessages(channelId, beforeId, limit);
      const messageIds = messages.map(m => m.id);
      const allReactions = await storage.listReactions(messageIds);
      
      const parentIds = Array.from(new Set(messages.filter(m => m.parent_id).map(m => m.parent_id)));
      const parents = await Promise.all(parentIds.map(id => storage.getMessage(id)));
      
      const messagesDetailed = messages.map(m => ({
        ...m,
        reactions: allReactions.filter(r => r.message_id === m.id),
        parent: m.parent_id ? parents.find(p => p?.id === m.parent_id) : null
      }));
      
      return new Response(JSON.stringify(messagesDetailed), { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
    }

    if (url.pathname === '/api/submit-message' && request.method === 'POST') {
      const body = await request.json() as any;
      const profile = await verifyIdentity(body);
      const { content, channelId, clientId, parentId } = body;
      const msgId = ulid();
      const parent = parentId ? await storage.getMessage(parentId) : null;
      const msg = { id: msgId, did: profile.did, handle: profile.handle, content, channel_id: channelId || null, parent_id: parentId || null, created_at: new Date().toISOString(), clientId, reactions: [], parent };
      await storage.addMessage(msg.id, msg.did, msg.handle, msg.content, msg.channel_id, msg.parent_id);
      if (notifier) await notifier.broadcast(msg.channel_id, { type: 'new_message', message: msg });
      return new Response(JSON.stringify({ ok: true, id: msgId }), { headers });
    }

    if (url.pathname === '/api/edit-message' && request.method === 'POST') {
      const body = await request.json() as any;
      const profile = await verifyIdentity(body);
      const { id, content } = body;
      const success = await storage.updateMessage(id, profile.did, content);
      if (!success) throw { status: 403, error: 'Unauthorized' };
      const msg = await storage.getMessage(id);
      const allReactions = await storage.listReactions([id]);
      if (notifier) await notifier.broadcast(msg.channel_id, { type: 'edit_message', message: { ...msg, reactions: allReactions } });
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

    if (url.pathname === '/api/react' && request.method === 'POST') {
      const body = await request.json() as any;
      const profile = await verifyIdentity(body);
      const { messageId, emoji } = body;
      await storage.addReaction(messageId, profile.did, profile.handle, emoji);
      const msg = await storage.getMessage(messageId);
      if (notifier && msg) {
        const reactions = await storage.listReactions([messageId]);
        notifier.broadcast(msg.channel_id, { type: 'reaction_update', messageId, reactions });
      }
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

    if (url.pathname === '/api/unreact' && request.method === 'POST') {
      const body = await request.json() as any;
      const profile = await verifyIdentity(body);
      const { messageId, emoji } = body;
      await storage.removeReaction(messageId, profile.did, emoji);
      const msg = await storage.getMessage(messageId);
      if (notifier && msg) {
        const reactions = await storage.listReactions([messageId]);
        notifier.broadcast(msg.channel_id, { type: 'reaction_update', messageId, reactions });
      }
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

    return new Response('Not Found', { status: 404, headers });

  } catch (err: any) {
    const status = err.status === 401 ? 200 : (err.status || 500);
    const errorBody = err instanceof Error ? { error: err.message, stack: err.stack } : err;
    return new Response(JSON.stringify(errorBody), { status, headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json' } });
  }
}
