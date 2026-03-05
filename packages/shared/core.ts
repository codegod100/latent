import { ulid } from 'ulid';
import { Storage } from './storage';

export interface Notifier {
  broadcast(channelId: string | null, message: any): Promise<void>;
}

const identityCache = new Map<string, { profile: any, expires: number }>();
const CACHE_TTL = 5 * 60 * 1000;

// Performance Cache: Avoid redundant DB hits on every request
let isBootstrapped = false;
let cachedConfig: { serverId: string, serverName: string, adminHandle: string } | null = null;

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
    // 0. OPTIMIZED BOOTSTRAP (Once per isolate lifecycle)
    if (!isBootstrapped) {
      await storage.ensureTables();
      let serverId = await storage.getConfig('server_id');
      if (!serverId) { serverId = ulid(); await storage.setConfig('server_id', serverId); }
      let serverName = await storage.getConfig('server_name');
      if (!serverName) { serverName = configSeed.defaultName; await storage.setConfig('server_name', serverName); }
      let adminHandle = await storage.getConfig('admin_handle');
      if (!adminHandle) { adminHandle = configSeed.adminHandle; await storage.setConfig('admin_handle', adminHandle); }
      const channels = await storage.listChannels();
      if (channels.length === 0) await storage.addChannel(ulid(), null, 'general', 'General discussion', 0);
      cachedConfig = { serverId, serverName, adminHandle };
      isBootstrapped = true;
    }

    const { serverId, serverName, adminHandle } = cachedConfig!;

    // 1. HELPERS
    const verifyIdentity = async (body: any) => {
      const authHeader = request.headers.get('Authorization');
      if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        const session = await storage.getSession(token);
        if (session) return { did: session.did, handle: session.handle };
      }
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

    // 2. ROUTING
    if (url.pathname === '/') {
      return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>Latent Backend</title></head><body><h1>${serverName}</h1><p>Status: Active</p></body></html>`, { headers: { ...Object.fromEntries(headers), 'Content-Type': 'text/html' } });
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

    if (url.pathname === '/api/meta' && request.method === 'GET') {
      const [categories, chanList] = await Promise.all([storage.listCategories(), storage.listChannels()]);
      return new Response(JSON.stringify({ id: serverId, name: serverName, adminHandle, categories, channels: chanList, features: { ws: !!notifier } }), { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
    }

    // --- MESSAGES & SEARCH ---
    if (url.pathname === '/api/messages' && request.method === 'GET') {
      const channelId = url.searchParams.get('channelId');
      const beforeId = url.searchParams.get('before');
      const limit = parseInt(url.searchParams.get('limit') || '50');
      const messages = await storage.listMessages(channelId, beforeId, limit);
      if (messages.length === 0) return new Response(JSON.stringify([]), { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json' } });
      const messageIds = messages.map(m => m.id);
      const allReactions = await storage.listReactions(messageIds);
      const parentIds = Array.from(new Set(messages.filter(m => m.parent_id).map(m => m.parent_id)));
      const parents = await Promise.all(parentIds.map(id => storage.getMessage(id!)));
      const messagesDetailed = messages.map(m => ({
        ...m,
        reactions: allReactions.filter(r => r.message_id === m.id),
        parent: m.parent_id ? parents.find(p => p?.id === m.parent_id) : null
      }));
      return new Response(JSON.stringify(messagesDetailed), { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
    }

    if (url.pathname === '/api/search' && request.method === 'GET') {
      const channelId = url.searchParams.get('channelId');
      const query = url.searchParams.get('q');
      if (!query) return new Response(JSON.stringify([]), { headers });
      const results = await storage.searchMessages(channelId, query, 20);
      return new Response(JSON.stringify(results), { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json' } });
    }

    if (url.pathname === '/api/message-context' && request.method === 'GET') {
      const channelId = url.searchParams.get('channelId');
      const targetId = url.searchParams.get('id');
      if (!targetId) return new Response(JSON.stringify([]), { headers });
      // Fetch 50 messages starting from the target message (inclusive) downwards
      // Since our listMessages is "beforeId", we fetch with id <= targetId
      const messages = await storage.listMessages(channelId, targetId + 'z', 50); 
      const messageIds = messages.map(m => m.id);
      const allReactions = await storage.listReactions(messageIds);
      const parentIds = Array.from(new Set(messages.filter(m => m.parent_id).map(m => m.parent_id)));
      const parents = await Promise.all(parentIds.map(id => storage.getMessage(id!)));
      const detailed = messages.map(m => ({
        ...m,
        reactions: allReactions.filter(r => r.message_id === m.id),
        parent: m.parent_id ? parents.find(p => p?.id === m.parent_id) : null
      }));
      return new Response(JSON.stringify(detailed), { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json' } });
    }

    // --- WRITE OPERATIONS ---
    if (request.method === 'POST' || request.method === 'DELETE') {
      const body = await (async () => { try { return await request.json() } catch(e) { return {} } })();
      
      if (url.pathname === '/api/submit-message') {
        const profile = await verifyIdentity(body);
        const { content, channelId, clientId, parentId } = body;
        const msgId = ulid();
        const parent = parentId ? await storage.getMessage(parentId) : null;
        const msg = { id: msgId, did: profile.did, handle: profile.handle, content, channel_id: channelId || null, parent_id: parentId || null, created_at: new Date().toISOString(), clientId, reactions: [], parent };
        await storage.addMessage(msg.id, msg.did, msg.handle, msg.content, msg.channel_id, msg.parent_id);
        if (notifier) await notifier.broadcast(msg.channel_id, { type: 'new_message', message: msg });
        return new Response(JSON.stringify({ ok: true, id: msgId }), { headers });
      }

      if (url.pathname === '/api/edit-message') {
        const profile = await verifyIdentity(body);
        const { id, content } = body;
        const success = await storage.updateMessage(id, profile.did, content);
        if (!success) throw { status: 403, error: 'Unauthorized' };
        const msg = await storage.getMessage(id);
        const allReactions = await storage.listReactions([id]);
        if (notifier) await notifier.broadcast(msg.channel_id, { type: 'edit_message', message: { ...msg, reactions: allReactions } });
        return new Response(JSON.stringify({ ok: true }), { headers });
      }

      if (url.pathname === '/api/react') {
        const profile = await verifyIdentity(body);
        const { messageId, emoji } = body;
        await storage.addReaction(messageId, profile.did, profile.handle, emoji);
        const msg = await storage.getMessage(messageId);
        if (notifier && msg) {
          const reactions = await storage.listReactions([messageId]);
          await notifier.broadcast(msg.channel_id, { type: 'reaction_update', messageId, reactions });
        }
        return new Response(JSON.stringify({ ok: true }), { headers });
      }

      if (url.pathname === '/api/unreact') {
        const profile = await verifyIdentity(body);
        const { messageId, emoji } = body;
        await storage.removeReaction(messageId, profile.did, emoji);
        const msg = await storage.getMessage(messageId);
        if (notifier && msg) {
          const reactions = await storage.listReactions([messageId]);
          await notifier.broadcast(msg.channel_id, { type: 'reaction_update', messageId, reactions });
        }
        return new Response(JSON.stringify({ ok: true }), { headers });
      }

      if (url.pathname === '/api/meta') {
        await verifyAdmin(body); await storage.setConfig('server_name', body.name);
        if (cachedConfig) cachedConfig.serverName = body.name;
        return new Response(JSON.stringify({ ok: true }), { headers });
      }
      if (url.pathname === '/api/categories') {
        await verifyAdmin(body); const id = ulid(); await storage.addCategory(id, body.name, body.sort_order || 0);
        return new Response(JSON.stringify({ ok: true, id }), { headers });
      }
      if (url.pathname.startsWith('/api/categories/') && request.method === 'DELETE') {
        const id = url.pathname.split('/').pop()!; await verifyAdmin(body); await storage.deleteCategory(id);
        return new Response(JSON.stringify({ ok: true }), { headers });
      }
      if (url.pathname === '/api/channels') {
        await verifyAdmin(body); const id = ulid(); await storage.addChannel(id, body.category_id || null, body.name, body.description || '', body.sort_order || 0);
        return new Response(JSON.stringify({ ok: true, id }), { headers });
      }
      if (url.pathname.startsWith('/api/channels/') && request.method === 'DELETE') {
        const id = url.pathname.split('/').pop()!; await verifyAdmin(body); await storage.deleteChannel(id);
        return new Response(JSON.stringify({ ok: true }), { headers });
      }
    }

    return new Response('Not Found', { status: 404, headers });

  } catch (err: any) {
    const status = err.status === 401 ? 200 : (err.status || 500);
    const errorBody = err instanceof Error ? { error: err.message, stack: err.stack } : err;
    return new Response(JSON.stringify(errorBody), { status, headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json' } });
  }
}
