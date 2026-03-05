import { ulid } from 'ulid';
import { parse } from 'smol-toml';
// @ts-ignore
import tomlString from './server-config.toml';

const configSeed = parse(tomlString) as { adminHandle: string, defaultName: string };

export interface Env {
  DB: D1Database;
}

async function getOrSeedConfig(db: D1Database, key: string, defaultValue: string): Promise<string> {
  const row = await db.prepare('SELECT value FROM config WHERE key = ?').bind(key).first() as { value: string } | null;
  if (row) return row.value;
  await db.prepare('INSERT INTO config (key, value) VALUES (?, ?)').bind(key, defaultValue).run();
  return defaultValue;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const headers = new Headers({
      'Access-Control-Allow-Origin': '*', 
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, DPoP',
    });

    if (request.method === 'OPTIONS') return new Response(null, { headers });

    const serverName = await getOrSeedConfig(env.DB, 'server_name', configSeed.defaultName);
    const adminHandle = await getOrSeedConfig(env.DB, 'admin_handle', configSeed.adminHandle);

    const verifyAdmin = async (body: any) => {
      const { accessToken, dpopProof, pdsUrl, did } = body;
      const probeUrl = `${String(pdsUrl).replace(/\/+$/, '')}/xrpc/app.bsky.actor.getProfile?actor=${did}`;
      const pdsRes = await fetch(probeUrl, { headers: { 'Authorization': `DPoP ${accessToken}`, 'DPoP': dpopProof } });
      const dpopNonce = pdsRes.headers.get('dpop-nonce');
      if (!pdsRes.ok) throw { status: pdsRes.status, dpopNonce, error: 'Verification failed' };
      const profile = await pdsRes.json() as any;
      if (profile.handle !== adminHandle) throw { status: 403, error: 'Admin only' };
      return profile;
    };

    try {
      // 0. SERVER META (Includes Channels/Categories)
      if (url.pathname === '/api/meta') {
        if (request.method === 'GET') {
          const categories = await env.DB.prepare('SELECT * FROM categories ORDER BY sort_order ASC').all();
          const channels = await env.DB.prepare('SELECT * FROM channels ORDER BY sort_order ASC').all();
          return new Response(JSON.stringify({
            name: serverName,
            adminHandle,
            categories: categories.results,
            channels: channels.results
          }), { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json' } });
        }
        if (request.method === 'POST') {
          const body = await request.json() as any;
          await verifyAdmin(body);
          await env.DB.prepare('UPDATE config SET value = ? WHERE key = ?').bind(body.name, 'server_name').run();
          return new Response(JSON.stringify({ ok: true }), { headers });
        }
      }

      // 1. CATEGORIES
      if (url.pathname === '/api/categories' && request.method === 'POST') {
        const body = await request.json() as any;
        await verifyAdmin(body);
        const id = ulid();
        await env.DB.prepare('INSERT INTO categories (id, name, sort_order) VALUES (?, ?, ?)')
          .bind(id, body.name, body.sort_order || 0).run();
        return new Response(JSON.stringify({ ok: true, id }), { headers });
      }
      if (url.pathname.startsWith('/api/categories/') && request.method === 'DELETE') {
        const id = url.pathname.split('/').pop();
        const body = await request.json() as any;
        await verifyAdmin(body);
        await env.DB.prepare('DELETE FROM categories WHERE id = ?').bind(id).run();
        await env.DB.prepare('UPDATE channels SET category_id = NULL WHERE category_id = ?').bind(id).run();
        return new Response(JSON.stringify({ ok: true }), { headers });
      }

      // 2. CHANNELS
      if (url.pathname === '/api/channels' && request.method === 'POST') {
        const body = await request.json() as any;
        await verifyAdmin(body);
        const id = ulid();
        await env.DB.prepare('INSERT INTO channels (id, category_id, name, description, sort_order) VALUES (?, ?, ?, ?, ?)')
          .bind(id, body.category_id || null, body.name, body.description || '', body.sort_order || 0).run();
        return new Response(JSON.stringify({ ok: true, id }), { headers });
      }
      if (url.pathname.startsWith('/api/channels/') && request.method === 'DELETE') {
        const id = url.pathname.split('/').pop();
        const body = await request.json() as any;
        await verifyAdmin(body);
        await env.DB.prepare('DELETE FROM channels WHERE id = ?').bind(id).run();
        return new Response(JSON.stringify({ ok: true }), { headers });
      }

      // 3. MESSAGES (Channel-specific)
      if (url.pathname === '/api/messages' && request.method === 'GET') {
        const channelId = url.searchParams.get('channelId');
        const { results } = await env.DB.prepare(
          'SELECT * FROM messages WHERE channel_id = ? OR (channel_id IS NULL AND ? IS NULL) ORDER BY id DESC LIMIT 50'
        ).bind(channelId, channelId).all();
        return new Response(JSON.stringify(results), { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json' } });
      }

      if (url.pathname === '/api/submit-message' && request.method === 'POST') {
        const body = await request.json() as any;
        const { accessToken, dpopProof, pdsUrl, did, content, channelId } = body;
        
        const probeUrl = `${String(pdsUrl).replace(/\/+$/, '')}/xrpc/app.bsky.actor.getProfile?actor=${did}`;
        const pdsRes = await fetch(probeUrl, { headers: { 'Authorization': `DPoP ${accessToken}`, 'DPoP': dpopProof } });
        const dpopNonce = pdsRes.headers.get('dpop-nonce');
        
        if (!pdsRes.ok) {
          if (pdsRes.status === 401 && dpopNonce) return new Response(JSON.stringify({ isChallenge: true, dpopNonce }), { status: 200, headers });
          return new Response(JSON.stringify({ error: 'Verification failed' }), { status: pdsRes.status, headers });
        }

        const profile = await pdsRes.json() as any;
        const msgId = ulid();
        await env.DB.prepare('INSERT INTO messages (id, did, handle, content, channel_id) VALUES (?, ?, ?, ?, ?)')
          .bind(msgId, did, profile.handle, content, channelId || null).run();

        return new Response(JSON.stringify({ ok: true, id: msgId }), { headers });
      }

    } catch (err: any) {
      if (err.status) return new Response(JSON.stringify(err), { status: err.status === 401 ? 200 : err.status, headers });
      return new Response(JSON.stringify({ error: String(err) }), { status: 500, headers });
    }

    return new Response('Not Found', { status: 404, headers });
  }
}
