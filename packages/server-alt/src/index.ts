export interface Env {
  DB: D1Database;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    
    // CORS Headers
    const headers = new Headers({
      'Access-Control-Allow-Origin': '*', // In production, restrict to your frontend origin
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, DPoP',
    });

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers });
    }

    // 1. GET MESSAGES
    if (url.pathname === '/api/messages' && request.method === 'GET') {
      const { results } = await env.DB.prepare(
        'SELECT * FROM messages ORDER BY created_at DESC LIMIT 50'
      ).all();
      return new Response(JSON.stringify(results), { headers: { ...Object.fromEntries(headers), 'Content-Type': 'application/json' } });
    }

    // 2. SUBMIT MESSAGE (Verified)
    if (url.pathname === '/api/submit-message' && request.method === 'POST') {
      const { accessToken, dpopProof, pdsUrl, did, content } = await request.json() as any;

      if (!content) return new Response(JSON.stringify({ error: 'Missing content' }), { status: 400, headers });

      try {
        // A. Verify with PDS
        const probeUrl = `${String(pdsUrl).replace(/\/+$/, '')}/xrpc/app.bsky.actor.getProfile?actor=${did}`;
        const pdsRes = await fetch(probeUrl, {
          headers: { 'Authorization': `DPoP ${accessToken}`, 'DPoP': dpopProof }
        });

        const dpopNonce = pdsRes.headers.get('dpop-nonce');
        if (!pdsRes.ok) {
          const errorData = await pdsRes.json() as any;
          // If it's a nonce challenge, return 200 so the browser console stays clean
          if (pdsRes.status === 401 && dpopNonce) {
            return new Response(JSON.stringify({ verified: false, dpopNonce, isChallenge: true }), { status: 200, headers });
          }
          return new Response(JSON.stringify({ verified: false, error: 'PDS verification failed', pdsResponse: errorData }), { status: pdsRes.status, headers });
        }

        const profile = await pdsRes.json() as any;
        const handle = profile.handle || 'unknown';

        // B. Store in D1
        await env.DB.prepare(
          'INSERT INTO messages (did, handle, content) VALUES (?, ?, ?)'
        ).bind(did, handle, content).run();

        return new Response(JSON.stringify({ ok: true, handle, content }), { headers });
      } catch (err) {
        return new Response(JSON.stringify({ error: String(err) }), { status: 500, headers });
      }
    }

    return new Response('Not Found', { status: 404, headers });
  }
}
