import { parse } from 'smol-toml';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Database } from 'bun:sqlite';
import { SQLiteStorage } from '../../shared/storage';
import { handleRequest, Notifier } from '../../shared/core';

// 1. LOAD CONFIG
const configPath = path.resolve('server-config.toml');
const tomlString = fs.readFileSync(configPath, 'utf8');
const configSeed = parse(tomlString) as { adminHandle: string, defaultName: string };

// 2. STORAGE
const IS_PROD = process.env.NODE_ENV === 'production' || !!process.env.FLY_APP_NAME;
const dbDir = IS_PROD ? '/app/data' : path.resolve('.');
const dbPath = path.join(dbDir, 'data.db');

if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(dbPath, { create: true });
const storage = new SQLiteStorage(db);

const PORT = 8789;

// 3. REAL-TIME NOTIFIER (Filtered by Auth)
let connectedSockets = new Set<any>();
const notifier: Notifier = {
  async broadcast(channelId, data) {
    const topic = channelId || 'global';
    const msg = JSON.stringify(data);
    
    // Auth-aware broadcast
    for (const ws of connectedSockets) {
      if (ws.data.authenticated && (ws.data.channelId === topic || topic === 'global')) {
        ws.send(msg);
      }
    }
  }
};

// 4. BUN SERVER
const bunServer = Bun.serve({
  port: PORT,
  async fetch(request, server) {
    const url = new URL(request.url);
    if (url.pathname === '/api/ws') {
      const channelId = url.searchParams.get('channelId') || 'global';
      if (server.upgrade(request, { data: { channelId, authenticated: false } })) return;
    }
    return handleRequest(request, storage, configSeed, notifier);
  },
  websocket: {
    open(ws) {
      connectedSockets.add(ws);
    },
    async message(ws, message) {
      try {
        const data = JSON.parse(String(message));
        if (data.type === 'auth') {
          const session = await storage.getSession(data.token);
          if (!session || await storage.isBanned(session.did)) {
            ws.send(JSON.stringify({ type: 'error', error: 'Banned' }));
            ws.close(4003, "Banned");
            return;
          }
          ws.data.authenticated = true;
          console.log(`[WebSocket] Authenticated: ${session.handle} (${session.did})`);
        }
      } catch (e) {}
    },
    close(ws) {
      connectedSockets.delete(ws);
    }
  }
});

console.log(`Docker server running at http://0.0.0.0:${PORT} (DB: ${dbPath})`);
