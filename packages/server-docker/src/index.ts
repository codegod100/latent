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

// 3. REAL-TIME NOTIFIER
let bunServer: any;
const notifier: Notifier = {
  async broadcast(channelId, data) {
    if (bunServer) {
      const topic = channelId || 'global';
      bunServer.publish(topic, JSON.stringify(data));
    }
  }
};

// 4. BUN SERVER
bunServer = Bun.serve({
  port: PORT,
  async fetch(request, server) {
    const url = new URL(request.url);
    if (url.pathname === '/api/ws') {
      const channelId = url.searchParams.get('channelId') || 'global';
      if (server.upgrade(request, { data: { channelId } })) return;
    }
    return handleRequest(request, storage, configSeed, notifier);
  },
  websocket: {
    open(ws) {
      const { channelId } = ws.data as any;
      ws.subscribe(channelId);
    },
    message(ws, message) {},
    close(ws) {
      const { channelId } = ws.data as any;
      ws.unsubscribe(channelId);
    }
  }
});

console.log(`Docker server running at http://0.0.0.0:${PORT} (DB: ${dbPath})`);
