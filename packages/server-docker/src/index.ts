import { parse } from 'smol-toml';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Database } from 'bun:sqlite';
import { SQLiteStorage } from './shared/storage';
import { handleRequest } from './shared/core';

// 1. LOAD CONFIG
const configPath = path.resolve('server-config.toml');
const tomlString = fs.readFileSync(configPath, 'utf8');
const configSeed = parse(tomlString) as { adminHandle: string, defaultName: string };

// 2. STORAGE (CRITICAL: Use persistent volume path in production)
const IS_PROD = process.env.NODE_ENV === 'production' || !!process.env.FLY_APP_NAME;
const dbDir = IS_PROD ? '/app/data' : path.resolve('.');
const dbPath = path.join(dbDir, 'data.db');

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new Database(dbPath, { create: true });
const storage = new SQLiteStorage(db);

const PORT = 8789;

// 3. BUN NATIVE SERVER
export default {
  port: PORT,
  async fetch(request: Request) {
    return handleRequest(request, storage, configSeed);
  }
}

console.log(`Docker server running at http://0.0.0.0:${PORT} (DB: ${dbPath})`);
