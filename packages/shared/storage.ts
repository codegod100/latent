export interface Storage {
  ensureTables(): Promise<void>;
  getConfig(key: string): Promise<string | null>;
  setConfig(key: string, value: string): Promise<void>;
  listCategories(): Promise<any[]>;
  addCategory(id: string, name: string, sortOrder: number): Promise<void>;
  deleteCategory(id: string): Promise<void>;
  listChannels(): Promise<any[]>;
  addChannel(id: string, catId: string | null, name: string, desc: string, sortOrder: number): Promise<void>;
  deleteChannel(id: string): Promise<void>;
  listMessages(channelId: string | null, beforeId?: string | null, limit?: number): Promise<any[]>;
  addMessage(id: string, did: string, handle: string, content: string, channelId: string | null, parentId?: string | null): Promise<void>;
  updateMessage(id: string, did: string, content: string): Promise<boolean>;
  getMessage(id: string): Promise<any | null>;
  addReaction(messageId: string, did: string, handle: string, emoji: string): Promise<void>;
  removeReaction(messageId: string, did: string, emoji: string): Promise<void>;
  listReactions(messageIds: string[]): Promise<any[]>;
  searchMessages(channelId: string | null, query: string, limit?: number): Promise<any[]>;
  
  // Moderation
  addBan(did: string, handle: string | null, reason: string): Promise<void>;
  removeBan(did: string): Promise<void>;
  listBans(): Promise<any[]>;
  isBanned(did: string): Promise<boolean>;

  // Moderators
  addModerator(did: string, handle: string): Promise<void>;
  removeModerator(did: string): Promise<void>;
  listModerators(): Promise<any[]>;
  isModerator(did: string): Promise<boolean>;

  // Invites & Membership
  createInvite(code: string): Promise<void>;
  useInvite(code: string, did: string): Promise<boolean>;
  isMember(did: string): Promise<boolean>;
  addMember(did: string): Promise<void>;

  // Session Management
  createSession(token: string, did: string, handle: string, expiresAt: string): Promise<void>;
  getSession(token: string): Promise<any | null>;
}

const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)`,
  `CREATE TABLE IF NOT EXISTS categories (id TEXT PRIMARY KEY, name TEXT NOT NULL, sort_order INTEGER DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS channels (id TEXT PRIMARY KEY, category_id TEXT, name TEXT NOT NULL, description TEXT, sort_order INTEGER DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, did TEXT NOT NULL, handle TEXT NOT NULL, content TEXT NOT NULL, channel_id TEXT, parent_id TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE TABLE IF NOT EXISTS reactions (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT NOT NULL, did TEXT NOT NULL, handle TEXT NOT NULL, emoji TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(message_id, did, emoji))`,
  `CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, did TEXT NOT NULL, handle TEXT NOT NULL, expires_at DATETIME NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS bans (did TEXT PRIMARY KEY, handle TEXT, reason TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE TABLE IF NOT EXISTS members (did TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE TABLE IF NOT EXISTS invites (code TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE TABLE IF NOT EXISTS moderators (did TEXT PRIMARY KEY, handle TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE INDEX IF NOT EXISTS idx_messages_channel_id ON messages(channel_id)`,
  `CREATE INDEX IF NOT EXISTS idx_messages_id_desc ON messages(id DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_reactions_message_id ON reactions(message_id)`
];

// Implementation for Cloudflare D1
export class D1Storage implements Storage {
  constructor(private db: D1Database) {}
  
  async ensureTables() {
    for (const stmt of SCHEMA_STATEMENTS) { await this.db.prepare(stmt).run(); }
    try { await this.db.prepare('ALTER TABLE messages ADD COLUMN channel_id TEXT').run(); } catch (e) {} 
    try { await this.db.prepare('ALTER TABLE messages ADD COLUMN parent_id TEXT').run(); } catch (e) {}
  }

  async getConfig(key: string) { return (await this.db.prepare('SELECT value FROM config WHERE key = ?').bind(key).first() as any)?.value || null; }
  async setConfig(key: string, value: string) { await this.db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').bind(key, value).run(); }
  async listCategories() { return (await this.db.prepare('SELECT * FROM categories ORDER BY sort_order ASC').all()).results; }
  async addCategory(id: string, name: string, sortOrder: number) { await this.db.prepare('INSERT INTO categories (id, name, sort_order) VALUES (?, ?, ?)').bind(id, name, sortOrder).run(); }
  async deleteCategory(id: string) { 
    await this.db.prepare('DELETE FROM categories WHERE id = ?').bind(id).run(); 
    await this.db.prepare('UPDATE channels SET category_id = NULL WHERE category_id = ?').bind(id).run(); 
  }
  async listChannels() { return (await this.db.prepare('SELECT * FROM channels ORDER BY sort_order ASC').all()).results; }
  async addChannel(id: string, catId: string | null, name: string, desc: string, sortOrder: number) { 
    await this.db.prepare('INSERT INTO channels (id, category_id, name, description, sort_order) VALUES (?, ?, ?, ?, ?)').bind(id, catId, name, desc, sortOrder).run(); 
  }
  async deleteChannel(id: string) { await this.db.prepare('DELETE FROM channels WHERE id = ?').bind(id).run(); }
  
  async listMessages(channelId: string | null, beforeId: string | null = null, limit: number = 50) {
    let query = 'SELECT * FROM messages WHERE (channel_id = ? OR (channel_id IS NULL AND ? IS NULL))';
    const params: any[] = [channelId, channelId];
    if (beforeId) { query += ' AND id < ?'; params.push(beforeId); }
    query += ' ORDER BY id DESC LIMIT ?';
    params.push(limit);
    return (await this.db.prepare(query).bind(...params).all()).results;
  }

  async searchMessages(channelId: string | null, query: string, limit: number = 20) {
    let sql = 'SELECT * FROM messages WHERE ';
    const params: any[] = [];
    if (channelId) { sql += 'channel_id = ? AND '; params.push(channelId); }
    sql += 'content LIKE ? ORDER BY id DESC LIMIT ?';
    params.push(`%${query}%`, limit);
    const res = await this.db.prepare(sql).bind(...params).all();
    return res.results;
  }

  async addMessage(id: string, did: string, handle: string, content: string, channelId: string | null, parent_id: string | null = null) {
    await this.db.prepare('INSERT INTO messages (id, did, handle, content, channel_id, parent_id) VALUES (?, ?, ?, ?, ?, ?)').bind(id, did, handle, content, channelId, parent_id).run();
  }
  async getMessage(id: string) { return await this.db.prepare('SELECT * FROM messages WHERE id = ?').bind(id).first(); }
  async updateMessage(id: string, did: string, content: string) {
    const res = await this.db.prepare('UPDATE messages SET content = ? WHERE id = ? AND did = ?').bind(content, id, did).run();
    return res.meta.changes > 0;
  }
  async addReaction(messageId: string, did: string, handle: string, emoji: string) {
    await this.db.prepare('INSERT OR IGNORE INTO reactions (message_id, did, handle, emoji) VALUES (?, ?, ?, ?)').bind(messageId, did, handle, emoji).run();
  }
  async removeReaction(messageId: string, did: string, emoji: string) {
    await this.db.prepare('DELETE FROM reactions WHERE message_id = ? AND did = ? AND emoji = ?').bind(messageId, did, emoji).run();
  }
  async listReactions(messageIds: string[]) {
    if (messageIds.length === 0) return [];
    const placeholders = messageIds.map(() => '?').join(',');
    return (await this.db.prepare(`SELECT * FROM reactions WHERE message_id IN (${placeholders})`).bind(...messageIds).all()).results;
  }

  async addBan(did: string, handle: string | null, reason: string) { await this.db.prepare('INSERT OR REPLACE INTO bans (did, handle, reason) VALUES (?, ?, ?)').bind(did, handle || '', reason).run(); }
  async removeBan(did: string) { await this.db.prepare('DELETE FROM bans WHERE did = ?').bind(did).run(); }
  async listBans() { return (await this.db.prepare('SELECT * FROM bans ORDER BY created_at DESC').all()).results; }
  async isBanned(did: string) { return !!(await this.db.prepare('SELECT did FROM bans WHERE did = ?').bind(did).first()); }

  async addModerator(did: string, handle: string) { await this.db.prepare('INSERT OR REPLACE INTO moderators (did, handle) VALUES (?, ?)').bind(did, handle).run(); }
  async removeModerator(did: string) { await this.db.prepare('DELETE FROM moderators WHERE did = ?').bind(did).run(); }
  async listModerators() { return (await this.db.prepare('SELECT * FROM moderators ORDER BY created_at DESC').all()).results; }
  async isModerator(did: string) { return !!(await this.db.prepare('SELECT did FROM moderators WHERE did = ?').bind(did).first()); }

  async createInvite(code: string) { await this.db.prepare('INSERT INTO invites (code) VALUES (?)').bind(code).run(); }
  async useInvite(code: string, did: string) {
    const invite = await this.db.prepare('SELECT code FROM invites WHERE code = ?').bind(code).first();
    if (!invite) return false;
    await this.db.batch([
      this.db.prepare('DELETE FROM invites WHERE code = ?').bind(code),
      this.db.prepare('INSERT OR IGNORE INTO members (did) VALUES (?)').bind(did)
    ]);
    return true;
  }
  async isMember(did: string) { return !!(await this.db.prepare('SELECT did FROM members WHERE did = ?').bind(did).first()); }
  async addMember(did: string) { await this.db.prepare('INSERT OR IGNORE INTO members (did) VALUES (?)').bind(did).run(); }

  async createSession(token: string, did: string, handle: string, expiresAt: string) {
    await this.db.prepare('INSERT INTO sessions (token, did, handle, expires_at) VALUES (?, ?, ?, ?)').bind(token, did, handle, expiresAt).run();
  }
  async getSession(token: string) {
    return await this.db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > DATETIME("now")').bind(token).first();
  }
}

// Implementation for SQLite (Bun)
export class SQLiteStorage implements Storage {
  constructor(private db: any) {}
  async ensureTables() {
    for (const stmt of SCHEMA_STATEMENTS) { this.db.exec(stmt); }
    try { this.db.prepare('ALTER TABLE messages ADD COLUMN channel_id TEXT').run(); } catch (e) {}
    try { this.db.prepare('ALTER TABLE messages ADD COLUMN parent_id TEXT').run(); } catch (e) {}
  }
  async getConfig(key: string) { return this.db.prepare('SELECT value FROM config WHERE key = ?').get(key)?.value || null; }
  async setConfig(key: string, value: string) { this.db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(key, value); }
  async listCategories() { return this.db.prepare('SELECT * FROM categories ORDER BY sort_order ASC').all(); }
  async addCategory(id: string, name: string, sortOrder: number) { this.db.prepare('INSERT INTO categories (id, name, sort_order) VALUES (?, ?, ?)').run(id, name, sortOrder); }
  async deleteCategory(id: string) { 
    this.db.prepare('DELETE FROM categories WHERE id = ?').run(id); 
    this.db.prepare('UPDATE channels SET category_id = NULL WHERE category_id = ?').run(id); 
  }
  async listChannels() { return this.db.prepare('SELECT * FROM channels ORDER BY sort_order ASC').all(); }
  async addChannel(id: string, catId: string | null, name: string, desc: string, sortOrder: number) { 
    this.db.prepare('INSERT INTO channels (id, category_id, name, description, sort_order) VALUES (?, ?, ?, ?, ?)').run(id, catId, name, desc, sortOrder); 
  }
  async deleteChannel(id: string) { this.db.prepare('DELETE FROM channels WHERE id = ?').run(id); }
  
  async listMessages(channelId: string | null, beforeId: string | null = null, limit: number = 50) {
    let query = 'SELECT * FROM messages WHERE ';
    const params: any[] = [];
    if (channelId) { query += 'channel_id = ?'; params.push(channelId); } else { query += 'channel_id IS NULL'; }
    if (beforeId) { query += ' AND id < ?'; params.push(beforeId); }
    query += ' ORDER BY id DESC LIMIT ?';
    params.push(limit);
    return this.db.prepare(query).all(...params);
  }

  async searchMessages(channelId: string | null, query: string, limit: number = 20) {
    let sql = 'SELECT * FROM messages WHERE ';
    const params: any[] = [];
    if (channelId) { sql += 'channel_id = ? AND '; params.push(channelId); }
    sql += 'content LIKE ? ORDER BY id DESC LIMIT ?';
    params.push(`%${query}%`, limit);
    return this.db.prepare(sql).all(...params);
  }

  async addMessage(id: string, did: string, handle: string, content: string, channel_id: string | null, parent_id: string | null = null) {
    this.db.prepare('INSERT INTO messages (id, did, handle, content, channel_id, parent_id) VALUES (?, ?, ?, ?, ?, ?)').run(id, did, handle, content, channel_id, parent_id);
  }
  async getMessage(id: string) { return this.db.prepare('SELECT * FROM messages WHERE id = ?').get(id); }
  async updateMessage(id: string, did: string, content: string) {
    const res = this.db.prepare('UPDATE messages SET content = ? WHERE id = ? AND did = ?').run(content, id, did);
    return res.changes > 0;
  }
  async addReaction(messageId: string, did: string, handle: string, emoji: string) {
    this.db.prepare('INSERT OR IGNORE INTO reactions (message_id, did, handle, emoji) VALUES (?, ?, ?, ?)').run(messageId, did, handle, emoji);
  }
  async removeReaction(messageId: string, did: string, emoji: string) {
    this.db.prepare('DELETE FROM reactions WHERE message_id = ? AND did = ? AND emoji = ?').run(messageId, did, emoji);
  }
  async listReactions(messageIds: string[]) {
    if (messageIds.length === 0) return [];
    const placeholders = messageIds.map(() => '?').join(',');
    return this.db.prepare(`SELECT * FROM reactions WHERE message_id IN (${placeholders})`).all(...messageIds);
  }

  async addBan(did: string, handle: string | null, reason: string) { this.db.prepare('INSERT OR REPLACE INTO bans (did, handle, reason) VALUES (?, ?, ?)').run(did, handle || '', reason); }
  async removeBan(did: string) { this.db.prepare('DELETE FROM bans WHERE did = ?').run(did); }
  async listBans() { return this.db.prepare('SELECT * FROM bans ORDER BY created_at DESC').all(); }
  async isBanned(did: string) { return !!this.db.prepare('SELECT did FROM bans WHERE did = ?').get(did); }

  async addModerator(did: string, handle: string) { this.db.prepare('INSERT OR REPLACE INTO moderators (did, handle) VALUES (?, ?)').run(did, handle); }
  async removeModerator(did: string) { this.db.prepare('DELETE FROM moderators WHERE did = ?').run(did); }
  async listModerators() { return this.db.prepare('SELECT * FROM moderators ORDER BY created_at DESC').all(); }
  async isModerator(did: string) { return !!this.db.prepare('SELECT did FROM moderators WHERE did = ?').get(did); }

  async createInvite(code: string) { this.db.prepare('INSERT INTO invites (code) VALUES (?)').run(code); }
  async useInvite(code: string, did: string) {
    const invite = this.db.prepare('SELECT code FROM invites WHERE code = ?').get(code);
    if (!invite) return false;
    this.db.transaction(() => {
      this.db.prepare('DELETE FROM invites WHERE code = ?').run(code);
      this.db.prepare('INSERT OR IGNORE INTO members (did) VALUES (?)').run(did);
    })();
    return true;
  }
  async isMember(did: string) { return !!this.db.prepare('SELECT did FROM members WHERE did = ?').get(did); }
  async addMember(did: string) { this.db.prepare('INSERT OR IGNORE INTO members (did) VALUES (?)').run(did); }

  async createSession(token: string, did: string, handle: string, expiresAt: string) {
    this.db.prepare('INSERT INTO sessions (token, did, handle, expires_at) VALUES (?, ?, ?, ?)').run(token, did, handle, expiresAt);
  }
  async getSession(token: string) {
    return this.db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > DATETIME("now")').get(token);
  }
}
