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
  listMessages(channelId: string | null): Promise<any[]>;
  addMessage(id: string, did: string, handle: string, content: string, channelId: string | null, parentId?: string | null): Promise<void>;
  updateMessage(id: string, did: string, content: string): Promise<boolean>;
  getMessage(id: string): Promise<any | null>;
  addReaction(messageId: string, did: string, handle: string, emoji: string): Promise<void>;
  removeReaction(messageId: string, did: string, emoji: string): Promise<void>;
  listReactions(messageIds: string[]): Promise<any[]>;
}

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT);
  CREATE TABLE IF NOT EXISTS categories (id TEXT PRIMARY KEY, name TEXT NOT NULL, sort_order INTEGER DEFAULT 0);
  CREATE TABLE IF NOT EXISTS channels (id TEXT PRIMARY KEY, category_id TEXT, name TEXT NOT NULL, description TEXT, sort_order INTEGER DEFAULT 0);
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY, 
    did TEXT NOT NULL, 
    handle TEXT NOT NULL, 
    content TEXT NOT NULL, 
    channel_id TEXT, 
    parent_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL,
    did TEXT NOT NULL,
    handle TEXT NOT NULL,
    emoji TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(message_id, did, emoji)
  );
`;

// Implementation for Cloudflare D1
export class D1Storage implements Storage {
  constructor(private db: D1Database) {}
  
  async ensureTables() {
    await this.db.exec(SCHEMA);
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
  
  async listMessages(channelId: string | null) {
    return (await this.db.prepare('SELECT * FROM messages WHERE channel_id = ? OR (channel_id IS NULL AND ? IS NULL) ORDER BY id DESC LIMIT 50').bind(channelId, channelId).all()).results;
  }
  
  async addMessage(id: string, did: string, handle: string, content: string, channelId: string | null, parentId: string | null = null) {
    await this.db.prepare('INSERT INTO messages (id, did, handle, content, channel_id, parent_id) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id, did, handle, content, channelId, parentId).run();
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
}

// Implementation for SQLite (Bun)
export class SQLiteStorage implements Storage {
  constructor(private db: any) {}
  async ensureTables() {
    this.db.exec(SCHEMA);
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
  
  async listMessages(channelId: string | null) {
    if (channelId) return this.db.prepare('SELECT * FROM messages WHERE channel_id = ? ORDER BY id DESC LIMIT 50').all(channelId);
    return this.db.prepare('SELECT * FROM messages WHERE channel_id IS NULL ORDER BY id DESC LIMIT 50').all();
  }
  
  async addMessage(id: string, did: string, handle: string, content: string, channelId: string | null, parentId: string | null = null) {
    this.db.prepare('INSERT INTO messages (id, did, handle, content, channel_id, parent_id) VALUES (?, ?, ?, ?, ?, ?)').run(id, did, handle, content, channelId, parentId);
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
}
