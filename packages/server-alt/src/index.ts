import { parse } from 'smol-toml';
import { D1Storage } from '../../shared/storage';
import { handleRequest } from '../../shared/core';
import { NotifierDO, WorkerNotifier } from '../../shared/notifier-do';
// @ts-ignore
import tomlString from './server-config.toml';

const configSeed = parse(tomlString) as { adminHandle: string, defaultName: string };

export interface Env {
  DB: D1Database;
  NOTIFIER: DurableObjectNamespace;
}

// Export DO class for Cloudflare
export { NotifierDO };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const storage = new D1Storage(env.DB);
    const notifier = new WorkerNotifier(env.NOTIFIER);

    // Intercept WebSocket upgrades and send to Durable Object
    if (url.pathname === '/api/ws') {
      const id = env.NOTIFIER.idFromName('global-notifier');
      const stub = env.NOTIFIER.get(id);
      return stub.fetch(request);
    }

    return handleRequest(request, storage, configSeed, notifier);
  }
}
