import { parse } from 'smol-toml';
import { D1Storage } from '../../shared/storage';
import { handleRequest } from '../../shared/core';
// @ts-ignore
import tomlString from './server-config.toml';

const configSeed = parse(tomlString) as { adminHandle: string, defaultName: string };

export interface Env {
  DB: D1Database;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const storage = new D1Storage(env.DB);
    return handleRequest(request, storage, configSeed);
  }
}
