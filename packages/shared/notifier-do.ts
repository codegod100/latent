import { Notifier } from "./core";
import { Storage } from "./storage";

export class NotifierDO implements DurableObject {
  private storage: Storage | null = null;

  constructor(private state: DurableObjectState, private env: any) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/ws") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("Expected Upgrade: websocket", { status: 426 });
      }
      const channelId = url.searchParams.get("channelId") || "global";
      const [client, server] = new WebSocketPair();
      
      // Accept the socket - it starts as unauthenticated
      this.state.acceptWebSocket(server);
      (server as any)._authenticated = false;
      (server as any)._channelId = channelId;
      
      return new Response(null, { status: 101, webSocket: client });
    }

    if (url.pathname === "/broadcast" && request.method === "POST") {
      try {
        const { channelId, data } = await request.json() as any;
        const topic = channelId || "global";
        
        // Authoritative Broadcast: Only send to sockets that passed the 'auth' check
        const sockets = this.state.getWebSockets();
        let sentCount = 0;
        sockets.forEach(ws => {
          const s = ws as any;
          if (s._authenticated === true && (s._channelId === topic || topic === "global")) {
            try { 
              ws.send(JSON.stringify(data)); 
              sentCount++;
            } catch (e) {}
          }
        });
        
        return new Response(`ok: ${sentCount} recipients`);
      } catch (err) {
        return new Response(String(err), { status: 500 });
      }
    }

    return new Response("Not Found", { status: 404 });
  }

  async webSocketMessage(ws: WebSocket, message: string) {
    try {
      const data = JSON.parse(message);
      if (data.type === 'auth') {
        const token = data.token;
        if (!this.storage) {
          const { D1Storage } = await import("./storage");
          this.storage = new D1Storage(this.env.DB);
        }

        const session = await this.storage.getSession(token);
        // CRITICAL: If no session or user is banned, kill the socket immediately
        if (!session || await this.storage.isBanned(session.did)) {
          console.log(`[NotifierDO] Denied auth for token ${token?.substring(0,5)}... (Banned or Invalid)`);
          ws.send(JSON.stringify({ type: 'error', error: 'Banned' }));
          ws.close(4003, "Banned");
          return;
        }

        // Only after this point can the socket receive broadcasts
        (ws as any)._authenticated = true;
        log(`WebSocket authenticated and unlocked: ${session.handle} (${session.did})`);
      }
    } catch (e) {
      log(`WebSocket message error: ${String(e)}`);
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean) { ws.close(code, reason); }
  async webSocketError(ws: WebSocket, error: any) { ws.close(); }
}

const log = (m: string) => console.log(`[NotifierDO] ${m}`);

export class WorkerNotifier implements Notifier {
  constructor(private doNamespace: DurableObjectNamespace) {}

  async broadcast(channelId: string | null, data: any): Promise<void> {
    const id = this.doNamespace.idFromName("global-notifier");
    const stub = this.doNamespace.get(id);
    await stub.fetch("http://do/broadcast", {
      method: "POST",
      body: JSON.stringify({ channelId, data })
    });
  }
}
