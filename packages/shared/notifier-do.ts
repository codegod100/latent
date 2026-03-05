import { Notifier } from "./core";

export class NotifierDO implements DurableObject {
  private sessions = new Set<WebSocket>();

  constructor(private state: DurableObjectState) {
    // Resume any existing hibernated connections
    this.sessions = new Set(this.state.getWebSockets());
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/ws") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("Expected Upgrade: websocket", { status: 426 });
      }

      const channelId = url.searchParams.get("channelId") || "global";
      const [client, server] = new WebSocketPair();

      // Set up the server-side socket
      this.state.acceptWebSocket(server, [channelId]);
      
      return new Response(null, { status: 101, webSocket: client });
    }

    if (url.pathname === "/broadcast" && request.method === "POST") {
      const { channelId, data } = await request.json() as any;
      const topic = channelId || "global";
      
      // Broadcast to all sockets subscribed to this channel
      this.state.getWebSockets(topic).forEach(ws => {
        try {
          ws.send(JSON.stringify(data));
        } catch (e) {
          // Socket might be closed
        }
      });
      
      return new Response("ok");
    }

    return new Response("Not Found", { status: 404 });
  }

  // WebSocket event handlers (using hibernation API for efficiency)
  async webSocketMessage(ws: WebSocket, message: string) {
    // No client-to-server messages expected for now
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean) {
    ws.close(code, reason);
  }

  async webSocketError(ws: WebSocket, error: any) {
    ws.close();
  }
}

// Helper to use the DO as a Notifier in the shared core
export class WorkerNotifier implements Notifier {
  constructor(private doNamespace: DurableObjectNamespace) {}

  broadcast(channelId: string | null, data: any): void {
    // We use a singleton ID for the notifier to keep all sockets in one bucket
    const id = this.doNamespace.idFromName("global-notifier");
    const stub = this.doNamespace.get(id);
    
    // Fire and forget the broadcast call to the DO
    stub.fetch("http://do/broadcast", {
      method: "POST",
      body: JSON.stringify({ channelId, data })
    }).catch(e => console.error("DO Broadcast failed", e));
  }
}
