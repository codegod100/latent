import { Notifier } from "./core";

export class NotifierDO implements DurableObject {
  constructor(private state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/ws") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("Expected Upgrade: websocket", { status: 426 });
      }
      const channelId = url.searchParams.get("channelId") || "global";
      const [client, server] = new WebSocketPair();
      this.state.acceptWebSocket(server, [channelId]);
      return new Response(null, { status: 101, webSocket: client });
    }

    if (url.pathname === "/broadcast" && request.method === "POST") {
      try {
        const { channelId, data } = await request.json() as any;
        const topic = channelId || "global";
        
        // Broadcast to all sockets tagged with this channelId
        const sockets = this.state.getWebSockets(topic);
        sockets.forEach(ws => {
          try {
            ws.send(JSON.stringify(data));
          } catch (e) {}
        });
        
        return new Response("ok");
      } catch (err) {
        return new Response(String(err), { status: 500 });
      }
    }

    return new Response("Not Found", { status: 404 });
  }

  async webSocketMessage(ws: WebSocket, message: string) {}
  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean) { ws.close(code, reason); }
  async webSocketError(ws: WebSocket, error: any) { ws.close(); }
}

export class WorkerNotifier implements Notifier {
  constructor(private doNamespace: DurableObjectNamespace) {}

  async broadcast(channelId: string | null, data: any): Promise<void> {
    const id = this.doNamespace.idFromName("global-notifier");
    const stub = this.doNamespace.get(id);
    
    // CRITICAL: Must await the fetch to ensure it completes before Worker terminates
    await stub.fetch("http://do/broadcast", {
      method: "POST",
      body: JSON.stringify({ channelId, data })
    });
  }
}
