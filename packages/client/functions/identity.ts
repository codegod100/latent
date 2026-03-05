export const onRequest: PagesFunction = async (context) => {
  const url = new URL(context.request.url);
  
  if (url.pathname === '/identity/client-metadata.json') {
    const origin = url.origin;
    const metadata = {
      client_id: `${origin}/identity/client-metadata.json`,
      client_name: "Isolated ATProto Client",
      application_type: "web",
      token_endpoint_auth_method: "none",
      dpop_bound_access_tokens: true,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      redirect_uris: [`${origin}/`],
      scope: "atproto transition:generic"
    };

    return new Response(JSON.stringify(metadata), {
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store"
      }
    });
  }

  return context.next();
};
