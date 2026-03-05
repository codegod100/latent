const fs = require('fs');
const path = require('path');

const origin = process.argv[2];
const outputPath = process.argv[3] || 'client-metadata.json';

if (!origin) {
  console.error('Usage: node generate-metadata.js <origin> [outputPath]');
  process.exit(1);
}

const metadata = {
  client_id: `${origin.replace(/\/$/, '')}/client-metadata.json`,
  client_name: "Latent",
  application_type: "web",
  token_endpoint_auth_method: "none",
  dpop_bound_access_tokens: true,
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  redirect_uris: [`${origin.replace(/\/$/, '')}/`],
  scope: "atproto transition:generic"
};

fs.writeFileSync(outputPath, JSON.stringify(metadata, null, 2));
console.log(`Generated metadata for ${origin} at ${outputPath}`);
