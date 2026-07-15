# Codex Agent Identity Web

A small Cloudflare Worker that converts supported ChatGPT/Codex authentication
JSON into a Codex Agent Identity `auth.json`.

The UI supports:

- ChatGPT Web auth JSON with a top-level `accessToken`.
- Codex OAuth `auth.json` with `tokens.access_token`, `tokens.id_token`, and an
  optional `tokens.refresh_token`.
- Existing record-form Codex Agent Identity `auth.json`.

## Trust boundary

The Ed25519 key pair and final Agent Identity file are generated in the browser.
The private key is never sent to the Worker.

OAuth credentials do pass through the Worker while it forwards requests to
fixed OpenAI OAuth refresh, agent registration, and task registration endpoints.
The Worker has no storage bindings and observability is disabled, but you still
need to trust the Worker operator and Cloudflare runtime. Self-host the project
if that trust boundary is not acceptable.

The generated `auth.json` contains a reusable private key and task identity.
Treat it like a password: do not paste it into an untrusted deployment, publish
it, commit it, or include it in logs and screenshots.

## Local development

```bash
npm install
npm test
npm run check
npm run build
npm run dev
```

## Deploy

Authenticate Wrangler, review `wrangler.jsonc`, then deploy to your own
`workers.dev` subdomain. Change the placeholder Worker `name` first; the deploy
command intentionally refuses to use the repository default:

```bash
npm run deploy
```

For a custom domain, copy `wrangler.jsonc` to the ignored
`wrangler.production.jsonc`, set `workers_dev` to `false`, add your `routes`, and
run:

```bash
npm run deploy:production
```

Public deployments should also configure Cloudflare Rate Limiting for `/api/*`.
The Worker exposes only fixed authentication operations, but they are otherwise
available to unauthenticated HTTP clients.

## Credential validation

An explicitly authorized credential can be converted without printing its
fields. The output defaults to a private temporary directory with mode `0600`.

```bash
AUTH_PATH=/path/to/input.json npm run validate:auth
AUTH_PATH=/path/to/generated/auth.json npm run verify:auth
```

`verify:auth` makes a real request to the Codex usage endpoint. Never use a
credential you are not authorized to access.

## Status

This project implements an unofficial protocol observed in Codex clients. The
upstream endpoints and payloads can change without notice. It is not affiliated
with or endorsed by OpenAI.

## License

MIT
