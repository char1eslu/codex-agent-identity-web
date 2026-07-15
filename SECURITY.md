# Security

## Sensitive data

Do not include OAuth tokens, Agent Identity private keys, assertions, task IDs,
account IDs, generated `auth.json` files, or production credentials in issues,
pull requests, logs, screenshots, or test fixtures.

Use synthetic values when reporting a bug. If a report cannot be safely reduced
to synthetic data, open a private GitHub Security Advisory instead of a public
issue.

## Deployment model

The browser creates the private key locally. OAuth credentials transit through
the Worker only for fixed upstream authentication operations. The Worker has no
storage bindings, does not expose a general-purpose proxy, and disables Worker
observability in the supplied configuration.

Operators must still protect their Cloudflare account, review changes before
deployment, avoid adding request-body logging or third-party analytics, and
configure Cloudflare Rate Limiting for `/api/*` on public deployments.
