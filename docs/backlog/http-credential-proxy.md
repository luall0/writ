# HTTP credential proxy (v2)

**Status:** idea, sketched. **Area:** Credentials. **Kind:** feature.

Generic secret-store proxying is a [v1 non-goal](../product.md#non-goals); this is the v2 design sketch.

## Proposal

Same principle as git: **agents never hold API keys.** A ticket can request access to an HTTP service; the agent gets a placeholder token bound to its lease, and the daemon injects the real secret when forwarding each request.

**Two modes**

| Mode | How the agent calls | For | Against |
|---|---|---|---|
| **Base URL** | `https://writ.home:<http-port>/<service>/api/...` | No certificate to install; works wherever a base URL can be set (curl, most SDKs) | Breaks on absolute URLs in responses (pagination, redirects), hardcoded SDK hosts, browser OAuth flows |
| **Forward proxy** | `HTTPS_PROXY=https://writ.home:<http-port>`, original URLs unchanged | Fully transparent for almost every tool | The daemon decrypts TLS for registered hosts → a Writ CA must be trusted in the agent environment (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`…). Unregistered hosts pass through untouched or are blocked |

**Rules**
1. **The target host comes from the registry, never from the request.** In base URL mode, `<service>` is a service name declared in the registry, mapped to its real host and secret. Otherwise an injected agent could write `writ.home/attacker.com/...` and receive the key.
2. **No secret across hosts.** Redirects to another host are never followed with the secret attached.
3. **Finer scope than the key itself.** Tickets and templates restrict by service, **methods and paths** (e.g. `GET /api/weather/*` only, turning an admin key into a read-only one), request count, rate and duration.
4. **Placeholder tokens.** The agent sends `writ_tok_…`; the daemon validates it against the lease, strips it, and injects the real secret where the service expects it (header, query parameter, sometimes body), configured per service.
5. **OAuth refresh stays in the daemon.** The agent only ever sees placeholders.
6. **Redaction.** Responses are scanned for the real secret (some APIs echo keys in errors or debug output) and redacted.
7. **Streaming passthrough.** Server-Sent Events and WebSockets (LLM APIs, live feeds) are streamed, never buffered.
8. **Audit without bodies.** Log method, path, status, size and lease per request; bodies off by default.
9. **Own port**, separate from the SSH gateway.

**Registry sketch**

```yaml
services:
  weather:
    upstream: https://weather.com
    secret: weather-api-key            # in the sealed keystore
    inject:
      header: X-Api-Key                # or query: api_key / bearer: true
    allowed: ["GET /api/weather/*"]    # upper bound for any ticket
```

**Not solved:** responses can carry prompt injection. Writ limits what an injected agent can do with the API, not what it reads.

**Prior art:** CyberArk Secretless Broker, Fly.io tokenizer (secret injection by a proxy).

**Implementation notes:** hyper/axum + rustls; per-host certificates generated on the fly (`rcgen`) for proxy mode.

## Open questions

To write when picked: lease model fields for services, where the Writ CA lives, registry changes as admin changes.

## Plan

Added when picked.
