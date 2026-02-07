# Security

## Security Model Overview

The JWT auth module adds an authentication path to webtrees — it does not replace the existing login system. The module operates as passive middleware: it attempts to authenticate users via JWT tokens, but never blocks requests. If authentication fails for any reason, the request proceeds as if the module were not installed.

The module does not issue tokens. It only validates tokens issued by an external identity provider (e.g., Cloudflare Access).

## Rate Limiting

The module applies site-wide rate limiting before attempting token validation:

- **Limit:** 20 attempts per 60 seconds
- **Scope:** Site-wide (not per-user or per-IP)
- **Key:** `rate-limit-jwt-login`
- **Implementation:** Uses webtrees' built-in `RateLimitService`

When the rate limit is exceeded, `RateLimitService` throws an exception which is caught and logged. The request passes through without authentication.

## Algorithm Restrictions

### Allowlist

Only three algorithms are accepted: `RS256`, `HS256`, `ES256`. The admin config form enforces this via a `<select>` element, and the save handler validates against the allowlist before persisting.

### Private Key Rejection

The config save handler rejects any key/secret value containing:
- `BEGIN PRIVATE KEY`
- `BEGIN RSA PRIVATE KEY`
- `BEGIN EC PRIVATE KEY`

This prevents accidentally storing a private key in the database. Only public keys (for RS256/ES256) or shared secrets (for HS256) should be stored.

### HS256 Minimum Key Length

For HS256, the shared secret must be at least 32 characters. This is enforced at save time in the config action handler.

### JWKS URL Validation

When a JWKS URL is provided, the config save handler validates:
- The URL must use HTTPS (rejects HTTP endpoints)
- The URL must be a valid URL per `FILTER_VALIDATE_URL`

When a JWKS URL is set, algorithm and key validation are skipped since keys and algorithms come from the JWKS endpoint.

### Algorithm Confusion Prevention

The algorithm used for validation is read from the module's stored configuration, not from the JWT header. This prevents algorithm confusion attacks where an attacker sets `alg: HS256` in a token header and uses the public key as the HMAC secret.

`firebase/php-jwt` enforces this by requiring the expected algorithm to be passed explicitly to `JWT::decode()`.

## Token Source Security

The module only accepts tokens from HTTP headers and cookies. It deliberately does not support:

- **Query parameters** — tokens in URLs are logged in server access logs, browser history, and referrer headers
- **POST body** — would require the module to parse request bodies, and is not aligned with the middleware pattern of transparent authentication

### Header vs Cookie

- **HTTP headers** (e.g., `Cf-Access-Jwt-Assertion`) are the most secure source. They are set by the reverse proxy and are not accessible to client-side JavaScript.
- **Cookies** should use `HttpOnly` and `Secure` flags. The module reads cookies but does not set them — cookie management is the responsibility of the token issuer or reverse proxy.

## Authentication Logging

All authentication outcomes are logged to the webtrees authentication log (`Log::addAuthenticationLog()`):

| Event | Log message |
|---|---|
| No token in request | `JWT: no token found in request` |
| Config incomplete | `JWT: missing config - issuer=<set/empty> audience=<set/empty> key=<jwks/set/empty>` |
| Missing email claim | `JWT login failed: no email in token` |
| User not found | `JWT login failed: user not found for email` |
| Email not verified | `JWT login failed: email not verified for <username>` |
| Account not approved | `JWT login failed: account not approved for <username>` |
| Validation error | `JWT login failed: <exception message>` |
| Successful login | `JWT Login: <username>/<realname>` |

The diagnostic messages ("no token", "missing config") are logged on every request that doesn't carry a token or has incomplete configuration. They help diagnose silent failures but may be verbose — future versions may reduce their log level.

Logs do not include the email address from the token when the user is not found (to avoid logging potentially untrusted input). They do include the username for known users.

## Graceful Failure

The module wraps its entire authentication logic in a `try/catch` block. Any exception — whether from token validation, database access, rate limiting, or user lookup — is caught, logged, and silently ignored. The request proceeds to the next middleware handler.

This means:
- A misconfigured module will not break your webtrees installation
- Invalid tokens will not produce error pages
- The module never returns HTTP error responses

## JWKS Security

When using a JWKS endpoint for key management:

- **HTTPS only** — the JWKS URL must use HTTPS. The module rejects HTTP endpoints at configuration time.
- **Cache TTL** — fetched keysets are cached for 1 hour to reduce network requests and latency. After the TTL expires, the keyset is re-fetched on the next request.
- **Key rotation** — if a token presents a `kid` not found in the cached keyset, the module refreshes the cache and retries decoding once. This handles key rotation transparently. Signature verification failures (where the `kid` matches but the signature is invalid) are not retried.
- **Cache invalidation** — when the JWKS URL is changed in the admin config, the cache is cleared so the new endpoint is fetched immediately.
- **SSL verification** — the JWKS fetch uses `verify_peer` and `verify_peer_name` to prevent MITM attacks on the JWKS endpoint.

## Deployment Recommendations

### Use HTTPS

JWT tokens are bearer tokens. If transmitted over HTTP, they can be intercepted. Always serve webtrees over HTTPS when using this module.

### Prefer Header-Only Mode

If your setup supports it (e.g., Cloudflare Access), configure `jwt_auth_source_priority` to `header` only. This eliminates cookie-based attack vectors (CSRF with cookie replay).

### Set HttpOnly and Secure on Cookies

If using cookie-based token delivery, ensure the cookie is set with:
- `HttpOnly` — prevents JavaScript access (mitigates XSS token theft)
- `Secure` — only sent over HTTPS
- `SameSite=Strict` or `SameSite=Lax` — mitigates CSRF

The module does not set cookies itself — this must be configured in your reverse proxy or identity provider.

### Use Short-Lived Tokens

Configure your identity provider to issue tokens with short expiration times. The module validates `exp` and `nbf` claims on every request. Shorter token lifetimes reduce the window of exposure if a token is compromised.

### Restrict the Public Key

For RS256/ES256, only the public key is needed. Never store the private key in the module configuration. The config save handler rejects private keys, but the key should also be protected at the identity provider side.

### Keep webtrees User Accounts in Sync

The module does not create user accounts. Users must exist in webtrees with a matching email address, be email-verified, and be admin-approved before JWT authentication will work. Deactivating a user in webtrees effectively revokes JWT access without needing to change the identity provider configuration.
