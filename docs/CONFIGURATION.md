# Configuration Reference

## Settings Reference

| Setting | DB Preference Key | config.ini.php Key | Default | Description |
|---|---|---|---|---|
| JWT Issuer | `JWT_AUTH_ISSUER` | `jwt_auth_issuer` | (empty) | Expected `iss` claim value |
| JWT Audience | `JWT_AUTH_AUDIENCE` | `jwt_auth_audience` | (empty) | Expected `aud` claim value |
| JWKS URL | `JWT_AUTH_JWKS_URL` | `jwt_auth_jwks_url` | (empty) | JWKS endpoint URL for automatic key fetching |
| Public Key / Secret | `JWT_AUTH_PUBLIC_KEY` | — | (empty) | Public key (RS256/ES256) or shared secret (HS256) |
| Algorithm | `JWT_AUTH_ALGORITHM` | — | `RS256` | Signing algorithm: `RS256`, `HS256`, or `ES256` |
| Token Source Priority | `JWT_AUTH_SOURCE_PRIORITY` | `jwt_auth_source_priority` | `header,cookie` | Comma-separated list of sources to check |
| Header Name | `JWT_AUTH_HEADER_NAME` | `jwt_auth_header_name` | `Authorization` | HTTP header to read the token from |
| Cookie Name | `JWT_AUTH_COOKIE_NAME` | `jwt_auth_cookie_name` | `jwt_token` | Cookie name to read the token from |

The module requires **Issuer**, **Audience**, and either a **JWKS URL** or **Public Key / Secret** to be non-empty for authentication to activate. If any of these is missing, the module silently passes through without attempting validation.

## Admin Panel Configuration

1. Go to **Control Panel > Modules > All modules**
2. Find "JWT Authentication" and click the settings icon (wrench)
3. Fill in the settings and click **Save**

The config page is at `/admin/modules/jwt-auth/config` and requires administrator access.

## config.ini.php Configuration

Add settings to your webtrees `data/config.ini.php` file. These take precedence over the admin panel for the 6 supported keys:

```ini
jwt_auth_issuer="https://your-team.cloudflareaccess.com"
jwt_auth_audience="your-audience-hash"
jwt_auth_jwks_url="https://your-team.cloudflareaccess.com/cdn-cgi/access/certs"
jwt_auth_header_name="Cf-Access-Jwt-Assertion"
jwt_auth_cookie_name="jwt_token"
jwt_auth_source_priority="header,cookie"
```

Only `jwt_auth_issuer`, `jwt_auth_audience`, `jwt_auth_jwks_url`, `jwt_auth_header_name`, `jwt_auth_cookie_name`, and `jwt_auth_source_priority` can be set in `config.ini.php`. The public key and algorithm must be configured through the admin panel.

## Precedence Rules

For settings that support both sources:

1. **config.ini.php** is checked first (read from request attributes set by webtrees `ReadConfigIni` middleware)
2. **Admin panel** (DB preferences) is used as fallback when config.ini.php has no value

This means config.ini.php values cannot be overridden from the admin panel. The admin panel always shows the DB-stored values regardless of config.ini.php.

## Key Source Setup

### JWKS Endpoint (recommended for providers like Cloudflare Access)

When a **JWKS URL** is configured, the module fetches signing keys from the endpoint automatically instead of using a static public key. This enables seamless key rotation.

- Set **JWKS URL** to your provider's JWKS endpoint (e.g., `https://your-team.cloudflareaccess.com/cdn-cgi/access/certs`)
- The URL must use HTTPS
- Keys are cached for 1 hour
- When a token presents an unknown `kid` (key ID), the cache is refreshed and decoding retried once — this handles key rotation without manual intervention
- When JWKS URL is set, the **Algorithm** and **Public Key / Secret** fields are ignored

### Static Key

If your identity provider does not expose a JWKS endpoint, configure the algorithm and key manually using the settings below.

## Algorithm-Specific Setup

### RS256 (RSA — recommended)

- Set **Algorithm** to `RS256`
- Paste the **public key** (PEM format) into the Public Key / Secret field:
  ```
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
  -----END PUBLIC KEY-----
  ```
- The module rejects private keys — only the public key is needed

### ES256 (ECDSA)

- Set **Algorithm** to `ES256`
- Paste the **EC public key** (PEM format)
- Same private key rejection applies

### HS256 (HMAC)

- Set **Algorithm** to `HS256`
- Paste the **shared secret** (minimum 32 characters)
- The same secret must be used by both the token issuer and this module
- HS256 is a symmetric algorithm — the secret must be kept confidential on both sides

## Token Source Configuration

### Source Priority

The `jwt_auth_source_priority` setting controls which sources are checked and in what order. Valid sources: `header`, `cookie`.

Examples:
- `header,cookie` — check header first, then cookie (default)
- `header` — header only (highest security)
- `cookie,header` — check cookie first, then header
- `cookie` — cookie only

### Header Extraction

When the header source is enabled, the module reads the configured header name (default: `Authorization`):

- If the value starts with `Bearer `, the prefix is stripped and the remainder is used as the token
- Otherwise the raw header value is used as the token

For Cloudflare Access, set the header name to `Cf-Access-Jwt-Assertion` (Cloudflare sends the token directly, without a `Bearer` prefix).

### Cookie Extraction

When the cookie source is enabled, the module reads the cookie with the configured name (default: `jwt_token`). The cookie value is used directly as the token.

The cookie name can be configured through the admin panel or `config.ini.php` (key: `jwt_auth_cookie_name`).
