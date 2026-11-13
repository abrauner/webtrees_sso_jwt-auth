# Local API Access for MCP Agents

> **Status: done (2026-11-13), via Option D with a module change.** The same webtrees
> also answers as `https://stammbaum.local.retis.tech`, an nginx vhost on the normal
> port 443 that shares the public vhost's root and PHP-FPM pool and only allows the home
> networks and the WireGuard VPN (cloudflared's host is denied). That vhost sets
> `fastcgi_param JWT_AUTH_SKIP "1"`, so this module passes its requests through
> untouched (v0.1.1, see "Skipping on a local hostname" in the README). Users log in
> there with their webtrees password, and the webtrees-api works with its own OAuth2
> tokens (`/api/get-version` → `2.2.6`).
>
> - Problems 1 and 4: `config.ini.php` has `base_url="${WEBTREES_BASE_URL}"`; PHP
>   expands it from the FastCGI params, and each vhost passes its own URL.
> - Problem 2: the existing `*.local.retis.tech` wildcard certificate.
> - Problem 3: the local name never redirects to the public one.
>
> Infrastructure details: `docs/webtrees.md` in the homelab repo (nibbler). The rest of
> this document is the analysis from before.

## Problem Statement

AI agents using MCP cannot easily obtain a Cloudflare Access JWT (which requires a
browser-based login flow). The webtrees instance is publicly exposed only through
Cloudflare Access + Tunnel, so a bypass is needed for local agent access without
compromising the security of the public domain.

## Current Infrastructure

```
Internet → Cloudflare Access → Tunnel → cloudflared (local) → nginx:443 → PHP-FPM → webtrees
```

| Setting | Value |
|---|---|
| Public domain | `stammbaum.schulze-everding.de` |
| JWT header | `Cf-Access-Jwt-Assertion` |
| JWT issuer | `https://retis.cloudflareaccess.com` |
| Trusted proxy | `10.27.73.23/32` |

**Key insight:** nginx port 443 is already local-only. `cloudflared` connects outbound
and is the only thing routing internet traffic to it. A second nginx port is genuinely
unreachable from the internet without explicit tunnel ingress configuration.

## Options

### Option A: IP-based subnet bypass in JWT middleware

Add subnet detection at the top of `process()` to skip JWT auth for requests from a
configured local CIDR.

- **Pros:** Self-contained, no infra changes
- **Cons:** IP spoofing risk if trusted proxy headers are misconfigured; subnet config
  lives in module
- **Status:** Not pursued

---

### Option B: Route-based path prefix bypass

Skip JWT auth for requests to a specific path prefix (e.g. `/api/local/`).

- **Pros:** No network dependency
- **Cons:** Requires combining with firewall rules to be meaningful
- **Status:** Not pursued

---

### Option C: Static API key in JWT middleware (code change required)

Extend `process()` to check for an `X-Api-Key` header before the JWT flow. Match
against a secret stored as a module preference. Log in a configured service user on
match.

**Files to change:** `JwtAuthModule.php`, `JwtConfigAction.php`, `JwtConfigPage.php`,
`resources/views/config.phtml`, tests.

```php
$apiKey = $request->getHeaderLine('X-Api-Key');
if (!empty($apiKey) && hash_equals($this->getPreference('jwt_auth_api_key'), $apiKey)) {
    $user = $this->userService->find((int)$this->getPreference('jwt_auth_api_user_id'));
    Auth::login($user);
    return $handler->handle($request);
}
```

- **Pros:** Works through the existing Cloudflare URL; no infra changes; stateless
  per-request (no session/redirect problem)
- **Cons:** API key travels over HTTPS; Cloudflare Access must allow unauthenticated
  pass-through for the tunnel (or bypass Access for requests with this header)
- **Open question:** Which user does the API key authenticate as — dedicated service
  account or existing user?
- **Status:** Viable, not yet implemented. Preferred if the `base_url` redirect problem
  is a blocker.

---

### Option D: Second nginx server block on local-only port (no code changes)

Add a second `server {}` block bound to `127.0.0.1:8443` (or subnet IP). Override JWT
config via `fastcgi_param` to pass empty values, triggering the existing silent
pass-through in the middleware (step 5: issuer/audience/key all empty → pass through).

```nginx
server {
    listen 127.0.0.1:8443 ssl;
    server_name _;

    include /etc/nginx/snippets/ssl-wildcard.conf;
    include /etc/nginx/snippets/ssl-params.conf;

    root /data/www/webtrees/stammbaum.schulze-everding.de/htdocs;
    index index.php index.html /index.html =404;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff|woff2)$ {
        expires 365d;
    }

    location ~ \.php$ {
        include fastcgi.conf;
        fastcgi_pass php-webtrees_719000e0e9;
        fastcgi_read_timeout 300;

        # Disable JWT auth — empty issuer triggers silent pass-through
        fastcgi_param JWT_AUTH_ISSUER   "";
        fastcgi_param JWT_AUTH_AUDIENCE "";
        fastcgi_param JWT_AUTH_JWKS_URL "";
    }

    location ~ /\. {
        deny all;
    }
}
```

- **Pros:** Zero code changes; `cloudflared` never exposes this port (not in tunnel
  ingress config); clean separation of concerns
- **Cons:** SSL cert must cover local hostname; `base_url` redirect problem (see below)
- **Status:** Preferred infra approach, blocked by `base_url` redirect problem depending
  on MCP usage pattern

---

### Option E: Cloudflare Service Token (Zero Trust)

Use Cloudflare Access Service Tokens (`CF-Access-Client-Id` +
`CF-Access-Client-Secret` headers) for machine-to-machine auth at the Cloudflare layer.

- **Pros:** Stays entirely within the Cloudflare security model
- **Cons:** Requires Cloudflare Zero Trust paid plan
- **Status:** Not pursued

---

## Problems Discovered

### Problem 1: `base_url` redirect after login

Webtrees stores `base_url=https://stammbaum.schulze-everding.de` in the DB. After a
local login via Option D, webtrees redirects the client to the public domain, which hits
Cloudflare Access and requires a JWT.

**Mitigations (in order of simplicity):**

1. MCP client calls webtrees endpoints directly without following login redirects — viable
   if the MCP only needs API-style calls, not session-based navigation
2. Override `base_url` via `fastcgi_param BASE_URL` — webtrees may not read this from
   request attributes (unverified; `base_url` is not in the list of `config.ini.php`
   overridable keys)
3. Use Option C instead — stateless per-request auth through the public URL, no redirect
   involved

---

### Problem 2: SSL certificate coverage for local hostname

The wildcard cert `*.retis.tech` does not cover `*.local.retis.tech` (wildcards cover
only one DNS label). Options:

- Use a cert that explicitly covers the local hostname
- Use plain HTTP on loopback if truly loopback-only and the MCP client runs on the same
  host
- Accept a cert mismatch with `server_name _;` and configure the MCP client to skip
  verification (not recommended)

---

### Problem 3: Cloudflare Access challenges public domain requests

Even with a local bypass, if the MCP client follows redirects to the public domain,
Cloudflare Access will challenge for a JWT. Option C avoids this entirely since it
operates on the public Cloudflare URL using a header — Cloudflare Tunnel forwards the
request without requiring Access auth (Access is a separate layer explicitly attached to
the tunnel application).

---

### Problem 4: webtrees has no multi-`base_url` support

Webtrees does not support virtual hosting or multiple base URLs natively. `base_url` is
a single value in the `site_setting` DB table and is not overridable via
`config.ini.php`. All solutions are at the infrastructure (nginx/proxy) or middleware
(JWT module) layer.

---

## Recommended Path

### Short term — no code changes (Option D)

Add a second nginx server block on `127.0.0.1:8443` with `fastcgi_param` overrides.
Firewall the port to loopback or local subnet. The JWT middleware silently passes through
due to empty issuer/audience.

**Prerequisite:** Clarify what the MCP client actually needs to do. If it only makes
direct API-style calls without following login redirects, the `base_url` redirect problem
is irrelevant and Option D is complete.

### If redirect is a blocker (Option C)

Implement static API key support in the JWT middleware. The MCP client sends
`X-Api-Key: <secret>` to the existing public Cloudflare URL. No infra changes, no
redirects, stateless per-request auth.

**Decision needed before implementing Option C:**
- Should the API key authenticate as a dedicated service account (recommended) or an
  existing user?
