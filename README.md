# webtrees-jwt-auth

JWT authentication middleware for [webtrees](https://webtrees.net/). Automatically authenticates users via JWT tokens on every request — no separate login endpoint needed.

## How It Works

This module runs as PSR-15 middleware on every HTTP request. It extracts a JWT token from the `Authorization` header or a cookie, validates the signature and claims, looks up the webtrees user by the token's `email` claim, and creates a session. If no token is found or validation fails, the request passes through normally to the standard webtrees login flow.

## Installation

### Production

Download the latest `jwt-auth-vX.X.X.tar.gz` from the [releases page](https://github.com/abrauner/webtrees-jwt-auth/releases) and extract it into your webtrees `modules_v4/` directory:

```bash
cd /path/to/webtrees/modules_v4/
tar -xzf jwt-auth-vX.X.X.tar.gz
```

The archive includes all dependencies — no need to run Composer.

Enable the module in **Control Panel > Modules > All modules**.

### Development

```bash
cd /path/to/webtrees/modules_v4/
git clone https://github.com/abrauner/webtrees-jwt-auth.git jwt-auth
cd jwt-auth
composer install
```

## Configuration

Configure the module in **Control Panel > Modules > JWT Authentication** (settings icon).

Required settings:

| Setting | Description |
|---|---|
| JWT Issuer | Expected `iss` claim value |
| JWT Audience | Expected `aud` claim value |
| Public Key / Secret | Public key (RS256/ES256) or shared secret (HS256) |
| Algorithm | `RS256`, `HS256`, or `ES256` |

Optional settings:

| Setting | Default | Description |
|---|---|---|
| Token Source Priority | `header,cookie` | Order to check for tokens |
| Header Name | `Authorization` | HTTP header containing the token |
| Cookie Name | `jwt_token` | Cookie containing the token |

Settings can also be defined in `data/config.ini.php`, which takes precedence over the admin panel. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the full reference.

## JWT Token Requirements

The token must contain these claims:

| Claim | Required | Description |
|---|---|---|
| `iss` | Yes | Must match the configured issuer |
| `aud` | Yes | Must contain the configured audience (string or array) |
| `email` | Yes | Email address used to look up the webtrees user |
| `exp` | Yes | Expiration time (validated by firebase/php-jwt) |
| `nbf` | No | Not-before time (validated if present) |

Example payload:

```json
{
  "iss": "https://your-team.cloudflareaccess.com",
  "aud": ["3e011168046ad436d012835a1d46bb2c0f76cf96221a29969a899244bbeb6c88"],
  "email": "user@example.com",
  "exp": 1770342589,
  "iat": 1770320989,
  "nbf": 1770320989,
  "sub": "837b8b38-99af-549b-b1f9-af21790bee0a"
}
```

## User Requirements

The user account must:
- Already exist in webtrees (the module does not create accounts)
- Have a matching email address (the `email` claim is used for lookup via `UserService::findByEmail()`)
- Be email-verified
- Be approved by an administrator

## Cloudflare Access Quick Start

1. Create a Cloudflare Access application for your webtrees site
2. Get the public key from `https://<your-team>.cloudflareaccess.com/cdn-cgi/access/certs`
3. Configure the module:
   - **Issuer:** `https://<your-team>.cloudflareaccess.com`
   - **Audience:** your application's AUD tag
   - **Algorithm:** `RS256`
   - **Public Key:** from the certs endpoint
   - **Header Name:** `Cf-Access-Jwt-Assertion` (Cloudflare sets this header automatically)
4. Ensure webtrees users exist with email addresses matching their Cloudflare identity

## Troubleshooting

All authentication events are logged in **Control Panel > Website logs > Authentication log**.

| Log message | Cause |
|---|---|
| `JWT login failed: no email in token` | Token is missing the `email` claim |
| `JWT login failed: user not found for email` | No webtrees user with that email address |
| `JWT login failed: email not verified for <user>` | User's email is not verified in webtrees |
| `JWT login failed: account not approved for <user>` | User's account is not approved in webtrees |
| `JWT validation failed: ...` | Signature, expiration, or claim mismatch |
| `JWT Login: <user>/<name>` | Successful authentication |

## Development

Run the test suite (67 tests):

```bash
vendor/bin/phpunit
```

Build a release archive:

```bash
./build.sh v1.0.0
```

Or push a `v*` tag to trigger the GitHub Actions release workflow.

## Further Documentation

- [Architecture](docs/ARCHITECTURE.md) — middleware flow, class responsibilities, webtrees integration
- [Configuration Reference](docs/CONFIGURATION.md) — all settings, config.ini.php, admin panel
- [Security](docs/SECURITY.md) — security model, threat mitigations, deployment recommendations

## License

GPL-3.0-or-later. See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.html).
