# CLAUDE.md

## Project Overview

**webtrees-jwt-auth** is a custom module for [webtrees](https://webtrees.net/) (v2.1.x) that authenticates users via JWT tokens. It runs as PSR-15 middleware on every request, extracting tokens from HTTP headers or cookies, validating them, and creating a webtrees session for the matched user.

- **Namespace:** `Anschev\JwtAuth`
- **Composer package:** `abrauner/webtrees-jwt-auth`
- **License:** GPL-3.0-or-later
- **PHP:** ^8.3
- **Dependency:** `firebase/php-jwt` ^6.10

## Development Setup

This is a standalone module. All dependencies (including webtrees and PHPUnit) are installed via Composer.

```bash
cd jwt-auth
composer install
```

Note: webtrees is installed from source (not dist) so that its `tests/TestCase.php` is available.

## Commands

```bash
# Run tests (85 tests)
vendor/bin/phpunit

# Build a release archive
./build.sh v1.0.0
```

## Architecture

### Entry Point

`module.php` — loaded by the webtrees module scanner. Loads `vendor/autoload.php` if present, then `require_once`s `JwtAuthModule.php` and returns a new instance.

### Core Class

`JwtAuthModule.php` extends `AbstractModule` and implements:

| Interface | Purpose |
|---|---|
| `ModuleCustomInterface` | Author name, version (`0.0.0-dev`, replaced at release), support URL |
| `ModuleConfigInterface` | Admin config page link via `getConfigLink()` |
| `MiddlewareInterface` | JWT validation on every request via `process()` |

### boot()

Registers the `jwt-auth` view namespace and two routes (GET + POST) for the admin config page, both protected with `AuthAdministrator` middleware.

### Middleware Flow (process())

1. Skip if user already logged in (`Auth::id() !== null`)
2. Rate limit (20 attempts / 60s site-wide, key: `rate-limit-jwt-login`)
3. Extract token from header or cookie (configurable priority via `jwt_auth_source_priority`)
4. Load config — `config.ini.php` overrides DB preferences for `JWT_AUTH_ISSUER`, `JWT_AUTH_AUDIENCE`, `JWT_AUTH_JWKS_URL`, `JWT_AUTH_HEADER_NAME`, `JWT_AUTH_COOKIE_NAME`, `JWT_AUTH_SOURCE_PRIORITY`
5. Require issuer, audience, and either JWKS URL or public key to be non-empty (silent pass-through if missing)
6. Decode and validate JWT — via JWKS keyset (if JWKS URL configured) or static key via `firebase/php-jwt` (signature, exp, nbf)
7. Validate `iss` and `aud` claims against config
8. Require `email` claim in token
9. Find webtrees user by email via `UserService::findByEmail()`
10. Verify account status (email verified + approved)
11. Create session via `Auth::login()`, set active timestamp, load language/theme preferences
12. Update request user attribute and DI container so downstream handlers see the authenticated user
13. On any failure: log via `Log::addAuthenticationLog()` and pass through to next handler (never block)

### Token Extraction

`extractToken()` iterates over `jwt_auth_source_priority` (default: `header,cookie`):

- **Header:** Reads the configured header (default: `Authorization`). Strips `Bearer ` prefix if present, otherwise uses the raw value.
- **Cookie:** Reads the configured cookie (default: `jwt_token`). Cookie name supports config.ini.php override via `jwt_auth_cookie_name`.

### Config Resolution (getConfig())

For `jwt_auth_issuer` → `JWT_AUTH_ISSUER`, `jwt_auth_audience` → `JWT_AUTH_AUDIENCE`, `jwt_auth_jwks_url` → `JWT_AUTH_JWKS_URL`, `jwt_auth_header_name` → `JWT_AUTH_HEADER_NAME`, `jwt_auth_cookie_name` → `JWT_AUTH_COOKIE_NAME`, and `jwt_auth_source_priority` → `JWT_AUTH_SOURCE_PRIORITY`:
1. Check `Validator::attributes($request)->string()` (populated from `config.ini.php` by webtrees `ReadConfigIni` middleware)
2. Fall back to `$this->getPreference()` (DB `module_setting` table)

`JWT_AUTH_PUBLIC_KEY` and `JWT_AUTH_ALGORITHM` are always read from DB preferences only.

`JWT_AUTH_JWKS_CACHE` and `JWT_AUTH_JWKS_CACHE_TIMESTAMP` are internal DB preferences used for caching the JWKS keyset (1 hour TTL).

### Request Handlers

- `Http/RequestHandlers/JwtConfigPage.php` — GET handler. Uses `ViewResponseTrait` with admin layout. Finds the module via `ModuleService::findByInterface()` and passes all 8 preferences to the view.
- `Http/RequestHandlers/JwtConfigAction.php` — POST handler (`final readonly class`). Validates JWKS URL (HTTPS-only), algorithm against allowlist, rejects private keys, enforces HS256 minimum key length (32 chars), builds `jwt_auth_source_priority` from checkboxes, clears JWKS cache on URL change, saves all 8 preferences. Algorithm/key validation is skipped when JWKS URL is set.

Both routes: `/admin/modules/jwt-auth/config`

### Config Validation (JwtConfigAction)

- JWKS URL must use HTTPS and be a valid URL (when provided)
- When JWKS URL is set, algorithm and key validation are skipped
- Algorithm must be in `['RS256', 'HS256', 'ES256']`
- Rejects private keys (checks for `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`)
- HS256 shared secret minimum 32 characters
- JWKS cache is cleared when the URL changes

### View

`resources/views/config.phtml` — Bootstrap form for admin config. Registered under the `jwt-auth` view namespace in `boot()`.

## File Structure

```
jwt-auth/
├── JwtAuthModule.php              # Main module class (middleware + config)
├── module.php                     # Entry point (returns module instance)
├── composer.json                  # Package definition
├── phpunit.xml                    # Test configuration
├── build.sh                       # Release archive builder
├── Http/RequestHandlers/
│   ├── JwtConfigPage.php          # Admin config display (GET)
│   └── JwtConfigAction.php        # Admin config save (POST)
├── resources/views/
│   └── config.phtml               # Config form template
├── tests/
│   ├── bootstrap.php              # Autoloader + webtrees TestCase require
│   ├── JwtAuthModuleTest.php      # Middleware tests (T01-T70)
│   ├── JwtConfigPageTest.php      # Config page tests (T49-T52)
│   └── JwtConfigActionTest.php    # Config action tests (T41-T48)
├── docs/
│   ├── ARCHITECTURE.md            # Module lifecycle, flow diagrams
│   ├── CONFIGURATION.md           # Full settings reference
│   └── SECURITY.md                # Security model and recommendations
└── .github/workflows/release.yml  # Automated release on tag push
```

## Testing Patterns

Tests extend `Fisharebest\Webtrees\TestCase` which provides an in-memory SQLite database.

### Key conventions

- **Module DB name:** `_jwt-auth_` (webtrees convention: `_<dirname>_`)
- **DB registration required:** Tests must insert into the `module` table for `getPreference`/`setPreference` to work:
  ```php
  DB::table('module')->insertOrIgnore(['module_name' => '_jwt-auth_', 'status' => 'enabled']);
  ```
- **`module.php` uses `require_once`** to avoid class redeclaration when tests also autoload the class
- **`boot()` is called explicitly in `setUp()`** to register routes (previously done by `bootModules()` scanning `modules_v4/`)
- **Re-fetch users from DB** after middleware sets preferences (objects become stale)
- **Use `en-US` locale** in tests to avoid missing language file warnings
- **`viewResponse` requires `$title`** in layout data when using admin layout
- **RateLimitService** is stubbed in setUp to avoid rate limit interference

### Test organization

Tests are numbered covering:
- Token extraction (header, cookie, priority, skip logged-in)
- JWT validation (algorithms, signatures, claims)
- Authentication flow (session, preferences, failures)
- Config resolution (config.ini.php vs DB preferences)
- Config action validation (including JWKS URL validation and cache clearing)
- Config page rendering (including JWKS URL field)
- Module metadata
- Security (tampering, none algorithm, confusion attacks)
- Edge cases
- JWKS (keyset fetch, caching, key rotation, fallback, error handling)

## Webtrees Integration Context

### How webtrees discovers modules

`ModuleService` scans `modules_v4/*/module.php`, calls each file, and expects a `ModuleInterface` instance returned. The module's `boot()` method is called by the `BootModules` middleware during request processing.

### Module middleware

Any module implementing `MiddlewareInterface` is auto-discovered by `Router.php` via `ModuleService::findByInterface(MiddlewareInterface::class)`. Module middleware runs after `CheckCsrf` but before the final `RequestHandler`.

### Configuration storage

- **Module preferences** are stored in the `module_setting` DB table, accessed via `$module->getPreference()` / `$module->setPreference()`
- **`config.ini.php`** values are injected as request attributes by the `ReadConfigIni` middleware; access via `Validator::attributes($request)->string('key')`
- config.ini.php takes precedence over module preferences (for the 5 keys that support it)

### Services

Obtain services from the DI container: `Registry::container()->get(ServiceClass::class)`

Key services used by this module:
- `UserService` — find users by email
- `RateLimitService` — site-wide rate limiting
- `ModuleService` — find module instances by interface

### Coding style

- Constructor property promotion with `private readonly` and trailing commas
- PSR-12 coding standard
- Route auth via `->extras(['middleware' => [AuthAdministrator::class]])`
- `Auth::id()` returns `int|null` (null when not logged in)

## Releases

Tagging `v*` triggers `.github/workflows/release.yml` which:
1. Validates version format (`v*.*.*`)
2. Replaces `0.0.0-dev` in `JwtAuthModule.php` with the version number
3. Installs production dependencies (`--no-dev`)
4. Strips dev files (tests, docs, .git, build.sh, phpunit.xml, composer.json/lock)
5. Creates `jwt-auth-vX.X.X.tar.gz` with vendor/ included
6. Publishes a GitHub release

The workflow also supports `workflow_dispatch` for manual triggering with a version input.

Manual build: `./build.sh v1.0.0`
