# Copilot Instructions

## Project Overview

**webtrees-jwt-auth** is a PHP custom module for [webtrees](https://webtrees.net/) (v2.1.x) that authenticates users via JWT tokens. It runs as PSR-15 middleware on every request, extracting tokens from HTTP headers or cookies, validating them, and creating a webtrees session for the matched user.

- **Namespace:** `Anschev\JwtAuth`
- **PHP:** ^8.3
- **Key dependency:** `firebase/php-jwt` ^6.10
- **License:** GPL-3.0-or-later

## Development Setup

```bash
composer install          # Install all dependencies (including webtrees + PHPUnit)
vendor/bin/phpunit        # Run all tests (85 tests)
```

Always run `composer install` before building or testing. Webtrees is installed from source (not dist) so its `tests/TestCase.php` is available.

## File Layout

| Path | Purpose |
|---|---|
| `module.php` | Entry point loaded by webtrees module scanner |
| `JwtAuthModule.php` | Core class — middleware `process()`, config resolution, token extraction |
| `Http/RequestHandlers/JwtConfigPage.php` | GET handler for admin config page |
| `Http/RequestHandlers/JwtConfigAction.php` | POST handler for saving admin config |
| `resources/views/config.phtml` | Bootstrap admin config form template |
| `tests/JwtAuthModuleTest.php` | Middleware tests (T01–T70) |
| `tests/JwtConfigPageTest.php` | Config page tests (T49–T52) |
| `tests/JwtConfigActionTest.php` | Config action tests (T41–T48) |
| `tests/bootstrap.php` | Test autoloader + webtrees TestCase require |
| `docs/` | ARCHITECTURE.md, CONFIGURATION.md, SECURITY.md |
| `.github/workflows/release.yml` | Automated release on tag push |

## Coding Conventions

- **PSR-12** coding standard with strict types (`declare(strict_types=1);`)
- Constructor property promotion with `private readonly` and trailing commas
- Type declarations for all parameters and return values
- Access services via `Registry::container()->get(ServiceClass::class)`
- Use `Validator::attributes($request)->string()` for config.ini.php values
- Use `$this->getPreference()` / `$this->setPreference()` for DB preferences
- Route authorization via `->extras(['middleware' => [AuthAdministrator::class]])`

## Testing Conventions

All tests extend `Fisharebest\Webtrees\TestCase` (in-memory SQLite database).

Key patterns every test must follow:
- Register the module in DB before using preferences:
  ```php
  DB::table('module')->insertOrIgnore(['module_name' => '_jwt-auth_', 'status' => 'enabled']);
  ```
- Call `boot()` explicitly in `setUp()` to register routes
- Use `en-US` locale to avoid missing language file warnings
- Stub `RateLimitService` in setUp to avoid rate limit interference
- Re-fetch users from DB after middleware sets preferences (objects become stale)
- When using `viewResponse`, always include `$title` in layout data

## Architecture Notes

- `JwtAuthModule` implements `ModuleCustomInterface`, `ModuleConfigInterface`, and `MiddlewareInterface`
- The middleware never blocks requests on failure — it logs and passes through to the next handler
- Config resolution: `config.ini.php` attributes override DB preferences for issuer, audience, JWKS URL, header name, cookie name, and source priority
- `JWT_AUTH_PUBLIC_KEY` and `JWT_AUTH_ALGORITHM` are always DB-only preferences
- JWKS keyset is cached for 1 hour via `JWT_AUTH_JWKS_CACHE` / `JWT_AUTH_JWKS_CACHE_TIMESTAMP` DB preferences
- The module DB name is `_jwt-auth_` (webtrees convention: `_<dirname>_`)
- Version string `0.0.0-dev` in `JwtAuthModule.php` is replaced at release time by the build process

## Security Considerations

- Algorithm must be one of `RS256`, `HS256`, `ES256`
- JWKS URL must use HTTPS
- Private keys are rejected (checks for `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`)
- HS256 shared secret minimum 32 characters
- Rate limiting: 20 attempts / 60s site-wide
- Never expose JWT validation errors to end users — log them only
