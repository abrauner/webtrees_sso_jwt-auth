<?php

/**
 * JWT Authentication Module for webtrees
 * Copyright (C) 2025 Ansgar Schulze Everding
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

declare(strict_types=1);

namespace Anschev\JwtAuth;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Fisharebest\Webtrees\Auth;
use Fisharebest\Webtrees\Contracts\UserInterface;
use Fisharebest\Webtrees\Http\Middleware\AuthAdministrator;
use Fisharebest\Webtrees\I18N;
use Fisharebest\Webtrees\Log;
use Fisharebest\Webtrees\Module\AbstractModule;
use Fisharebest\Webtrees\Module\ModuleConfigInterface;
use Fisharebest\Webtrees\Module\ModuleConfigTrait;
use Fisharebest\Webtrees\Module\ModuleCustomInterface;
use Fisharebest\Webtrees\Module\ModuleCustomTrait;
use Fisharebest\Webtrees\Registry;
use Fisharebest\Webtrees\Services\RateLimitService;
use Fisharebest\Webtrees\Services\UserService;
use Fisharebest\Webtrees\Session;
use Fisharebest\Webtrees\Validator;
use Fisharebest\Webtrees\View;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Anschev\JwtAuth\Http\RequestHandlers\JwtConfigAction;
use Anschev\JwtAuth\Http\RequestHandlers\JwtConfigPage;

use function str_starts_with;
use function time;

/**
 * JWT Authentication Module
 *
 * Implements MiddlewareInterface to validate JWT tokens on every request.
 * Tokens are extracted from HTTP headers or cookies only (no query/POST).
 */
class JwtAuthModule extends AbstractModule implements ModuleCustomInterface, ModuleConfigInterface, MiddlewareInterface
{
    use ModuleCustomTrait;
    use ModuleConfigTrait;

    // Rate limiting: Allow 20 authentication attempts per 60 seconds site-wide
    // Note: max is intdiv(256, strlen(timestamp.',')) due to site_setting VARCHAR(256) storage
    private const JWT_AUTH_RATE_LIMIT_REQUESTS = 20;
    private const JWT_AUTH_RATE_LIMIT_SECONDS = 60;

    // JWKS cache TTL in seconds (1 hour)
    private const JWT_AUTH_JWKS_CACHE_TTL = 3600;

    /**
     * Bootstrap the module
     */
    public function boot(): void
    {
        // Register the view namespace so jwt-auth::config resolves
        View::registerNamespace('jwt-auth', __DIR__ . '/resources/views/');

        // Register configuration routes with AuthAdministrator middleware
        Registry::routeFactory()->routeMap()
            ->get(JwtConfigPage::class, '/admin/modules/jwt-auth/config', JwtConfigPage::class)
            ->extras(['middleware' => [AuthAdministrator::class]]);

        Registry::routeFactory()->routeMap()
            ->post(JwtConfigAction::class, '/admin/modules/jwt-auth/config', JwtConfigAction::class)
            ->extras(['middleware' => [AuthAdministrator::class]]);
    }

    /**
     * Module title
     */
    public function title(): string
    {
        return I18N::translate('JWT Authentication');
    }

    /**
     * Module description
     */
    public function description(): string
    {
        return I18N::translate('Authenticate users via JWT tokens');
    }

    /**
     * Module author
     */
    public function customModuleAuthorName(): string
    {
        return 'Ansgar Schulze Everding';
    }

    /**
     * Module version — replaced by release workflow; shows 'dev' in development
     */
    public function customModuleVersion(): string
    {
        return '0.0.0-dev';
    }

    /**
     * Module support URL
     */
    public function customModuleSupportUrl(): string
    {
        return 'https://github.com/abrauner/webtrees_sso_jwt-auth';
    }

    /**
     * Get the configuration URL for this module
     */
    public function getConfigLink(): string
    {
        return route(JwtConfigPage::class);
    }

    /**
     * PSR-15 middleware: check every request for a JWT token in headers/cookies.
     * If found and valid, authenticate the user. Always passes through to the next handler.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Skip if user is already logged in
        if (Auth::id() !== null) {
            return $handler->handle($request);
        }

        try {
            // Rate limiting: Prevent brute force attacks
            $rate_limit_service = Registry::container()->get(RateLimitService::class);
            $rate_limit_service->limitRateForSite(
                self::JWT_AUTH_RATE_LIMIT_REQUESTS,
                self::JWT_AUTH_RATE_LIMIT_SECONDS,
                'rate-limit-jwt-login',
            );

            // Extract JWT token from header or cookie only
            $token = $this->extractToken($request);

            if ($token === null) {
                Log::addAuthenticationLog('JWT: no token found in request');
                return $handler->handle($request);
            }

            // Get configuration
            $issuer = $this->getConfig($request, 'jwt_auth_issuer', 'JWT_AUTH_ISSUER');
            $audience = $this->getConfig($request, 'jwt_auth_audience', 'JWT_AUTH_AUDIENCE');
            $jwks_url = $this->getConfig($request, 'jwt_auth_jwks_url', 'JWT_AUTH_JWKS_URL');
            $public_key = $this->getPreference('JWT_AUTH_PUBLIC_KEY', '');

            if ($issuer === '' || $audience === '' || ($jwks_url === '' && $public_key === '')) {
                Log::addAuthenticationLog('JWT: missing config - issuer=' . ($issuer !== '' ? 'set' : 'empty') . ' audience=' . ($audience !== '' ? 'set' : 'empty') . ' key=' . ($jwks_url !== '' ? 'jwks' : ($public_key !== '' ? 'set' : 'empty')));
                return $handler->handle($request);
            }

            // Decode and validate JWT
            $decoded = $this->validateJwt($token, $issuer, $audience, $jwks_url);

            // Extract email from JWT
            $email = $decoded->email ?? null;
            if ($email === null) {
                Log::addAuthenticationLog('JWT login failed: no email in token');
                return $handler->handle($request);
            }

            // Find user by email
            $user_service = Registry::container()->get(UserService::class);
            $user = $user_service->findByEmail($email);

            if ($user === null) {
                Log::addAuthenticationLog('JWT login failed: user not found for email');
                return $handler->handle($request);
            }

            // Validate user account status
            if ($user->getPreference(UserInterface::PREF_IS_EMAIL_VERIFIED) !== '1') {
                Log::addAuthenticationLog('JWT login failed: email not verified for ' . $user->userName());
                return $handler->handle($request);
            }

            if ($user->getPreference(UserInterface::PREF_IS_ACCOUNT_APPROVED) !== '1') {
                Log::addAuthenticationLog('JWT login failed: account not approved for ' . $user->userName());
                return $handler->handle($request);
            }

            // Create session
            Auth::login($user);
            Log::addAuthenticationLog('JWT Login: ' . Auth::user()->userName() . '/' . Auth::user()->realName());
            Auth::user()->setPreference(UserInterface::PREF_TIMESTAMP_ACTIVE, (string) time());

            Session::put('language', Auth::user()->getPreference(UserInterface::PREF_LANGUAGE, 'en-US'));
            Session::put('theme', Auth::user()->getPreference(UserInterface::PREF_THEME));
            I18N::init(Auth::user()->getPreference(UserInterface::PREF_LANGUAGE, 'en-US'));

            // Update request attribute and DI container so downstream middleware/handlers
            // see the authenticated user. UseSession set GuestUser on the request earlier
            // in the global middleware stack, before our module middleware runs.
            $request = $request->withAttribute('user', $user);
            Registry::container()->set(UserInterface::class, $user);
        } catch (Exception $ex) {
            Log::addAuthenticationLog('JWT login failed: ' . $ex->getMessage());
        }

        return $handler->handle($request);
    }

    /**
     * Extract JWT token from request (header or cookie only)
     */
    private function extractToken(ServerRequestInterface $request): ?string
    {
        $priority = $this->getConfig($request, 'jwt_auth_source_priority', 'JWT_AUTH_SOURCE_PRIORITY') ?: 'header,cookie';
        $sources = explode(',', $priority);

        foreach ($sources as $source) {
            $token = match (trim($source)) {
                'header' => $this->extractFromHeader($request),
                'cookie' => $this->extractFromCookie($request),
                default  => null,
            };

            if ($token !== null && $token !== '') {
                return $token;
            }
        }

        return null;
    }

    /**
     * Extract token from Authorization header or custom header
     */
    private function extractFromHeader(ServerRequestInterface $request): ?string
    {
        $header_name = $this->getConfig($request, 'jwt_auth_header_name', 'JWT_AUTH_HEADER_NAME') ?: 'Authorization';
        $header_value = $request->getHeaderLine($header_name);

        if ($header_value !== '') {
            if (str_starts_with($header_value, 'Bearer ')) {
                return substr($header_value, 7);
            }
            return $header_value;
        }

        return null;
    }

    /**
     * Extract token from cookie
     */
    private function extractFromCookie(ServerRequestInterface $request): ?string
    {
        $cookie_name = $this->getConfig($request, 'jwt_auth_cookie_name', 'JWT_AUTH_COOKIE_NAME') ?: 'jwt_token';
        $cookies = $request->getCookieParams();

        return $cookies[$cookie_name] ?? null;
    }

    /**
     * Get configuration value from config.ini.php or module preferences
     */
    private function getConfig(ServerRequestInterface $request, string $configKey, string $preferenceKey): string
    {
        // First try config.ini.php
        $value = Validator::attributes($request)->string($configKey, '');

        // Fall back to module preferences
        if ($value === '') {
            $value = $this->getPreference($preferenceKey, '');
        }

        return $value;
    }

    /**
     * Validate JWT token
     */
    private function validateJwt(string $token, string $issuer, string $audience, string $jwksUrl = ''): object
    {
        try {
            if ($jwksUrl !== '') {
                $decoded = $this->decodeWithJwks($token, $jwksUrl);
            } else {
                $public_key = $this->getPreference('JWT_AUTH_PUBLIC_KEY', '');
                $algorithm = $this->getPreference('JWT_AUTH_ALGORITHM', 'RS256');
                $decoded = JWT::decode($token, new Key($public_key, $algorithm));
            }

            // Verify issuer
            if (!isset($decoded->iss) || $decoded->iss !== $issuer) {
                throw new Exception('Invalid issuer');
            }

            // Verify audience (can be array or string)
            $aud = $decoded->aud ?? null;
            if ($aud === null) {
                throw new Exception('Invalid audience');
            }
            $token_audiences = is_array($aud) ? $aud : [$aud];
            if (!in_array($audience, $token_audiences, true)) {
                throw new Exception('Invalid audience');
            }

            return $decoded;
        } catch (Exception $e) {
            throw new Exception('JWT validation failed: ' . $e->getMessage());
        }
    }

    /**
     * Decode JWT using JWKS keyset, with automatic key rotation handling.
     * If the kid from the token is not found in the cached keyset, refresh and retry once.
     */
    private function decodeWithJwks(string $token, string $jwksUrl): object
    {
        $keyset = $this->getJwksKeyset($jwksUrl);

        try {
            return JWT::decode($token, $keyset);
        } catch (SignatureInvalidException $e) {
            throw $e;
        } catch (Exception $e) {
            // If kid not found or key mismatch, refresh cache and retry once
            if (str_contains($e->getMessage(), '"kid" invalid') || str_contains($e->getMessage(), 'unable to lookup correct key')) {
                $keyset = $this->getJwksKeyset($jwksUrl, forceRefresh: true);
                return JWT::decode($token, $keyset);
            }
            throw $e;
        }
    }

    /**
     * Get JWKS keyset, using cache when available and fresh.
     *
     * @return array<string, Key>
     */
    private function getJwksKeyset(string $jwksUrl, bool $forceRefresh = false): array
    {
        if (!$forceRefresh) {
            $cached = $this->getCachedJwksKeyset();
            if ($cached !== null) {
                return $cached;
            }
        }

        return $this->fetchAndCacheJwks($jwksUrl);
    }

    /**
     * Return cached JWKS keyset if cache is fresh, null otherwise.
     *
     * @return array<string, Key>|null
     */
    private function getCachedJwksKeyset(): ?array
    {
        $cachedJson = $this->getPreference('JWT_AUTH_JWKS_CACHE', '');
        $cachedTimestamp = (int) $this->getPreference('JWT_AUTH_JWKS_CACHE_TIMESTAMP', '0');

        if ($cachedJson === '' || $cachedTimestamp === 0) {
            return null;
        }

        if ((time() - $cachedTimestamp) >= self::JWT_AUTH_JWKS_CACHE_TTL) {
            return null;
        }

        $jwks = json_decode($cachedJson, true);
        if (!is_array($jwks) || !isset($jwks['keys'])) {
            return null;
        }

        return JWK::parseKeySet($jwks);
    }

    /**
     * Fetch JWKS from URL, parse, and cache in module preferences.
     *
     * @return array<string, Key>
     */
    private function fetchAndCacheJwks(string $jwksUrl): array
    {
        $json = $this->fetchJwksJson($jwksUrl);
        if ($json === '') {
            throw new Exception('Failed to fetch JWKS from ' . $jwksUrl);
        }

        $jwks = json_decode($json, true);
        if (!is_array($jwks) || !isset($jwks['keys'])) {
            throw new Exception('Invalid JWKS response from ' . $jwksUrl);
        }

        $keyset = JWK::parseKeySet($jwks);

        $this->setPreference('JWT_AUTH_JWKS_CACHE', $json);
        $this->setPreference('JWT_AUTH_JWKS_CACHE_TIMESTAMP', (string) time());

        return $keyset;
    }

    /**
     * Fetch raw JWKS JSON from a URL. Protected so tests can override without real HTTP.
     */
    protected function fetchJwksJson(string $url): string
    {
        $context = stream_context_create([
            'http' => [
                'timeout' => 10,
            ],
            'ssl' => [
                'verify_peer'      => true,
                'verify_peer_name' => true,
            ],
        ]);

        $result = @file_get_contents($url, false, $context);

        return $result !== false ? $result : '';
    }
}
