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

namespace Anschev\JwtAuth\Http\RequestHandlers;

use Fisharebest\Webtrees\FlashMessages;
use Fisharebest\Webtrees\I18N;
use Fisharebest\Webtrees\Services\ModuleService;
use Fisharebest\Webtrees\Validator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Anschev\JwtAuth\JwtAuthModule;

use function filter_var;
use function redirect;
use function route;
use function str_contains;
use function str_starts_with;
use function strlen;

/**
 * Save JWT authentication configuration
 */
final readonly class JwtConfigAction implements RequestHandlerInterface
{
    private const ALLOWED_ALGORITHMS = ['RS256', 'HS256', 'ES256'];
    private const HS256_MIN_KEY_LENGTH = 32;

    public function __construct(
        private readonly ModuleService $module_service,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $module = $this->module_service->findByInterface(JwtAuthModule::class)->first();

        if ($module === null) {
            FlashMessages::addMessage(I18N::translate('JWT Auth module not found'), 'danger');
            return redirect(route('admin-control-panel'));
        }

        // Get form values
        $jwt_auth_issuer = Validator::parsedBody($request)->string('jwt_auth_issuer', '');
        $jwt_auth_audience = Validator::parsedBody($request)->string('jwt_auth_audience', '');
        $jwt_auth_jwks_url = Validator::parsedBody($request)->string('jwt_auth_jwks_url', '');
        $jwt_auth_public_key = Validator::parsedBody($request)->string('jwt_auth_public_key', '');
        $jwt_auth_algorithm = Validator::parsedBody($request)->string('jwt_auth_algorithm', 'RS256');
        $jwt_auth_header_name = Validator::parsedBody($request)->string('jwt_auth_header_name', 'Authorization');
        $jwt_auth_cookie_name = Validator::parsedBody($request)->string('jwt_auth_cookie_name', 'jwt_token');

        // Validate JWKS URL
        if ($jwt_auth_jwks_url !== '') {
            if (!str_starts_with($jwt_auth_jwks_url, 'https://')) {
                FlashMessages::addMessage(I18N::translate('The JWKS URL must use HTTPS.'), 'danger');
                return redirect(route(JwtConfigPage::class));
            }
            if (filter_var($jwt_auth_jwks_url, FILTER_VALIDATE_URL) === false) {
                FlashMessages::addMessage(I18N::translate('The JWKS URL is not a valid URL.'), 'danger');
                return redirect(route(JwtConfigPage::class));
            }
        }

        // Skip algorithm/key validation when JWKS URL is set (keys come from the endpoint)
        if ($jwt_auth_jwks_url === '') {
            // Validate algorithm against allowlist
            if (!in_array($jwt_auth_algorithm, self::ALLOWED_ALGORITHMS, true)) {
                FlashMessages::addMessage(I18N::translate('Invalid algorithm selected.'), 'danger');
                return redirect(route(JwtConfigPage::class));
            }

            // Validate public key
            if ($jwt_auth_public_key !== '') {
                // Reject private keys
                if (str_contains($jwt_auth_public_key, 'BEGIN PRIVATE KEY') || str_contains($jwt_auth_public_key, 'BEGIN RSA PRIVATE KEY') || str_contains($jwt_auth_public_key, 'BEGIN EC PRIVATE KEY')) {
                    FlashMessages::addMessage(I18N::translate('Private keys must not be stored here. Please provide a public key or shared secret only.'), 'danger');
                    return redirect(route(JwtConfigPage::class));
                }

                // For HS256, enforce minimum key length
                if ($jwt_auth_algorithm === 'HS256' && strlen($jwt_auth_public_key) < self::HS256_MIN_KEY_LENGTH) {
                    FlashMessages::addMessage(I18N::translate('The HS256 shared secret must be at least %s characters long.', (string) self::HS256_MIN_KEY_LENGTH), 'danger');
                    return redirect(route(JwtConfigPage::class));
                }
            }
        }

        // Build token source priority from checkboxes (header/cookie only)
        $sources = [];
        if (Validator::parsedBody($request)->string('source_header', '') !== '') {
            $sources[] = 'header';
        }
        if (Validator::parsedBody($request)->string('source_cookie', '') !== '') {
            $sources[] = 'cookie';
        }
        $jwt_auth_source_priority = implode(',', $sources);

        // Clear JWKS cache when URL changes
        $old_jwks_url = $module->getPreference('JWT_AUTH_JWKS_URL', '');
        if ($jwt_auth_jwks_url !== $old_jwks_url) {
            $module->setPreference('JWT_AUTH_JWKS_CACHE', '');
            $module->setPreference('JWT_AUTH_JWKS_CACHE_TIMESTAMP', '');
        }

        // Save preferences
        $module->setPreference('JWT_AUTH_ISSUER', $jwt_auth_issuer);
        $module->setPreference('JWT_AUTH_AUDIENCE', $jwt_auth_audience);
        $module->setPreference('JWT_AUTH_JWKS_URL', $jwt_auth_jwks_url);
        $module->setPreference('JWT_AUTH_PUBLIC_KEY', $jwt_auth_public_key);
        $module->setPreference('JWT_AUTH_ALGORITHM', $jwt_auth_algorithm);
        $module->setPreference('JWT_AUTH_SOURCE_PRIORITY', $jwt_auth_source_priority);
        $module->setPreference('JWT_AUTH_HEADER_NAME', $jwt_auth_header_name);
        $module->setPreference('JWT_AUTH_COOKIE_NAME', $jwt_auth_cookie_name);

        FlashMessages::addMessage(I18N::translate('The preferences for the module "%s" have been updated.', $module->title()), 'success');

        return redirect(route(JwtConfigPage::class));
    }
}
