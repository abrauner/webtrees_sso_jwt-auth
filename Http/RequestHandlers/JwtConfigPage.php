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

use Fisharebest\Webtrees\Http\ViewResponseTrait;
use Fisharebest\Webtrees\I18N;
use Fisharebest\Webtrees\Services\ModuleService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Anschev\JwtAuth\JwtAuthModule;

/**
 * Display JWT authentication configuration page
 */
final class JwtConfigPage implements RequestHandlerInterface
{
    use ViewResponseTrait;

    public function __construct(
        private readonly ModuleService $module_service,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->layout = 'layouts/administration';

        $module = $this->module_service->findByInterface(JwtAuthModule::class)->first();

        if ($module === null) {
            return $this->viewResponse('components/alert-danger', [
                'title' => I18N::translate('JWT Authentication Configuration'),
                'alert' => I18N::translate('JWT Auth module not found'),
            ]);
        }

        return $this->viewResponse('jwt-auth::config', [
            'title'                  => I18N::translate('JWT Authentication Configuration'),
            'module'                 => $module,
            'jwt_auth_issuer'        => $module->getPreference('JWT_AUTH_ISSUER', ''),
            'jwt_auth_audience'      => $module->getPreference('JWT_AUTH_AUDIENCE', ''),
            'jwt_auth_jwks_url'      => $module->getPreference('JWT_AUTH_JWKS_URL', ''),
            'jwt_auth_public_key'    => $module->getPreference('JWT_AUTH_PUBLIC_KEY', ''),
            'jwt_auth_algorithm'     => $module->getPreference('JWT_AUTH_ALGORITHM', 'RS256'),
            'jwt_auth_source_priority' => $module->getPreference('JWT_AUTH_SOURCE_PRIORITY', 'header,cookie'),
            'jwt_auth_header_name'   => $module->getPreference('JWT_AUTH_HEADER_NAME', 'Authorization'),
            'jwt_auth_cookie_name'   => $module->getPreference('JWT_AUTH_COOKIE_NAME', 'jwt_token'),
        ]);
    }
}
