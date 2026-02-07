<?php

declare(strict_types=1);

namespace Anschev\JwtAuth\Tests;

use Fig\Http\Message\StatusCodeInterface;
use Fisharebest\Webtrees\DB;
use Fisharebest\Webtrees\I18N;
use Fisharebest\Webtrees\Registry;
use Fisharebest\Webtrees\Services\ModuleService;
use Fisharebest\Webtrees\TestCase;
use Fisharebest\Webtrees\View;
use PHPUnit\Framework\Attributes\CoversClass;
use Anschev\JwtAuth\Http\RequestHandlers\JwtConfigPage;
use Anschev\JwtAuth\JwtAuthModule;

#[CoversClass(JwtConfigPage::class)]
class JwtConfigPageTest extends TestCase
{
    protected static bool $uses_database = true;

    private const string MODULE_NAME = '_jwt-auth_';

    private JwtAuthModule $module;

    protected function setUp(): void
    {
        parent::setUp();

        $this->module = new JwtAuthModule();
        $this->module->setName(self::MODULE_NAME);

        // Register the module in the database
        DB::table('module')->insertOrIgnore([
            'module_name' => self::MODULE_NAME,
            'status'      => 'enabled',
        ]);

        // Set default preferences
        $this->module->setPreference('JWT_AUTH_ISSUER', 'https://issuer.example.com');
        $this->module->setPreference('JWT_AUTH_AUDIENCE', 'test-audience');
        $this->module->setPreference('JWT_AUTH_PUBLIC_KEY', 'test-public-key-at-least-32-characters!');
        $this->module->setPreference('JWT_AUTH_ALGORITHM', 'RS256');
        $this->module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'header,cookie');
        $this->module->setPreference('JWT_AUTH_HEADER_NAME', 'Authorization');
        $this->module->setPreference('JWT_AUTH_COOKIE_NAME', 'jwt_token');

        // Register view namespace for the module template
        View::registerNamespace('jwt-auth', dirname(__DIR__) . '/resources/views/');

        // Register routes (previously done by bootModules() scanning modules_v4/)
        $this->module->boot();
    }

    // -------------------------------------------------------------------------
    // T49-T52: Config Page Rendering
    // -------------------------------------------------------------------------

    public function testConfigPageRendersSuccessfully(): void
    {
        // T49: Config page should render with 200 status
        $module_service = self::createStub(ModuleService::class);
        $module_service->method('findByInterface')
            ->willReturn(collect([$this->module]));

        $handler = new JwtConfigPage($module_service);
        $request = self::createRequest();
        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testConfigPageContainsFormFields(): void
    {
        // T50: Config page should contain the expected form fields
        $module_service = self::createStub(ModuleService::class);
        $module_service->method('findByInterface')
            ->willReturn(collect([$this->module]));

        $handler = new JwtConfigPage($module_service);
        $request = self::createRequest();
        $response = $handler->handle($request);

        $html = $response->getBody()->getContents();

        self::assertStringContainsString('jwt_auth_issuer', $html);
        self::assertStringContainsString('jwt_auth_audience', $html);
        self::assertStringContainsString('jwt_auth_public_key', $html);
        self::assertStringContainsString('jwt_auth_algorithm', $html);
        self::assertStringContainsString('jwt_auth_header_name', $html);
        self::assertStringContainsString('jwt_auth_cookie_name', $html);
    }

    public function testConfigPageShowsCurrentValues(): void
    {
        // T51: Config page should display current preference values
        $module_service = self::createStub(ModuleService::class);
        $module_service->method('findByInterface')
            ->willReturn(collect([$this->module]));

        $handler = new JwtConfigPage($module_service);
        $request = self::createRequest();
        $response = $handler->handle($request);

        $html = $response->getBody()->getContents();

        self::assertStringContainsString('https://issuer.example.com', $html);
        self::assertStringContainsString('test-audience', $html);
    }

    public function testConfigPageWhenModuleNotFound(): void
    {
        // T52: When module not found, should show error
        $module_service = self::createStub(ModuleService::class);
        $module_service->method('findByInterface')
            ->willReturn(collect([]));

        $handler = new JwtConfigPage($module_service);
        $request = self::createRequest();
        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
        $html = $response->getBody()->getContents();
        self::assertStringContainsString('JWT Auth module not found', $html);
    }

    public function testConfigPageContainsJwksUrlField(): void
    {
        $module_service = self::createStub(ModuleService::class);
        $module_service->method('findByInterface')
            ->willReturn(collect([$this->module]));

        $handler = new JwtConfigPage($module_service);
        $request = self::createRequest();
        $response = $handler->handle($request);

        $html = $response->getBody()->getContents();

        self::assertStringContainsString('jwt_auth_jwks_url', $html);
    }
}
