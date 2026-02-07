<?php

declare(strict_types=1);

namespace Anschev\JwtAuth\Tests;

use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Fisharebest\Webtrees\DB;
use Fisharebest\Webtrees\FlashMessages;
use Fisharebest\Webtrees\Registry;
use Fisharebest\Webtrees\Services\ModuleService;
use Fisharebest\Webtrees\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Anschev\JwtAuth\Http\RequestHandlers\JwtConfigAction;
use Anschev\JwtAuth\Http\RequestHandlers\JwtConfigPage;
use Anschev\JwtAuth\JwtAuthModule;

#[CoversClass(JwtConfigAction::class)]
class JwtConfigActionTest extends TestCase
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

        // Register module in the container so ModuleService can find it
        $module_service = self::createStub(ModuleService::class);
        $module_service->method('findByInterface')
            ->willReturn(collect([$this->module]));
        Registry::container()->set(ModuleService::class, $module_service);

        // Register routes (previously done by bootModules() scanning modules_v4/)
        $this->module->boot();
    }

    // -------------------------------------------------------------------------
    // T41-T48: Configuration Save & Validation
    // -------------------------------------------------------------------------

    public function testSaveValidConfiguration(): void
    {
        // T41: Valid config should be saved successfully
        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_public_key'    => 'a-shared-secret-that-is-at-least-32-characters-long!',
            'jwt_auth_algorithm'     => 'HS256',
            'source_header'     => '1',
            'source_cookie'     => '1',
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        self::assertSame('https://issuer.example.com', $this->module->getPreference('JWT_AUTH_ISSUER'));
        self::assertSame('test-audience', $this->module->getPreference('JWT_AUTH_AUDIENCE'));
        self::assertSame('HS256', $this->module->getPreference('JWT_AUTH_ALGORITHM'));
        self::assertSame('header,cookie', $this->module->getPreference('JWT_AUTH_SOURCE_PRIORITY'));
    }

    public function testSaveRs256Configuration(): void
    {
        // T42: RS256 config with public key
        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----";

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_public_key'    => $publicKey,
            'jwt_auth_algorithm'     => 'RS256',
            'source_header'     => '1',
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        self::assertSame($publicKey, $this->module->getPreference('JWT_AUTH_PUBLIC_KEY'));
        self::assertSame('RS256', $this->module->getPreference('JWT_AUTH_ALGORITHM'));
    }

    public function testRejectInvalidAlgorithm(): void
    {
        // T43: Algorithm not in allowlist should be rejected
        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_public_key'    => 'some-key',
            'jwt_auth_algorithm'     => 'none',
            'source_header'     => '1',
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());

        // Should have a danger flash message
        $messages = FlashMessages::getMessages();
        self::assertNotEmpty($messages);
        self::assertSame('danger', $messages[0]->status);
    }

    public function testRejectPrivateKey(): void
    {
        // T44: Private key should be rejected
        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_public_key'    => "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhki...\n-----END PRIVATE KEY-----",
            'jwt_auth_algorithm'     => 'RS256',
            'source_header'     => '1',
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());

        $messages = FlashMessages::getMessages();
        self::assertNotEmpty($messages);
        self::assertSame('danger', $messages[0]->status);
    }

    public function testRejectRsaPrivateKey(): void
    {
        // T45: RSA private key should be rejected
        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_public_key'    => "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
            'jwt_auth_algorithm'     => 'RS256',
            'source_header'     => '1',
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());

        $messages = FlashMessages::getMessages();
        self::assertNotEmpty($messages);
        self::assertSame('danger', $messages[0]->status);
    }

    public function testRejectEcPrivateKey(): void
    {
        // T46: EC private key should be rejected
        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_public_key'    => "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEICQ...\n-----END EC PRIVATE KEY-----",
            'jwt_auth_algorithm'     => 'ES256',
            'source_header'     => '1',
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());

        $messages = FlashMessages::getMessages();
        self::assertNotEmpty($messages);
        self::assertSame('danger', $messages[0]->status);
    }

    public function testRejectShortHs256Secret(): void
    {
        // T47: HS256 secret shorter than 32 characters should be rejected
        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_public_key'    => 'short',
            'jwt_auth_algorithm'     => 'HS256',
            'source_header'     => '1',
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());

        $messages = FlashMessages::getMessages();
        self::assertNotEmpty($messages);
        self::assertSame('danger', $messages[0]->status);
    }

    public function testHeaderOnlySourcePriority(): void
    {
        // T48: Only header checkbox selected
        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_public_key'    => 'a-shared-secret-that-is-at-least-32-characters-long!',
            'jwt_auth_algorithm'     => 'HS256',
            'source_header'     => '1',
            // source_cookie NOT set
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        self::assertSame('header', $this->module->getPreference('JWT_AUTH_SOURCE_PRIORITY'));
    }

    // -------------------------------------------------------------------------
    // JWKS URL Configuration Tests
    // -------------------------------------------------------------------------

    public function testSaveJwksUrl(): void
    {
        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_jwks_url'          => 'https://issuer.example.com/.well-known/jwks.json',
            'jwt_auth_public_key'    => '',
            'jwt_auth_algorithm'     => 'RS256',
            'source_header'     => '1',
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        self::assertSame('https://issuer.example.com/.well-known/jwks.json', $this->module->getPreference('JWT_AUTH_JWKS_URL'));
    }

    public function testRejectHttpJwksUrl(): void
    {
        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_jwks_url'          => 'http://issuer.example.com/.well-known/jwks.json',
            'jwt_auth_public_key'    => '',
            'jwt_auth_algorithm'     => 'RS256',
            'source_header'     => '1',
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());

        $messages = FlashMessages::getMessages();
        self::assertNotEmpty($messages);
        self::assertSame('danger', $messages[0]->status);
    }

    public function testRejectInvalidJwksUrl(): void
    {
        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_jwks_url'          => 'https://',
            'jwt_auth_public_key'    => '',
            'jwt_auth_algorithm'     => 'RS256',
            'source_header'     => '1',
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());

        $messages = FlashMessages::getMessages();
        self::assertNotEmpty($messages);
        self::assertSame('danger', $messages[0]->status);
    }

    public function testJwksCacheClearedOnUrlChange(): void
    {
        // Pre-set existing JWKS URL and cache
        $this->module->setPreference('JWT_AUTH_JWKS_URL', 'https://old-issuer.example.com/.well-known/jwks.json');
        $this->module->setPreference('JWT_AUTH_JWKS_CACHE', '{"keys":[]}');
        $this->module->setPreference('JWT_AUTH_JWKS_CACHE_TIMESTAMP', (string) time());

        $handler = new JwtConfigAction(
            Registry::container()->get(ModuleService::class),
        );

        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], [
            'jwt_auth_issuer'        => 'https://issuer.example.com',
            'jwt_auth_audience'      => 'test-audience',
            'jwt_auth_jwks_url'          => 'https://new-issuer.example.com/.well-known/jwks.json',
            'jwt_auth_public_key'    => '',
            'jwt_auth_algorithm'     => 'RS256',
            'source_header'     => '1',
            'jwt_auth_header_name' => 'Authorization',
            'jwt_auth_cookie_name' => 'jwt_token',
        ]);

        $response = $handler->handle($request);

        self::assertSame(StatusCodeInterface::STATUS_FOUND, $response->getStatusCode());
        self::assertSame('https://new-issuer.example.com/.well-known/jwks.json', $this->module->getPreference('JWT_AUTH_JWKS_URL'));
        self::assertSame('', $this->module->getPreference('JWT_AUTH_JWKS_CACHE'));
        self::assertSame('', $this->module->getPreference('JWT_AUTH_JWKS_CACHE_TIMESTAMP'));
    }
}
