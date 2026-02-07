<?php

declare(strict_types=1);

namespace Anschev\JwtAuth\Tests;

use Exception;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Fisharebest\Webtrees\Auth;
use Fisharebest\Webtrees\Contracts\UserInterface;
use Fisharebest\Webtrees\DB;
use Fisharebest\Webtrees\I18N;
use Fisharebest\Webtrees\Registry;
use Fisharebest\Webtrees\Services\RateLimitService;
use Fisharebest\Webtrees\Services\UserService;
use Fisharebest\Webtrees\Session;
use Fisharebest\Webtrees\TestCase;
use Fisharebest\Webtrees\User;
use Fisharebest\Webtrees\Validator;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Anschev\JwtAuth\JwtAuthModule;

use function time;

#[CoversClass(JwtAuthModule::class)]
class JwtAuthModuleTest extends TestCase
{
    protected static bool $uses_database = true;

    private const string MODULE_NAME = '_jwt-auth_';
    private const string HS256_SECRET = 'this-is-a-test-secret-key-at-least-32-chars!';
    private const string ISSUER = 'https://test-issuer.example.com';
    private const string AUDIENCE = 'test-audience';

    private JwtAuthModule $module;

    protected function setUp(): void
    {
        parent::setUp();

        $this->module = new JwtAuthModule();
        $this->module->setName(self::MODULE_NAME);

        // Register the module in the database so getPreference/setPreference work
        DB::table('module')->insertOrIgnore([
            'module_name' => self::MODULE_NAME,
            'status'      => 'enabled',
        ]);

        // Register a no-op RateLimitService mock in the container
        $rate_limit_service = self::createStub(RateLimitService::class);
        Registry::container()->set(RateLimitService::class, $rate_limit_service);

        // Register routes (previously done by bootModules() scanning modules_v4/)
        $this->module->boot();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function createHs256Token(array $payload, string $secret = self::HS256_SECRET): string
    {
        return JWT::encode($payload, $secret, 'HS256');
    }

    private function createRs256Token(array $payload, string $privateKey): string
    {
        return JWT::encode($payload, $privateKey, 'RS256');
    }

    private function createEs256Token(array $payload, string $privateKey): string
    {
        return JWT::encode($payload, $privateKey, 'ES256');
    }

    /**
     * Generate an RSA key pair for testing.
     *
     * @return array{private: string, public: string}
     */
    private function generateRsaKeyPair(): array
    {
        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $key = openssl_pkey_new($config);
        openssl_pkey_export($key, $privateKey);
        $details = openssl_pkey_get_details($key);

        return [
            'private' => $privateKey,
            'public'  => $details['key'],
        ];
    }

    /**
     * Generate an EC key pair for testing.
     *
     * @return array{private: string, public: string}
     */
    private function generateEcKeyPair(): array
    {
        $config = [
            'curve_name'       => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ];
        $key = openssl_pkey_new($config);
        openssl_pkey_export($key, $privateKey);
        $details = openssl_pkey_get_details($key);

        return [
            'private' => $privateKey,
            'public'  => $details['key'],
        ];
    }

    private function standardPayload(array $overrides = []): array
    {
        return array_merge([
            'iss'   => self::ISSUER,
            'aud'   => self::AUDIENCE,
            'email' => 'test@example.com',
            'iat'   => time(),
            'exp'   => time() + 3600,
        ], $overrides);
    }

    private function configureModuleForHs256(): void
    {
        $this->module->setPreference('JWT_AUTH_ISSUER', self::ISSUER);
        $this->module->setPreference('JWT_AUTH_AUDIENCE', self::AUDIENCE);
        $this->module->setPreference('JWT_AUTH_PUBLIC_KEY', self::HS256_SECRET);
        $this->module->setPreference('JWT_AUTH_ALGORITHM', 'HS256');
        $this->module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'header,cookie');
        $this->module->setPreference('JWT_AUTH_HEADER_NAME', 'Authorization');
        $this->module->setPreference('JWT_AUTH_COOKIE_NAME', 'jwt_token');
    }

    private function configureModuleForRs256(string $publicKey): void
    {
        $this->module->setPreference('JWT_AUTH_ISSUER', self::ISSUER);
        $this->module->setPreference('JWT_AUTH_AUDIENCE', self::AUDIENCE);
        $this->module->setPreference('JWT_AUTH_PUBLIC_KEY', $publicKey);
        $this->module->setPreference('JWT_AUTH_ALGORITHM', 'RS256');
        $this->module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'header,cookie');
        $this->module->setPreference('JWT_AUTH_HEADER_NAME', 'Authorization');
        $this->module->setPreference('JWT_AUTH_COOKIE_NAME', 'jwt_token');
    }

    private function configureModuleForEs256(string $publicKey): void
    {
        $this->module->setPreference('JWT_AUTH_ISSUER', self::ISSUER);
        $this->module->setPreference('JWT_AUTH_AUDIENCE', self::AUDIENCE);
        $this->module->setPreference('JWT_AUTH_PUBLIC_KEY', $publicKey);
        $this->module->setPreference('JWT_AUTH_ALGORITHM', 'ES256');
        $this->module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'header,cookie');
        $this->module->setPreference('JWT_AUTH_HEADER_NAME', 'Authorization');
        $this->module->setPreference('JWT_AUTH_COOKIE_NAME', 'jwt_token');
    }

    private function createVerifiedUser(string $email = 'test@example.com', string $userName = 'testuser'): User
    {
        $user_service = new UserService();
        $user = $user_service->create($userName, 'Test User', $email, 'password123');
        $user->setPreference(UserInterface::PREF_IS_EMAIL_VERIFIED, '1');
        $user->setPreference(UserInterface::PREF_IS_ACCOUNT_APPROVED, '1');

        return $user;
    }

    private function createStubHandler(?ResponseInterface $response = null): RequestHandlerInterface
    {
        if ($response === null) {
            $response = self::createStub(ResponseInterface::class);
            $response->method('getStatusCode')->willReturn(StatusCodeInterface::STATUS_OK);
        }

        $handler = self::createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        return $handler;
    }

    private function buildRequestWithHeader(string $headerName, string $headerValue): ServerRequestInterface
    {
        $request = self::createRequest();

        return $request->withHeader($headerName, $headerValue);
    }

    private function buildRequestWithCookie(string $cookieName, string $cookieValue): ServerRequestInterface
    {
        $request = self::createRequest();

        return $request->withCookieParams([$cookieName => $cookieValue]);
    }

    // -------------------------------------------------------------------------
    // T53-T57: Module Metadata
    // -------------------------------------------------------------------------

    public function testModuleTitle(): void
    {
        // T53
        self::assertNotEmpty($this->module->title());
    }

    public function testModuleDescription(): void
    {
        // T54
        self::assertNotEmpty($this->module->description());
    }

    public function testModuleVersion(): void
    {
        // T55
        self::assertSame('0.0.0-dev', $this->module->customModuleVersion());
    }

    public function testModuleImplementsMiddlewareInterface(): void
    {
        // T56
        self::assertInstanceOf(MiddlewareInterface::class, $this->module);
    }

    public function testBootRegistersRoutes(): void
    {
        // T57: boot() is called in setUp().
        // Verify the routes were registered by checking that route() can generate URLs.
        $configUrl = route(\Anschev\JwtAuth\Http\RequestHandlers\JwtConfigPage::class);

        // Route URL is encoded as query parameter in webtrees
        self::assertStringContainsString('jwt-auth', $configUrl);
        self::assertStringContainsString('config', $configUrl);
    }

    // -------------------------------------------------------------------------
    // T01-T08: Token Extraction
    // -------------------------------------------------------------------------

    public function testExtractTokenFromAuthorizationBearerHeader(): void
    {
        // T01
        $this->configureModuleForHs256();
        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testExtractTokenFromCustomHeader(): void
    {
        // T02
        $this->module->setPreference('JWT_AUTH_HEADER_NAME', 'Cf-Access-Jwt-Assertion');
        $this->configureModuleForHs256();
        // Re-set custom header after configureModuleForHs256 overrides it
        $this->module->setPreference('JWT_AUTH_HEADER_NAME', 'Cf-Access-Jwt-Assertion');

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Cf-Access-Jwt-Assertion', $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testExtractTokenFromCookie(): void
    {
        // T03
        $this->configureModuleForHs256();
        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithCookie('jwt_token', $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testNoTokenPassesThrough(): void
    {
        // T04
        $this->configureModuleForHs256();
        $request = self::createRequest();
        $handler = $this->createStubHandler();

        $response = $this->module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testHeaderPreferredOverCookie(): void
    {
        // T05: When both header and cookie have tokens, header takes precedence
        $this->configureModuleForHs256();
        $this->module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'header,cookie');

        $headerUser = $this->createVerifiedUser('header@example.com', 'headeruser');
        $this->createVerifiedUser('cookie@example.com', 'cookieuser');
        Registry::container()->set(UserService::class, new UserService());

        $headerToken = $this->createHs256Token($this->standardPayload(['email' => 'header@example.com']));
        $cookieToken = $this->createHs256Token($this->standardPayload(['email' => 'cookie@example.com']));

        $request = self::createRequest();
        $request = $request
            ->withHeader('Authorization', 'Bearer ' . $headerToken)
            ->withCookieParams(['jwt_token' => $cookieToken]);

        $handler = $this->createStubHandler();
        $this->module->process($request, $handler);

        self::assertSame($headerUser->id(), Auth::id());
    }

    public function testAuthorizationHeaderWithoutBearerPrefix(): void
    {
        // T06: If Authorization header doesn't start with "Bearer ", use full value
        $this->configureModuleForHs256();
        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        // Pass raw token without Bearer prefix
        $request = $this->buildRequestWithHeader('Authorization', $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testEmptyCookieValueSkipped(): void
    {
        // T07: Empty cookie value should be treated as no token
        $this->configureModuleForHs256();
        $this->module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'cookie');

        $request = self::createRequest();
        $request = $request->withCookieParams(['jwt_token' => '']);
        $handler = $this->createStubHandler();

        $response = $this->module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testAlreadyLoggedInSkipsJwtProcessing(): void
    {
        // T08: If user is already logged in, skip JWT processing entirely
        $this->configureModuleForHs256();
        $existingUser = $this->createVerifiedUser('existing@example.com', 'existinguser');
        Auth::login($existingUser);

        // Create a different user's token
        $this->createVerifiedUser('other@example.com', 'otheruser');
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload(['email' => 'other@example.com']));
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        // Should still be logged in as the existing user, not the JWT user
        self::assertSame($existingUser->id(), Auth::id());
    }

    // -------------------------------------------------------------------------
    // T09-T21: JWT Validation
    // -------------------------------------------------------------------------

    public function testValidHs256Token(): void
    {
        // T09
        $this->configureModuleForHs256();
        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testInvalidHs256Signature(): void
    {
        // T10: Token signed with wrong secret
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload(), 'wrong-secret-that-is-at-least-32-chars!!');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testExpiredToken(): void
    {
        // T11
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload([
            'exp' => time() - 3600,
            'iat' => time() - 7200,
        ]));
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testWrongIssuer(): void
    {
        // T12
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload([
            'iss' => 'https://wrong-issuer.example.com',
        ]));
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testWrongAudience(): void
    {
        // T13
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload([
            'aud' => 'wrong-audience',
        ]));
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testAudienceAsArray(): void
    {
        // T14: Token with audience as array containing the expected value
        $this->configureModuleForHs256();
        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload([
            'aud' => ['other-audience', self::AUDIENCE],
        ]));
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testAudienceAsArrayNotContaining(): void
    {
        // T15: Token with audience array NOT containing expected value
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload([
            'aud' => ['wrong-1', 'wrong-2'],
        ]));
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testValidRs256Token(): void
    {
        // T16
        $keyPair = $this->generateRsaKeyPair();
        $this->configureModuleForRs256($keyPair['public']);
        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createRs256Token($this->standardPayload(), $keyPair['private']);
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testInvalidRs256Signature(): void
    {
        // T17: Token signed with wrong RSA key
        $keyPair1 = $this->generateRsaKeyPair();
        $keyPair2 = $this->generateRsaKeyPair();
        $this->configureModuleForRs256($keyPair1['public']);
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        // Sign with keyPair2 private, but module has keyPair1 public
        $token = $this->createRs256Token($this->standardPayload(), $keyPair2['private']);
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testValidEs256Token(): void
    {
        // T18
        $keyPair = $this->generateEcKeyPair();
        $this->configureModuleForEs256($keyPair['public']);
        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createEs256Token($this->standardPayload(), $keyPair['private']);
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testAlgorithmMismatchRejected(): void
    {
        // T19: Module configured for RS256, but token is HS256
        $keyPair = $this->generateRsaKeyPair();
        $this->configureModuleForRs256($keyPair['public']);
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        // Create HS256 token but module expects RS256
        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testMissingIssuerClaim(): void
    {
        // T20: Token without iss claim
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $payload = $this->standardPayload();
        unset($payload['iss']);
        $token = $this->createHs256Token($payload);
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testMissingAudienceClaim(): void
    {
        // T21: Token without aud claim
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $payload = $this->standardPayload();
        unset($payload['aud']);
        $token = $this->createHs256Token($payload);
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    // -------------------------------------------------------------------------
    // T22-T32: Authentication Flow
    // -------------------------------------------------------------------------

    public function testSuccessfulLoginCreatesSession(): void
    {
        // T22: Successful JWT login sets session user
        $this->configureModuleForHs256();
        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
        self::assertTrue(Auth::check());
    }

    public function testSuccessfulLoginSetsLanguagePreference(): void
    {
        // T23: Session gets user's language preference
        $this->configureModuleForHs256();
        $user = $this->createVerifiedUser();
        $user->setPreference(UserInterface::PREF_LANGUAGE, 'en-US');
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame('en-US', Session::get('language'));
    }

    public function testSuccessfulLoginSetsThemePreference(): void
    {
        // T24: Session gets user's theme preference
        $this->configureModuleForHs256();
        $user = $this->createVerifiedUser();
        $user->setPreference(UserInterface::PREF_THEME, 'webtrees');
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame('webtrees', Session::get('theme'));
    }

    public function testSuccessfulLoginUpdatesActiveTimestamp(): void
    {
        // T25: User's active timestamp is updated
        $this->configureModuleForHs256();
        $user = $this->createVerifiedUser();
        $user_service = new UserService();
        Registry::container()->set(UserService::class, $user_service);

        $before = time();
        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);
        $after = time();

        // Re-fetch user from DB to see the updated preference
        $freshUser = $user_service->find(Auth::id());
        self::assertNotNull($freshUser);
        $timestamp = (int) $freshUser->getPreference(UserInterface::PREF_TIMESTAMP_ACTIVE);
        self::assertGreaterThanOrEqual($before, $timestamp);
        self::assertLessThanOrEqual($after, $timestamp);
    }

    public function testMissingEmailInTokenFailsGracefully(): void
    {
        // T26: Token without email claim should fail but pass through
        $this->configureModuleForHs256();
        Registry::container()->set(UserService::class, new UserService());

        $payload = $this->standardPayload();
        unset($payload['email']);
        $token = $this->createHs256Token($payload);
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $response = $this->module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testUserNotFoundFailsGracefully(): void
    {
        // T27: Email in token doesn't match any user
        $this->configureModuleForHs256();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload(['email' => 'nonexistent@example.com']));
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $response = $this->module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testUnverifiedEmailFailsGracefully(): void
    {
        // T28: User exists but email not verified
        $this->configureModuleForHs256();
        $user_service = new UserService();
        $user = $user_service->create('unverified', 'Unverified User', 'test@example.com', 'password');
        $user->setPreference(UserInterface::PREF_IS_EMAIL_VERIFIED, '0');
        $user->setPreference(UserInterface::PREF_IS_ACCOUNT_APPROVED, '1');
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $response = $this->module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testUnapprovedAccountFailsGracefully(): void
    {
        // T29: User exists but account not approved
        $this->configureModuleForHs256();
        $user_service = new UserService();
        $user = $user_service->create('unapproved', 'Unapproved User', 'test@example.com', 'password');
        $user->setPreference(UserInterface::PREF_IS_EMAIL_VERIFIED, '1');
        $user->setPreference(UserInterface::PREF_IS_ACCOUNT_APPROVED, '0');
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $response = $this->module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testFailureAlwaysPassesThrough(): void
    {
        // T30: Any JWT failure should still pass request to the next handler
        $this->configureModuleForHs256();
        Registry::container()->set(UserService::class, new UserService());

        $expectedResponse = self::createStub(ResponseInterface::class);
        $expectedResponse->method('getStatusCode')->willReturn(StatusCodeInterface::STATUS_OK);
        $handler = $this->createStubHandler($expectedResponse);

        // Malformed token
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer not.a.valid.token');

        $response = $this->module->process($request, $handler);

        self::assertSame($expectedResponse, $response);
    }

    public function testMissingConfigPassesThrough(): void
    {
        // T31: Missing issuer/audience/key config should pass through
        // Don't set any preferences (defaults are empty)
        $request = self::createRequest();
        $handler = $this->createStubHandler();

        $token = $this->createHs256Token($this->standardPayload());
        $request = $request->withHeader('Authorization', 'Bearer ' . $token);

        $response = $this->module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testEmptyPublicKeyPassesThrough(): void
    {
        // T32: Empty public key should cause pass-through
        $this->module->setPreference('JWT_AUTH_ISSUER', self::ISSUER);
        $this->module->setPreference('JWT_AUTH_AUDIENCE', self::AUDIENCE);
        $this->module->setPreference('JWT_AUTH_PUBLIC_KEY', '');
        $this->module->setPreference('JWT_AUTH_ALGORITHM', 'HS256');
        $this->module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'header,cookie');
        $this->module->setPreference('JWT_AUTH_HEADER_NAME', 'Authorization');

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $response = $this->module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    // -------------------------------------------------------------------------
    // T36-T40: Configuration Resolution (config.ini.php vs preferences)
    // -------------------------------------------------------------------------

    public function testConfigIniTakesPrecedenceForIssuer(): void
    {
        // T36: jwt_issuer in request attributes (simulating config.ini.php) takes precedence
        $this->configureModuleForHs256();
        $configIssuer = 'https://config-ini-issuer.example.com';

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        // Token uses config.ini.php issuer
        $token = $this->createHs256Token($this->standardPayload(['iss' => $configIssuer]));
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        // Simulate config.ini.php by setting request attribute
        $request = $request->withAttribute('jwt_auth_issuer', $configIssuer);

        $handler = $this->createStubHandler();
        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testConfigIniTakesPrecedenceForAudience(): void
    {
        // T37: jwt_audience in request attributes takes precedence
        $this->configureModuleForHs256();
        $configAudience = 'config-ini-audience';

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload(['aud' => $configAudience]));
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $request = $request->withAttribute('jwt_auth_audience', $configAudience);

        $handler = $this->createStubHandler();
        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testFallbackToPreferencesWhenConfigIniEmpty(): void
    {
        // T38: When config.ini.php values are empty, fall back to module preferences
        $this->configureModuleForHs256();
        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        // Don't set any config.ini attributes - should use module preferences

        $handler = $this->createStubHandler();
        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testConfigIniIssuerMismatchRejectsToken(): void
    {
        // T39: config.ini.php issuer doesn't match token issuer
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        // config.ini.php has different issuer than what's in the token
        $request = $request->withAttribute('jwt_auth_issuer', 'https://wrong.example.com');

        $handler = $this->createStubHandler();
        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testConfigIniAudienceMismatchRejectsToken(): void
    {
        // T40: config.ini.php audience doesn't match token audience
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $request = $request->withAttribute('jwt_auth_audience', 'wrong-audience');

        $handler = $this->createStubHandler();
        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testConfigIniTakesPrecedenceForTokenHeaderName(): void
    {
        // T40b: token_header_name in request attributes (simulating config.ini.php) takes precedence
        $this->configureModuleForHs256();
        // DB preference says "Authorization", but config.ini.php says "X-Custom-Token"
        $this->module->setPreference('JWT_AUTH_HEADER_NAME', 'Authorization');

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        // Send token via the custom header (not Authorization)
        $request = $this->buildRequestWithHeader('X-Custom-Token', $token);
        // Simulate config.ini.php overriding the header name
        $request = $request->withAttribute('jwt_auth_header_name', 'X-Custom-Token');

        $handler = $this->createStubHandler();
        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testConfigIniTakesPrecedenceForTokenSourcePriority(): void
    {
        // T40c: token_source_priority in request attributes (simulating config.ini.php) takes precedence
        $this->configureModuleForHs256();
        // DB preference says "header,cookie", but config.ini.php says "cookie" only
        $this->module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'header,cookie');

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        // Send token only via header — but config.ini.php restricts to cookie source
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $request = $request->withAttribute('jwt_auth_source_priority', 'cookie');

        $handler = $this->createStubHandler();
        $this->module->process($request, $handler);

        // Header token should be ignored because config.ini.php says cookie only
        self::assertNull(Auth::id());
    }

    public function testConfigIniTakesPrecedenceForTokenCookieName(): void
    {
        // T40d: token_cookie_name in request attributes (simulating config.ini.php) takes precedence
        $this->configureModuleForHs256();
        $this->module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'cookie');
        // DB preference says "jwt_token", but config.ini.php says "custom_cookie"
        $this->module->setPreference('JWT_AUTH_COOKIE_NAME', 'jwt_token');

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        // Send token via the custom cookie name (not jwt_token)
        $request = $this->buildRequestWithCookie('custom_cookie', $token);
        // Simulate config.ini.php overriding the cookie name
        $request = $request->withAttribute('jwt_auth_cookie_name', 'custom_cookie');

        $handler = $this->createStubHandler();
        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    // -------------------------------------------------------------------------
    // T58-T62: Security Tests
    // -------------------------------------------------------------------------

    public function testTamperedTokenRejected(): void
    {
        // T58: Modified payload in a signed token should fail validation
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        // Tamper with the token by modifying a character in the payload
        $parts = explode('.', $token);
        $parts[1] = $parts[1] . 'x';
        $tamperedToken = implode('.', $parts);

        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $tamperedToken);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testNoneAlgorithmRejected(): void
    {
        // T59: Token with "none" algorithm should be rejected
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        // Manually craft a "none" algorithm token
        $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'none']));
        $payload = base64_encode(json_encode($this->standardPayload()));
        $noneToken = $header . '.' . $payload . '.';

        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $noneToken);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testAlgorithmConfusionAttackRejected(): void
    {
        // T60: HS256 token presented to RS256-configured module
        $keyPair = $this->generateRsaKeyPair();
        $this->configureModuleForRs256($keyPair['public']);
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        // Try to use public key as HMAC secret (algorithm confusion)
        $token = $this->createHs256Token($this->standardPayload(), $keyPair['public']);
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testNoQueryParameterExtraction(): void
    {
        // T61: Verify module does NOT extract tokens from query parameters
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        // Put token in query parameter (should NOT be extracted)
        $request = self::createRequest(RequestMethodInterface::METHOD_GET, ['token' => $token]);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    public function testNoPostBodyExtraction(): void
    {
        // T62: Verify module does NOT extract tokens from POST body
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        // Put token in POST body (should NOT be extracted)
        $request = self::createRequest(RequestMethodInterface::METHOD_POST, [], ['token' => $token]);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertNull(Auth::id());
    }

    // -------------------------------------------------------------------------
    // T65-T70: Edge Cases
    // -------------------------------------------------------------------------

    public function testLongTokenHandled(): void
    {
        // T65: Very long token should be handled without error
        $this->configureModuleForHs256();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        // Create a token with a very large payload
        $payload = $this->standardPayload([
            'extra_data' => str_repeat('x', 10000),
        ]);
        $token = $this->createHs256Token($payload);
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $response = $this->module->process($request, $handler);

        // Should authenticate successfully despite long token
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testUnicodeEmailInToken(): void
    {
        // T66: Unicode characters in email
        $this->configureModuleForHs256();
        $unicodeEmail = 'tëst@example.com';
        $user = $this->createVerifiedUser($unicodeEmail, 'unicodeuser');
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload(['email' => $unicodeEmail]));
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testEmptyTokenStringSkipped(): void
    {
        // T67: Empty token string in header should be handled gracefully
        $this->configureModuleForHs256();

        $request = $this->buildRequestWithHeader('Authorization', '');
        $handler = $this->createStubHandler();

        $response = $this->module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testMalformedJwtRejected(): void
    {
        // T68: Completely malformed JWT string
        $this->configureModuleForHs256();
        Registry::container()->set(UserService::class, new UserService());

        $request = $this->buildRequestWithHeader('Authorization', 'Bearer not-even-close-to-jwt');
        $handler = $this->createStubHandler();

        $response = $this->module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testTokenWithOnlyTwoParts(): void
    {
        // T69: JWT with only two parts (missing signature)
        $this->configureModuleForHs256();
        Registry::container()->set(UserService::class, new UserService());

        $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
        $payload = base64_encode(json_encode($this->standardPayload()));
        $twoPartToken = $header . '.' . $payload;

        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $twoPartToken);
        $handler = $this->createStubHandler();

        $response = $this->module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testCookieOnlySourcePriority(): void
    {
        // T70: When source priority is cookie only, header tokens should be ignored
        $this->configureModuleForHs256();
        $this->module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'cookie');

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createHs256Token($this->standardPayload());
        // Token only in header, but module configured for cookie only
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        // Should NOT authenticate because header source is disabled
        self::assertNull(Auth::id());
    }

    // -------------------------------------------------------------------------
    // JWKS Helpers
    // -------------------------------------------------------------------------

    /**
     * Convert an RSA public key PEM to JWK array format.
     */
    private function rsaPublicKeyToJwk(string $publicKeyPem, string $kid = 'test-kid'): array
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        $details = openssl_pkey_get_details($key);

        return [
            'kty' => 'RSA',
            'kid' => $kid,
            'alg' => 'RS256',
            'use' => 'sig',
            'n'   => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
            'e'   => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
        ];
    }

    /**
     * Build a JWKS JSON string from JWK arrays.
     */
    private function buildJwksJson(array ...$jwks): string
    {
        return json_encode(['keys' => $jwks]);
    }

    /**
     * Create an RS256 token with a specific kid in the header.
     */
    private function createRs256TokenWithKid(array $payload, string $privateKey, string $kid): string
    {
        return JWT::encode($payload, $privateKey, 'RS256', $kid);
    }

    /**
     * Create a JwtAuthModule subclass with mocked fetchJwksJson().
     * $fetchResponses is an array of return values; each call pops the next one.
     */
    private function createModuleWithMockedJwksFetch(array &$fetchResponses): JwtAuthModule
    {
        $responses = &$fetchResponses;
        $module = new class($responses) extends JwtAuthModule {
            /** @var array<string> */
            private array $responses;
            public int $fetchCount = 0;

            public function __construct(array &$responses)
            {
                $this->responses = &$responses;
            }

            protected function fetchJwksJson(string $url): string
            {
                $this->fetchCount++;
                return array_shift($this->responses) ?? '';
            }
        };

        $module->setName(self::MODULE_NAME);

        return $module;
    }

    /**
     * Configure a module for JWKS-based auth.
     */
    private function configureModuleForJwks(JwtAuthModule $module, string $jwksUrl = 'https://example.com/.well-known/jwks.json'): void
    {
        $module->setPreference('JWT_AUTH_ISSUER', self::ISSUER);
        $module->setPreference('JWT_AUTH_AUDIENCE', self::AUDIENCE);
        $module->setPreference('JWT_AUTH_JWKS_URL', $jwksUrl);
        $module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'header,cookie');
        $module->setPreference('JWT_AUTH_HEADER_NAME', 'Authorization');
        $module->setPreference('JWT_AUTH_COOKIE_NAME', 'jwt_token');
    }

    // -------------------------------------------------------------------------
    // T71-T84: JWKS Support
    // -------------------------------------------------------------------------

    public function testJwksValidRs256Authentication(): void
    {
        // T71: Valid RS256 token authenticated via JWKS endpoint
        $keyPair = $this->generateRsaKeyPair();
        $jwk = $this->rsaPublicKeyToJwk($keyPair['public'], 'key-1');
        $jwksJson = $this->buildJwksJson($jwk);

        $fetchResponses = [$jwksJson];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        $this->configureModuleForJwks($module);

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPair['private'], 'key-1');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testJwksKeyRotationTriggersRefresh(): void
    {
        // T72: Token with unknown kid triggers cache refresh, second fetch has new key
        $keyPair1 = $this->generateRsaKeyPair();
        $keyPair2 = $this->generateRsaKeyPair();

        $jwk1 = $this->rsaPublicKeyToJwk($keyPair1['public'], 'old-key');
        $jwk2 = $this->rsaPublicKeyToJwk($keyPair2['public'], 'new-key');

        $oldJwks = $this->buildJwksJson($jwk1);
        $newJwks = $this->buildJwksJson($jwk1, $jwk2);

        $fetchResponses = [$oldJwks, $newJwks];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        $this->configureModuleForJwks($module);

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        // Sign with the NEW key that's not in the first JWKS response
        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPair2['private'], 'new-key');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
        self::assertSame(2, $module->fetchCount);
    }

    public function testJwksCacheHitSkipsFetch(): void
    {
        // T73: When cache is fresh, no HTTP fetch is made
        $keyPair = $this->generateRsaKeyPair();
        $jwk = $this->rsaPublicKeyToJwk($keyPair['public'], 'cached-key');
        $jwksJson = $this->buildJwksJson($jwk);

        $fetchResponses = [];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        $this->configureModuleForJwks($module);

        // Pre-populate cache
        $module->setPreference('JWT_AUTH_JWKS_CACHE', $jwksJson);
        $module->setPreference('JWT_AUTH_JWKS_CACHE_TIMESTAMP', (string) time());

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPair['private'], 'cached-key');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
        self::assertSame(0, $module->fetchCount);
    }

    public function testJwksExpiredCacheTriggersFetch(): void
    {
        // T74: Expired cache triggers a fresh fetch
        $keyPair = $this->generateRsaKeyPair();
        $jwk = $this->rsaPublicKeyToJwk($keyPair['public'], 'key-1');
        $jwksJson = $this->buildJwksJson($jwk);

        $fetchResponses = [$jwksJson];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        $this->configureModuleForJwks($module);

        // Pre-populate cache with expired timestamp
        $module->setPreference('JWT_AUTH_JWKS_CACHE', $jwksJson);
        $module->setPreference('JWT_AUTH_JWKS_CACHE_TIMESTAMP', (string) (time() - 7200));

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPair['private'], 'key-1');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
        self::assertSame(1, $module->fetchCount);
    }

    public function testJwksUrlTakesPriorityOverStaticKey(): void
    {
        // T75: JWKS URL takes priority over static public key when both are set
        $keyPairJwks = $this->generateRsaKeyPair();
        $keyPairStatic = $this->generateRsaKeyPair();

        $jwk = $this->rsaPublicKeyToJwk($keyPairJwks['public'], 'jwks-key');
        $jwksJson = $this->buildJwksJson($jwk);

        $fetchResponses = [$jwksJson];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        $this->configureModuleForJwks($module);
        // Also set a static key (should be ignored)
        $module->setPreference('JWT_AUTH_PUBLIC_KEY', $keyPairStatic['public']);
        $module->setPreference('JWT_AUTH_ALGORITHM', 'RS256');

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        // Sign with JWKS key
        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPairJwks['private'], 'jwks-key');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testJwksFetchFailurePassesThrough(): void
    {
        // T76: When JWKS fetch fails, request passes through gracefully
        $fetchResponses = [''];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        $this->configureModuleForJwks($module);

        $keyPair = $this->generateRsaKeyPair();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPair['private'], 'some-key');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $response = $module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testJwksInvalidJsonResponse(): void
    {
        // T77: Invalid JSON in JWKS response should fail gracefully
        $fetchResponses = ['not-valid-json'];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        $this->configureModuleForJwks($module);

        $keyPair = $this->generateRsaKeyPair();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPair['private'], 'some-key');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $response = $module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testJwksEmptyKeysArray(): void
    {
        // T78: JWKS response with empty keys array should fail gracefully
        $fetchResponses = ['{"keys":[]}'];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        $this->configureModuleForJwks($module);

        $keyPair = $this->generateRsaKeyPair();
        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPair['private'], 'some-key');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $response = $module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testJwksMultipleKeysCorrectKidSelected(): void
    {
        // T80: Multiple keys in JWKS, correct one selected by kid
        $keyPair1 = $this->generateRsaKeyPair();
        $keyPair2 = $this->generateRsaKeyPair();

        $jwk1 = $this->rsaPublicKeyToJwk($keyPair1['public'], 'key-1');
        $jwk2 = $this->rsaPublicKeyToJwk($keyPair2['public'], 'key-2');
        $jwksJson = $this->buildJwksJson($jwk1, $jwk2);

        $fetchResponses = [$jwksJson];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        $this->configureModuleForJwks($module);

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        // Sign with key-2
        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPair2['private'], 'key-2');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testStaticKeyBackwardCompatibility(): void
    {
        // T82: When JWKS_URL is not set, static key works as before
        $keyPair = $this->generateRsaKeyPair();
        $this->configureModuleForRs256($keyPair['public']);
        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createRs256Token($this->standardPayload(), $keyPair['private']);
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $this->module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }

    public function testJwksKidNotFoundEvenAfterRefresh(): void
    {
        // T83: Kid not found even after cache refresh → authentication fails
        $keyPair1 = $this->generateRsaKeyPair();
        $keyPair2 = $this->generateRsaKeyPair();

        $jwk1 = $this->rsaPublicKeyToJwk($keyPair1['public'], 'key-1');
        $jwksJson = $this->buildJwksJson($jwk1);

        // Both fetches return the same JWKS (without the needed kid)
        $fetchResponses = [$jwksJson, $jwksJson];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        $this->configureModuleForJwks($module);

        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        // Sign with a key that's never in the JWKS
        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPair2['private'], 'unknown-key');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $response = $module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testJwksWrongSignatureRejected(): void
    {
        // T84: Token signed with wrong key (right kid, wrong signature) is rejected
        $keyPair1 = $this->generateRsaKeyPair();
        $keyPairWrong = $this->generateRsaKeyPair();

        $jwk1 = $this->rsaPublicKeyToJwk($keyPair1['public'], 'key-1');
        $jwksJson = $this->buildJwksJson($jwk1);

        $fetchResponses = [$jwksJson];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        $this->configureModuleForJwks($module);

        $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        // Sign with wrong key but use correct kid
        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPairWrong['private'], 'key-1');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        $handler = $this->createStubHandler();

        $response = $module->process($request, $handler);

        self::assertNull(Auth::id());
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
    }

    public function testJwksUrlFromConfigIniTakesPrecedence(): void
    {
        // T85: jwks_url in request attributes (simulating config.ini.php) takes precedence
        $keyPair = $this->generateRsaKeyPair();
        $jwk = $this->rsaPublicKeyToJwk($keyPair['public'], 'key-1');
        $jwksJson = $this->buildJwksJson($jwk);

        $fetchResponses = [$jwksJson];
        $module = $this->createModuleWithMockedJwksFetch($fetchResponses);
        // Don't set JWT_AUTH_JWKS_URL in preferences — only via config.ini.php attribute
        $module->setPreference('JWT_AUTH_ISSUER', self::ISSUER);
        $module->setPreference('JWT_AUTH_AUDIENCE', self::AUDIENCE);
        $module->setPreference('JWT_AUTH_SOURCE_PRIORITY', 'header,cookie');
        $module->setPreference('JWT_AUTH_HEADER_NAME', 'Authorization');

        $user = $this->createVerifiedUser();
        Registry::container()->set(UserService::class, new UserService());

        $token = $this->createRs256TokenWithKid($this->standardPayload(), $keyPair['private'], 'key-1');
        $request = $this->buildRequestWithHeader('Authorization', 'Bearer ' . $token);
        // Simulate config.ini.php override
        $request = $request->withAttribute('jwt_auth_jwks_url', 'https://example.com/.well-known/jwks.json');

        $handler = $this->createStubHandler();
        $module->process($request, $handler);

        self::assertSame($user->id(), Auth::id());
    }
}
