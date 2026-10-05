<?php

declare(strict_types=1);

namespace OpenIDConnect\Tests\Feature;

use DateInterval;
use DateTimeImmutable;
use GuzzleHttp\Psr7;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entities\DeviceCodeEntityInterface;
use League\OAuth2\Server\Entities\Traits\DeviceCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use League\OAuth2\Server\Grant\DeviceCodeGrant;
use League\OAuth2\Server\Repositories\DeviceCodeRepositoryInterface;
use OpenIDConnect\ClaimExtractor;
use OpenIDConnect\Repositories\AccessTokenRepository;
use OpenIDConnect\Repositories\ClientRepository;
use OpenIDConnect\Repositories\IdentityRepository;
use OpenIDConnect\Repositories\RefreshTokenRepository;
use OpenIDConnect\Repositories\ScopeRepository;
use OpenIDConnect\Tests\Config;
use OpenIDConnect\Tests\Factories\ClientFactory;
use OpenIDConnect\Tests\Factories\ConfigutationFactory;
use OpenIDConnect\Tests\Factories\IdTokenResponseFactory;
use OpenIDConnect\Tests\Factories\KeyFactory;
use OpenIDConnect\Tests\Factories\ScopeFactory;
use OpenIDConnect\Tests\Feature\Traits\WithDefaultAsserts;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

/**
 * The RFC 8628 device authorization grant, run through a real authorization
 * server, so that what is asserted is the token response a device would poll.
 */
class DeviceCodeGrantTest extends TestCase
{
    use WithDefaultAsserts;

    private const DEVICE_CODE = 'a_device_code';

    protected function setUp(): void
    {
        $_SERVER['HTTP_HOST'] = Config::HTTP_HOST;
    }

    public function test_device_code_grant_returns_id_token_with_open_id_scope(): void
    {
        $response = $this->exchangeDeviceCode(['openid', 'email']);
        $this->defaultResponseAsserts($response);

        $json = json_decode($response->getBody()->getContents());
        $this->defaultTokenAsserts($json);

        $this->assertObjectHasProperty('id_token', $json);

        /** @var Plain $idToken */
        $idToken = ConfigutationFactory::default()->parser()->parse($json->id_token);

        $this->assertSame(Config::USER_ID, $idToken->claims()->get('sub'));
        $this->assertSame([Config::CLIENT_ID], $idToken->claims()->get('aud'));
        $this->assertTrue($idToken->claims()->has('email'));

        // Both are bound to a browser session at the authorization endpoint,
        // which the device flow never visits.
        $this->assertFalse($idToken->claims()->has('nonce'));
        $this->assertFalse($idToken->claims()->has('sid'));
    }

    public function test_device_code_grant_returns_no_id_token_without_open_id_scope(): void
    {
        $response = $this->exchangeDeviceCode(['email']);
        $this->defaultResponseAsserts($response);

        $json = json_decode($response->getBody()->getContents());
        $this->defaultTokenAsserts($json);

        $this->assertObjectNotHasProperty('id_token', $json);
    }

    /**
     * @param string[] $scopes
     */
    private function exchangeDeviceCode(array $scopes): ResponseInterface
    {
        $server = new AuthorizationServer(
            new ClientRepository(),
            new AccessTokenRepository(),
            new ScopeRepository(),
            KeyFactory::cryptKey(),
            base64_encode(random_bytes(32)),
            IdTokenResponseFactory::default(
                new IdentityRepository(),
                new ClaimExtractor(),
            ),
        );

        $server->enableGrantType(
            new DeviceCodeGrant(
                $this->approvedDeviceCodeRepository($scopes),
                new RefreshTokenRepository(),
                new DateInterval('PT10M'),
                'https://' . Config::HTTP_HOST . '/oauth/device',
            ),
            new DateInterval('PT1H'),
        );

        $request = (new Psr7\ServerRequest('POST', 'https://' . Config::HTTP_HOST . '/oauth/token'))
            ->withParsedBody([
                'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
                'client_id' => Config::CLIENT_ID,
                'device_code' => self::DEVICE_CODE,
            ]);

        return $server->respondToAccessTokenRequest($request, new Psr7\Response());
    }

    /**
     * A repository holding a single device code the end-user has already
     * approved, which is the state the device finds on its final poll.
     *
     * @param string[] $scopes
     */
    private function approvedDeviceCodeRepository(array $scopes): DeviceCodeRepositoryInterface
    {
        $deviceCode = new class() implements DeviceCodeEntityInterface {
            use EntityTrait;
            use DeviceCodeTrait;
            use TokenEntityTrait;
        };

        $deviceCode->setIdentifier(self::DEVICE_CODE);
        $deviceCode->setClient(ClientFactory::default());
        $deviceCode->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT10M')));
        $deviceCode->setUserIdentifier(Config::USER_ID);
        $deviceCode->setUserApproved(true);

        foreach ($scopes as $scope) {
            $deviceCode->addScope(ScopeFactory::default($scope));
        }

        return new class($deviceCode) implements DeviceCodeRepositoryInterface {
            public function __construct(private DeviceCodeEntityInterface $deviceCode)
            {
            }

            public function getNewDeviceCode(): DeviceCodeEntityInterface
            {
                return $this->deviceCode;
            }

            public function persistDeviceCode(DeviceCodeEntityInterface $deviceCodeEntity): void
            {
            }

            public function getDeviceCodeEntityByDeviceCode(string $deviceCodeEntity): ?DeviceCodeEntityInterface
            {
                return $deviceCodeEntity === $this->deviceCode->getIdentifier() ? $this->deviceCode : null;
            }

            public function revokeDeviceCode(string $codeId): void
            {
            }

            public function isDeviceCodeRevoked(string $codeId): bool
            {
                return false;
            }
        };
    }
}
