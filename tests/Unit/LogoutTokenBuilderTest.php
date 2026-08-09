<?php

declare(strict_types=1);

namespace OpenIDConnect\Tests\Unit;

use InvalidArgumentException;
use Lcobucci\JWT\Configuration;
use OpenIDConnect\LogoutTokenBuilder;
use OpenIDConnect\Tests\Factories\ConfigutationFactory;
use PHPUnit\Framework\TestCase;

class LogoutTokenBuilderTest extends TestCase
{
    private const ISSUER = 'https://op.example';

    private function builder(?Configuration $config = null): LogoutTokenBuilder
    {
        return new LogoutTokenBuilder(
            $config ?? ConfigutationFactory::default(),
            self::ISSUER,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function claimsOf(string $token): array
    {
        $config = ConfigutationFactory::default();

        return $config->parser()->parse($token)->claims()->all();
    }

    public function testItCarriesTheClaimsSection24Requires(): void
    {
        $token = $this->builder()->build('client-one', 'user-42', 'session-abc');

        $claims = $this->claimsOf($token);

        $this->assertSame(self::ISSUER, $claims['iss']);
        $this->assertSame(['client-one'], $claims['aud']);
        $this->assertSame('user-42', $claims['sub']);
        $this->assertSame('session-abc', $claims['sid']);
        $this->assertArrayHasKey('iat', $claims);
        $this->assertArrayHasKey('jti', $claims);
    }

    public function testItMarksTheTokenWithTheBackchannelLogoutEvent(): void
    {
        $token = $this->builder()->build('client-one', 'user-42', 'session-abc');

        $events = $this->claimsOf($token)['events'];

        $this->assertArrayHasKey(LogoutTokenBuilder::EVENT, (array) $events);
    }

    /**
     * The event value has to survive encoding as `{}` and not `[]`; a relying
     * party that validates the shape rejects the latter.
     */
    public function testTheEventValueEncodesAsAnEmptyJsonObject(): void
    {
        $token = $this->builder()->build('client-one', 'user-42', 'session-abc');

        $payload = base64_decode(strtr(explode('.', $token)[1], '-_', '+/'), true);

        // Asserted against the encoded payload rather than a decoded one:
        // json_decode with $assoc turns `{}` into `[]`, which is exactly the
        // distinction under test.
        $this->assertStringContainsString(
            json_encode([LogoutTokenBuilder::EVENT => new \stdClass()], JSON_UNESCAPED_SLASHES),
            $payload,
        );

        // And the decoded value is an object, not a list.
        $events = json_decode($payload)->events;

        $this->assertIsObject($events->{LogoutTokenBuilder::EVENT});
    }

    /**
     * Section 2.4: "A Logout Token MUST NOT contain a nonce Claim."
     */
    public function testItNeverCarriesANonce(): void
    {
        $token = $this->builder()->build('client-one', 'user-42', 'session-abc');

        $this->assertArrayNotHasKey('nonce', $this->claimsOf($token));
    }

    public function testASubjectAloneIsEnough(): void
    {
        $claims = $this->claimsOf($this->builder()->build('client-one', 'user-42', null));

        $this->assertSame('user-42', $claims['sub']);
        $this->assertArrayNotHasKey('sid', $claims);
    }

    public function testASessionAloneIsEnough(): void
    {
        $claims = $this->claimsOf($this->builder()->build('client-one', null, 'session-abc'));

        $this->assertSame('session-abc', $claims['sid']);
        $this->assertArrayNotHasKey('sub', $claims);
    }

    public function testItRefusesToBuildATokenThatIdentifiesNothing(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->builder()->build('client-one', null, null);
    }

    /**
     * Empty strings are the shape a missing value arrives in when it has been
     * round-tripped through a database column, and they identify a session no
     * better than null does.
     */
    public function testItTreatsEmptyIdentifiersAsAbsent(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->builder()->build('client-one', '', '');
    }

    public function testEachTokenGetsItsOwnJti(): void
    {
        $first = $this->claimsOf($this->builder()->build('client-one', 'user-42', 'session-abc'));
        $second = $this->claimsOf($this->builder()->build('client-one', 'user-42', 'session-abc'));

        $this->assertNotSame($first['jti'], $second['jti']);
    }

    public function testTheTokenIsAddressedToOneClientAtATime(): void
    {
        $first = $this->claimsOf($this->builder()->build('client-one', 'user-42', 'session-abc'));
        $second = $this->claimsOf($this->builder()->build('client-two', 'user-42', 'session-abc'));

        $this->assertSame(['client-one'], $first['aud']);
        $this->assertSame(['client-two'], $second['aud']);
    }

    public function testItExpires(): void
    {
        $claims = $this->claimsOf($this->builder()->build('client-one', 'user-42', 'session-abc'));

        $this->assertArrayHasKey('exp', $claims);
        $this->assertGreaterThan($claims['iat'], $claims['exp']);
    }

    public function testItIsSignedByTheConfiguredKey(): void
    {
        $config = ConfigutationFactory::default();

        $token = $this->builder($config)->build('client-one', 'user-42', 'session-abc');

        $parsed = $config->parser()->parse($token);

        $this->assertTrue(
            $config->validator()->validate(
                $parsed,
                new \Lcobucci\JWT\Validation\Constraint\SignedWith(
                    $config->signer(),
                    $config->verificationKey(),
                ),
            ),
        );
    }
}
