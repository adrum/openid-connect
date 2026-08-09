<?php

declare(strict_types=1);

namespace OpenIDConnect;

use DateInterval;
use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\JWT\Configuration;
use stdClass;

/**
 * Mints the Logout Token of OpenID Connect Back-Channel Logout 1.0 section 2.4.
 *
 * Deliberately free of framework concerns: what it produces is a string, and
 * everything it needs to produce one is passed in. That keeps the part of
 * back-channel logout with actual security content -- which claims go in the
 * token, and which combinations are refused -- testable on its own.
 */
class LogoutTokenBuilder
{
    /**
     * The event identifier that marks a JWT as a logout token. Section 2.4
     * requires the `events` claim to carry it as a key, with an empty JSON
     * object as its value.
     */
    public const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function __construct(
        private Configuration $config,
        private string $issuer,
        private ?string $kid = null,
    ) {
    }

    /**
     * Build a signed logout token for one audience.
     *
     * @param string      $audience  the client the token is addressed to
     * @param string|null $subject   the end-user whose session ended
     * @param string|null $sessionId the OP session that ended
     *
     * @throws InvalidArgumentException when neither a subject nor a session is given
     */
    public function build(
        string $audience,
        ?string $subject,
        ?string $sessionId,
        ?DateInterval $ttl = null,
    ): string {
        // Section 2.4: "A Logout Token MUST contain either a sub or a sid
        // Claim, and MAY contain both." A token with neither identifies no
        // session at all, so the RP could only respond by logging everyone out.
        if (($subject === null || $subject === '') && ($sessionId === null || $sessionId === '')) {
            throw new InvalidArgumentException(
                'A logout token must carry a sub claim, a sid claim, or both.',
            );
        }

        $issuedAt = new DateTimeImmutable();

        $builder = $this->config->builder();

        // Without this the token is unverifiable by any relying party that
        // fetches a JWKS with more than one key -- and by some that fetch one
        // with exactly one, since a keyed JWKS is selected by `kid` and a
        // library handed a key set with nothing to match on will refuse rather
        // than guess. The id_token carries the same header for the same reason.
        if ($this->kid !== null && $this->kid !== '') {
            $builder = $builder->withHeader('kid', $this->kid);
        }

        $builder = $builder
            ->issuedBy($this->issuer)
            ->permittedFor($audience)
            ->issuedAt($issuedAt)
            // Section 2.6 has the RP reject a jti it has seen before. Its value
            // to the RP is entirely in being unpredictable and unique, hence
            // random bytes rather than anything derived from the session.
            ->identifiedBy(bin2hex(random_bytes(16)))
            // An empty JSON *object*, not an empty array -- the distinction
            // survives into the encoded token, and an RP validating the shape
            // will refuse `[]`.
            ->withClaim('events', [self::EVENT => new stdClass()]);

        // Section 2.4 marks exp optional, but a logout token is delivered
        // immediately and acted on immediately; bounding it means one
        // intercepted off the wire is not replayable indefinitely against an RP
        // that does not track jti as thoroughly as it should.
        $builder = $builder->expiresAt($issuedAt->add($ttl ?? new DateInterval('PT2M')));

        if ($subject !== null && $subject !== '') {
            $builder = $builder->relatedTo($subject);
        }

        if ($sessionId !== null && $sessionId !== '') {
            $builder = $builder->withClaim('sid', $sessionId);
        }

        // Section 2.4: "A Logout Token MUST NOT contain a nonce Claim." The
        // prohibition exists so a logout token can never be mistaken for an
        // id_token by an RP that checks one and not the other. Nothing here
        // adds a nonce; the note is for whoever extends this next.

        return $builder->getToken(
            $this->config->signer(),
            $this->config->signingKey(),
        )->toString();
    }
}
