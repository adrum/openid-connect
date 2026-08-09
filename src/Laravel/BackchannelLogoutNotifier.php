<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use DateInterval;
use Illuminate\Support\Facades\Log;
use OpenIDConnect\Interfaces\BackchannelLogoutClientRepositoryInterface;
use OpenIDConnect\Interfaces\SessionClientRegistryInterface;
use OpenIDConnect\Laravel\Jobs\SendLogoutToken;
use OpenIDConnect\LogoutTokenBuilder;
use Throwable;

/**
 * Tells the relying parties that shared a session that it has ended.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html
 */
class BackchannelLogoutNotifier
{
    public function __construct(
        private SessionClientRegistryInterface $registry,
        private BackchannelLogoutClientRepositoryInterface $clients,
        private PassportJwtConfiguration $jwt,
    ) {
    }

    /**
     * Notify every relying party that took part in this session.
     *
     * The two identifiers answer different questions: `sid` says which session
     * ended, `sub` says whose. A relying party keyed on `sub` alone ends all of
     * that user's sessions everywhere, which is why an OP that can supply `sid`
     * should.
     */
    public function notify(?string $sessionId, ?string $subject): void
    {
        if (!config('openid.backchannel_logout.enabled', false)) {
            return;
        }

        if ($sessionId === null || $sessionId === '') {
            // Participation is recorded against the session, not the user, so
            // there is nothing to look up. Falling back to "every client this
            // user ever authorized" would reach applications they are not
            // currently signed in to, and tell those applications that the user
            // signed out of something else.
            return;
        }

        $clients = $this->registry->clientsFor($sessionId);

        if ($clients === []) {
            return;
        }

        $builder = new LogoutTokenBuilder(
            $this->jwt->forSigning(),
            $this->issuer(),
            // The same key identifier the JWKS endpoint publishes, so a relying
            // party can pick the right key out of the set.
            JwksController::computeKidFromPublicKey(JwksController::getPublicKey()),
        );

        $includeSubject = (bool) config('openid.backchannel_logout.include_subject', true);

        foreach ($clients as $clientIdentifier) {
            $uri = $this->clients->logoutUriFor($clientIdentifier);

            if ($uri === null) {
                // Registered nothing, so wants nothing. Not an error: plenty of
                // clients are APIs with no browser session to end.
                continue;
            }

            try {
                $token = $builder->build(
                    $clientIdentifier,
                    $includeSubject ? $subject : null,
                    $sessionId,
                    $this->tokenTtl(),
                );
            } catch (Throwable $e) {
                // One client's token failing to build must not stop the
                // fan-out; the whole point is that the others still get told.
                Log::warning('OIDC back-channel logout: could not build a logout token.', [
                    'client_id' => $clientIdentifier,
                    'exception' => $e->getMessage(),
                ]);

                continue;
            }

            SendLogoutToken::dispatch($uri, $token, $clientIdentifier)
                ->onQueue(config('openid.backchannel_logout.queue'));
        }

        // Dropped once dispatched. The session is over, so the mapping has no
        // further use, and leaving it would let a later logout that landed on a
        // recycled session identifier notify the wrong clients.
        $this->registry->forget($sessionId);
    }

    /**
     * How long a logout token stays valid.
     *
     * Has to outlast SendLogoutToken's retry schedule: the token is minted once
     * and every retry re-sends it, so anything scheduled past this point is
     * delivering something the relying party must reject.
     */
    private function tokenTtl(): DateInterval
    {
        $seconds = (int) config('openid.backchannel_logout.token_ttl', 120);

        return new DateInterval('PT' . max(1, $seconds) . 'S');
    }

    /**
     * The `iss` of the logout token, which the relying party checks against the
     * issuer it knows. Shares the end session endpoint's pinned value for the
     * same reason: url('/') follows the incoming request, and behind a
     * TLS-terminating proxy that produces an issuer no relying party accepts.
     */
    private function issuer(): string
    {
        $configured = config('openid.end_session.issuer');

        if (is_string($configured) && $configured !== '') {
            return rtrim($configured, '/');
        }

        return rtrim(url('/'), '/');
    }
}
