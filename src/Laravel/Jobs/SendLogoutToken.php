<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use RuntimeException;

/**
 * Delivers one logout token to one relying party.
 *
 * Queued, because the end-user is waiting on a logout and their session has
 * already been destroyed by the time this runs. A relying party that is slow
 * or down is not a reason to make them wait, and it is emphatically not a
 * reason to fail their logout -- so delivery is retried out of band instead.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html section 2.5
 */
class SendLogoutToken implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    /**
     * Spread out rather than uniform: an identity provider restarting takes
     * every relying party's endpoint down at once, and retrying them all on
     * the same schedule reproduces the thundering herd that caused it.
     *
     * @var int[]
     */
    public array $backoff = [10, 60, 300];

    public int $tries = 4;

    public function __construct(
        private string $uri,
        private string $logoutToken,
        private string $clientIdentifier,
    ) {
    }

    public function handle(): void
    {
        $response = Http::asForm()
            ->timeout((int) config('openid.backchannel_logout.timeout', 5))
            // Section 2.5: the OP does not follow redirects here. A redirect is
            // a misconfigured endpoint, and following one would deliver the
            // token -- and with it the fact that this user's session ended --
            // somewhere the client never registered.
            ->withoutRedirecting()
            ->withHeaders([
                // Section 2.5 requires both, so that a logout token is never
                // served from a cache or logged by an intermediary.
                'Cache-Control' => 'no-cache, no-store',
                'Pragma' => 'no-cache',
            ])
            ->post($this->uri, ['logout_token' => $this->logoutToken]);

        if ($response->successful()) {
            return;
        }

        // Thrown rather than logged-and-swallowed so the queue's retry and
        // failure handling applies. The token is short-lived, so by the last
        // attempt it may be too late regardless -- which is the point at which
        // an operator needs to know, and a failed job is how they find out.
        throw new RuntimeException(sprintf(
            'Back-channel logout for client [%s] was rejected with HTTP %d.',
            $this->clientIdentifier,
            $response->status(),
        ));
    }

    public function failed(\Throwable $e): void
    {
        Log::warning('OIDC back-channel logout: giving up on a relying party.', [
            'client_id' => $this->clientIdentifier,
            // The URI is logged; the token is not. It is a bearer credential
            // for ending a session, and it outlives the log line.
            'uri' => $this->uri,
            'exception' => $e->getMessage(),
        ]);
    }
}
