<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Illuminate\Support\Facades\Log;
use Laravel\Passport\Passport;
use OpenIDConnect\Interfaces\BackchannelLogoutClientRepositoryInterface;

/**
 * Default implementation: read the registration from attributes on the
 * Passport client model.
 *
 * Passport's schema has no such column, so applications opting into
 * back-channel logout need to add a `backchannel_logout_uri` string column.
 * Until then no client has an endpoint registered and none is notified, which
 * is the safe direction to fail: a logout that notifies nobody leaves stale RP
 * sessions, whereas one that posts tokens to an unvetted URI tells a third
 * party when and for whom sessions end.
 */
class BackchannelLogoutClientRepository implements BackchannelLogoutClientRepositoryInterface
{
    public function logoutUriFor(string $clientIdentifier): ?string
    {
        $client = $this->find($clientIdentifier);

        $uri = $client->backchannel_logout_uri ?? null;

        if (!is_string($uri) || $uri === '') {
            return null;
        }

        // Only the cheap half of the vetting happens here. This runs inside the
        // logout request the end-user is waiting on, so it must not do I/O --
        // the half that resolves the host lives in LogoutUriGuard and runs on
        // the queue, at delivery time.
        //
        // Section 3.1: the registered URI "MUST be an https URL".
        if (!str_starts_with($uri, 'https://')) {
            Log::warning('OIDC back-channel logout: refusing a logout URI that is not https.', [
                'client_id' => $clientIdentifier,
            ]);

            return null;
        }

        return $uri;
    }

    /**
     * @return object|null
     */
    private function find(string $clientIdentifier)
    {
        $model = Passport::clientModel();

        return $model::find($clientIdentifier);
    }
}
