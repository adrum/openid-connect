<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

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

        return is_string($uri) && $uri !== '' ? $uri : null;
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
