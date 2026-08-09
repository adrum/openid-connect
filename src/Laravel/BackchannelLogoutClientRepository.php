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

        return $this->isDeliverable($uri) ? $uri : null;
    }

    /**
     * Whether this is somewhere the OP is willing to send a request.
     *
     * The value is registration data, so it is only as trustworthy as whoever
     * can write to the clients table -- and unlike a redirect_uri, which merely
     * points a browser somewhere, this one is fetched by the identity provider
     * itself, from inside the network. Left unchecked it is a server-side
     * request forgery primitive pointed at the OP: cloud metadata endpoints,
     * internal admin panels, anything the OP can reach and the internet cannot.
     *
     * The scheme check is the spec's own requirement (section 3.1, "MUST be an
     * https URL"); the host check is what makes the https one worth having,
     * since https://169.254.169.254/ satisfies the first on its own.
     */
    private function isDeliverable(string $uri): bool
    {
        $parts = parse_url($uri);

        if ($parts === false || ($parts['scheme'] ?? null) !== 'https') {
            Log::warning('OIDC back-channel logout: refusing a logout URI that is not https.', [
                'uri' => $uri,
            ]);

            return false;
        }

        $host = $parts['host'] ?? '';

        if ($host === '') {
            return false;
        }

        if (!config('openid.backchannel_logout.allow_private_hosts', false)
            && $this->isPrivateHost($host)) {
            Log::warning('OIDC back-channel logout: refusing a logout URI on a private address.', [
                'uri' => $uri,
            ]);

            return false;
        }

        return true;
    }

    /**
     * Whether the host resolves somewhere only the OP can reach.
     *
     * Literal addresses are checked directly. Names are resolved first,
     * because a name is free to point at 127.0.0.1 -- and commonly does, in
     * exactly the setups where this matters.
     *
     * This is not a complete SSRF defence and cannot be: resolution here and
     * resolution at connect time are separate lookups, so a name that changes
     * between them slips through. It raises the cost considerably, and the
     * registration table remains the real trust boundary.
     */
    private function isPrivateHost(string $host): bool
    {
        $addresses = filter_var($host, FILTER_VALIDATE_IP)
            ? [$host]
            : array_merge(
                gethostbynamel($host) ?: [],
                // AAAA records, which gethostbynamel does not return.
                array_column(@dns_get_record($host, DNS_AAAA) ?: [], 'ipv6'),
            );

        if ($addresses === []) {
            // Resolves to nothing. Not necessarily hostile, but not
            // deliverable either, and refusing is the cheaper mistake.
            return true;
        }

        foreach ($addresses as $address) {
            $public = filter_var(
                $address,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
            );

            if ($public === false) {
                return true;
            }
        }

        return false;
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
