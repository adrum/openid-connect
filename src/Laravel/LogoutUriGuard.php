<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

/**
 * Decides whether a registered logout URI is somewhere this server is willing
 * to send a request.
 *
 * The value is registration data, so it is only as trustworthy as whoever can
 * write to the clients table. Unlike a redirect_uri, which merely points a
 * browser somewhere, this one is fetched by the identity provider itself from
 * inside the network -- which makes an unchecked value a server-side request
 * forgery primitive aimed at the OP: cloud metadata endpoints, internal admin
 * panels, anything the OP can reach and the internet cannot.
 *
 * Resolving a host costs a DNS round trip, which is why this is consulted on
 * the queue at delivery time rather than in the logout request the end-user is
 * waiting on.
 *
 * It is not a complete defence and cannot be: this lookup and the one the HTTP
 * client makes when it connects are separate, so a name that changes in
 * between still gets through. It raises the cost of a hostile registration
 * considerably; the clients table remains the real trust boundary.
 */
class LogoutUriGuard
{
    public function isDeliverable(string $uri): bool
    {
        if (config('openid.backchannel_logout.allow_private_hosts', false)) {
            return true;
        }

        $host = parse_url($uri, PHP_URL_HOST);

        if (!is_string($host) || $host === '') {
            return false;
        }

        // parse_url keeps the brackets on an IPv6 literal; the filters do not
        // want them.
        $host = trim($host, '[]');

        return !$this->isPrivate($host);
    }

    private function isPrivate(string $host): bool
    {
        $addresses = filter_var($host, FILTER_VALIDATE_IP)
            ? [$host]
            : $this->resolve($host);

        if ($addresses === []) {
            // Resolves to nothing, so it is not deliverable in any case.
            // Refusing is the cheaper of the two mistakes available here.
            return true;
        }

        foreach ($addresses as $address) {
            $isPublic = filter_var(
                $address,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
            );

            // Every address the name answers with has to be acceptable. One
            // private answer is enough to refuse, because which one the HTTP
            // client ends up using is not ours to choose.
            if ($isPublic === false) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return string[]
     */
    private function resolve(string $host): array
    {
        $v4 = gethostbynamel($host) ?: [];

        // gethostbynamel is IPv4 only, and a name that answers only on AAAA
        // would otherwise look unresolvable.
        $v6 = array_column(@dns_get_record($host, DNS_AAAA) ?: [], 'ipv6');

        return array_merge($v4, $v6);
    }
}
