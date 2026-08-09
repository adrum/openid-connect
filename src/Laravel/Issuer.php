<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

/**
 * The one value this OP calls itself.
 *
 * Every part of OpenID Connect that crosses a trust boundary compares issuers
 * for exact equality: a relying party checks the `iss` of an id_token against
 * what discovery advertised, the end session endpoint checks the `iss` of an
 * id_token_hint against what it minted, and a back-channel logout token is
 * accepted or refused on the same basis.
 *
 * The natural default, url('/'), derives that value from the incoming request.
 * Behind a TLS-terminating proxy without trusted proxies configured, a request
 * arriving as http produces `http://...` while the request that minted the
 * token produced `https://...`, and every one of those comparisons fails. The
 * symptom is not an error but a slow discovery that single sign-on has stopped
 * working, with each half of it blaming the other.
 *
 * Pinning it here makes the value a decision rather than an accident, and
 * makes it the same decision everywhere.
 */
class Issuer
{
    public static function resolve(): string
    {
        $configured = config('openid.issuer');

        if (is_string($configured) && $configured !== '') {
            return rtrim($configured, '/');
        }

        // Predates openid.issuer, and applications are still setting it.
        $legacy = config('openid.end_session.issuer');

        if (is_string($legacy) && $legacy !== '') {
            return rtrim($legacy, '/');
        }

        return rtrim(url('/'), '/');
    }
}
