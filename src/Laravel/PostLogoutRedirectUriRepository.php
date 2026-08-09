<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Laravel\Passport\Passport;
use OpenIDConnect\Interfaces\PostLogoutRedirectUriRepositoryInterface;

/**
 * Default implementation: read the registered URIs from a
 * `post_logout_redirect_uris` attribute on the Passport client model.
 *
 * Passport's schema has no such column, so applications wanting to use this
 * default need to add one (a json column, or a text column cast to an array).
 * Until then nothing is registered and no redirect is ever honoured, which is
 * the safe direction to fail.
 */
class PostLogoutRedirectUriRepository implements PostLogoutRedirectUriRepositoryInterface
{
    public function isRegistered(string $clientIdentifier, string $uri): bool
    {
        $model = Passport::clientModel();

        $client = $model::find($clientIdentifier);

        if ($client === null) {
            return false;
        }

        $registered = $client->post_logout_redirect_uris ?? null;

        if (is_string($registered)) {
            $registered = preg_split('/[\s,]+/', $registered, -1, PREG_SPLIT_NO_EMPTY);
        }

        if (!is_array($registered)) {
            return false;
        }

        foreach ($registered as $candidate) {
            // OpenID Connect RP-Initiated Logout 1.0 section 2: the value is
            // compared using simple string comparison. No normalising, no
            // prefix matching -- a prefix match would let
            // https://rp.example.com.attacker.test through.
            if (is_string($candidate) && hash_equals($candidate, $uri)) {
                return true;
            }
        }

        return false;
    }
}
