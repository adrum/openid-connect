<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

class DiscoveryController
{
    public function __invoke(Request $request)
    {
        $response = [
            'issuer' => Issuer::resolve(),
            'authorization_endpoint' => route('passport.authorizations.authorize'),
            'token_endpoint' => route('passport.token'),
            'jwks_uri' => route('openid.jwks'),
            'response_types_supported' => [
                'code',
                'token',
                'id_token',
                'code token',
                'code id_token',
                'token id_token',
                'code token id_token',
                'none',
            ],
            'subject_types_supported' => [
                'public',
            ],
            'id_token_signing_alg_values_supported' => [
                'RS256',
            ],
            'scopes_supported' => array_keys(config('openid.passport.tokens_can')),
            'token_endpoint_auth_methods_supported' => [
                'client_secret_basic',
                'client_secret_post',
            ],
            /**
             * Required by RFC 8414 for any server supporting PKCE. The
             * underlying league/oauth2-server AuthCodeGrant binds and verifies
             * a code_challenge whenever the client sends one — for
             * confidential clients as well as public ones — but without this
             * key a relying party has no way to discover that, and several
             * OIDC client libraries skip PKCE entirely when it is absent.
             *
             * Only S256 is advertised. The grant also accepts `plain`, but
             * offering it here would invite clients to downgrade to it for no
             * benefit.
             */
            'code_challenge_methods_supported' => [
                'S256',
            ],
        ];

        if (Route::has('openid.userinfo')) {
            $response['userinfo_endpoint'] = route('openid.userinfo');
        }

        if (Route::has('openid.end_session_endpoint')) {
            $response['end_session_endpoint'] = route('openid.end_session_endpoint');
        }

        if (config('openid.backchannel_logout.enabled', false)) {
            $response['backchannel_logout_supported'] = true;

            /**
             * Advertised together, because this OP always puts a `sid` in the
             * logout tokens it sends. A relying party reads this key to decide
             * whether it may key its own sessions on `sid` instead of falling
             * back to logging the subject out of everything -- so claiming it
             * while sometimes omitting the claim would strand precisely the
             * relying parties that believed it.
             */
            $response['backchannel_logout_session_supported'] = true;
        }

        return response()->json($response, 200, [], JSON_PRETTY_PRINT);
    }
}
