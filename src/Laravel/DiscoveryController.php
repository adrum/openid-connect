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
            'issuer' => url('/'),
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
        ];

        if (Route::has('openid.userinfo')) {
            $response['userinfo_endpoint'] = route('openid.userinfo');
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
