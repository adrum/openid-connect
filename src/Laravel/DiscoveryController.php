<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Passport;

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
            'grant_types_supported' => $this->grantTypesSupported(),
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

        if ($this->deviceCodeGrantEnabled()) {
            $response['device_authorization_endpoint'] = route('passport.device.code');
        }

        if (Route::has('openid.userinfo')) {
            $response['userinfo_endpoint'] = route('openid.userinfo');
        }

        return response()->json($response, 200, [], JSON_PRETTY_PRINT);
    }

    /**
     * The grants Passport has enabled on the token endpoint.
     *
     * Without this key a relying party has to assume the OpenID Connect
     * Discovery default of `authorization_code` and `implicit`, which hides
     * the refresh token, client credentials and device code grants from any
     * client that configures itself from this document.
     *
     * @return string[]
     */
    private function grantTypesSupported(): array
    {
        $grantTypes = [
            'authorization_code',
            'refresh_token',
            'client_credentials',
        ];

        if (Passport::$implicitGrantEnabled) {
            $grantTypes[] = 'implicit';
        }

        if (Passport::$passwordGrantEnabled) {
            $grantTypes[] = 'password';
        }

        if ($this->deviceCodeGrantEnabled()) {
            $grantTypes[] = 'urn:ietf:params:oauth:grant-type:device_code';
        }

        return $grantTypes;
    }

    /**
     * Whether the RFC 8628 device authorization grant is available.
     *
     * Mirrors the check Passport makes before enabling the grant on the
     * authorization server, so discovery never advertises a flow the token
     * endpoint would reject.
     */
    private function deviceCodeGrantEnabled(): bool
    {
        return Passport::$deviceCodeGrantEnabled
            && Route::has('passport.device')
            && Route::has('passport.device.code');
    }
}
