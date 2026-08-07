<?php

declare(strict_types=1);

return [
    'passport' => [

        /**
         * Place your Passport and OpenID Connect scopes here.
         * To receive an `id_token, you should at least provide the openid scope.
         */
        'tokens_can' => [
            'openid' => 'Enable OpenID Connect',
            'profile' => 'Information about your profile',
            'email' => 'Information about your email address',
            'phone' => 'Information about your phone numbers',
            'address' => 'Information about your address',
            // 'login' => 'See your login information',
        ],
    ],

    /**
     * Place your custom claim sets here.
     */
    'custom_claim_sets' => [
        // 'login' => [
        //     'last-login',
        // ],
        // 'company' => [
        //     'company_name',
        //     'company_address',
        //     'company_phone',
        //     'company_email',
        // ],
    ],

    /**
     * You can override the repositories below.
     */
    'repositories' => [
        'identity' => \OpenIDConnect\Repositories\IdentityRepository::class,
        'scope' => \OpenIDConnect\Repositories\ScopeRepository::class,
    ],

    /**
     * The signer to be used
     * Can be Ecdsa, Hmac or RSA
     */
    'signer' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,

    'routes' => [
        /**
         * When set to true, this package will expose the OpenID Connect Discovery endpoint.
         *  - /.well-known/openid-configuration
         */
        'discovery' => true,
        /**
         * When set to true, this package will expose the JSON Web Key Set endpoint.
         * - /oauth/jwks
         */
        'jwks' => true,
        /**
         * When set to true, this package will expose the RP-Initiated Logout
         * end session endpoint.
         * - /oauth/logout
         *
         * Off by default: it adds a route that ends user sessions, so opting
         * in should be a decision rather than an upgrade side effect.
         */
        'end_session' => false,
    ],

    /**
     * RP-Initiated Logout. Only relevant when routes.end_session is enabled.
     *
     * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
     */
    'end_session' => [
        /**
         * The path the end session endpoint is served from.
         */
        'path' => 'oauth/logout',

        /**
         * Middleware for the end session endpoint. It needs whatever group
         * starts the session, since it has to be able to end it.
         */
        'middleware' => ['web'],

        /**
         * When to ask the end-user to confirm before ending their session.
         *
         *   'unverified' (default) - prompt unless the request carries a
         *                            verified id_token_hint issued to the
         *                            signed-in user.
         *   'always'               - always prompt.
         *   'never'                - never prompt.
         *
         * The default is what section 2 asks for:
         *
         *   "the OP SHOULD ask the End-User whether to log out of the OP as
         *    well. Furthermore, the OP MUST ask the End-User this question if
         *    an id_token_hint was not provided or if the supplied ID Token
         *    does not belong to the current OP session with the RP and/or
         *    currently logged in End-User."
         *
         * It also draws the line in the right place in practice. The endpoint
         * answers GET, and a GET carries no CSRF token, so a request with no
         * hint may be a drive-by <img src="...end_session"> that ends the
         * user's session -- and every SSO session behind it -- without them
         * doing anything. A verified hint for the signed-in user cannot be
         * that, which is why it is the one case allowed to skip the prompt,
         * and it is also every legitimate RP-initiated logout.
         *
         * true and false are accepted as aliases for 'always' and 'never'.
         */
        'confirm' => 'unverified',

        /**
         * The `iss` an id_token_hint must carry. Null derives it from url('/').
         *
         * That default follows the incoming request, so an OP behind a
         * TLS-terminating proxy without trusted proxies configured reports
         * http:// while its own id_tokens say https://. Every hint then fails
         * the issuer check and single sign-out quietly stops working. Pin it
         * if the app is not guaranteed to see a consistent scheme and host.
         */
        'issuer' => null,

        /**
         * The view rendered when confirm is enabled. Publish the package views
         * with `php artisan vendor:publish --tag=openid-views` to restyle it,
         * or point this at your own. For anything beyond a view -- an Inertia
         * page, say -- bind LogoutConfirmationInterface instead.
         */
        'confirmation_view' => 'openid::logout-confirm',

        /**
         * The guard whose session is ended.
         */
        'guard' => 'web',

        /**
         * Require a verified id_token_hint before honouring a
         * post_logout_redirect_uri.
         *
         * With this off, a bare client_id is accepted as the RP's identity.
         * That is permitted by the spec and the redirect is still restricted
         * to URIs registered by that client, but the claim itself is
         * unauthenticated -- anyone can name any client.
         */
        'require_id_token_hint' => true,

        /**
         * Where the browser goes when there is no usable
         * post_logout_redirect_uri. The logout itself has already happened by
         * this point.
         */
        'default_redirect' => '/',
    ],
];
