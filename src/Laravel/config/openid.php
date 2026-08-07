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
         * Middleware for the end session endpoint. It needs whatever group
         * starts the session, since it has to be able to end it.
         */
        'middleware' => ['web'],

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
