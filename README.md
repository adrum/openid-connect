# OpenID Connect

OpenID Connect support to the PHP League's OAuth2 Server.

**Compatible with [Laravel Passport](https://laravel.com/docs/8.x/passport)!**

## Requirements

* Requires PHP version `^7.4|^8.0`.
* [lcobucci/jwt](https://github.com/lcobucci/jwt) version `^4.0`.
* [league/oauth2-server](https://github.com/thephpleague/oauth2-server) `^8.2`.

## Installation
```sh
composer require ronvanderheijden/openid-connect
```

## Keys

To sign and encrypt the tokens, we need a private and a public key.
```sh
mkdir -m 700 -p tmp

openssl genrsa -out tmp/private.key 2048
openssl rsa -in tmp/private.key -pubout -out tmp/public.key

chmod 600 tmp/private.key
chmod 644 tmp/public.key
```

## Example
I recommend to [read this](https://oauth2.thephpleague.com/authorization-server/auth-code-grant/) first.

To enable OpenID Connect, follow these simple steps

```php
$privateKeyPath = 'tmp/private.key';

$currentRequestService = new CurrentRequestService();
$currentRequestService->setRequest(ServerRequestFactory::fromGlobals());

// create the response_type
$responseType = new IdTokenResponse(
    new IdentityRepository(),
    new ClaimExtractor(),
    Configuration::forSymmetricSigner(
        new Sha256(),
        InMemory::file($privateKeyPath),
    ),
    $currentRequestService,
    $encryptionKey,
);

$server = new \League\OAuth2\Server\AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKeyPath,
    $encryptionKey,
    // add the response_type
    $responseType,
);
```

Now when calling the `/authorize` endpoint, provide the `openid` scope to get an `id_token`.  
Provide more scopes (e.g. `openid profile email`) to receive additional claims in the `id_token`.

For a complete implementation, visit [the OAuth2 Server example](https://github.com/ronvanderheijden/openid-connect/tree/main/example).

## Nonce support

To prevent replay attacks, some clients can provide a "nonce" in the authorization request. If a client does so, the
server MUST include back a `nonce` claim in the `id_token`.

To enable this feature, when registering an AuthCodeGrant, you need to use the `\OpenIDConnect\Grant\AuthCodeGrant` 
instead of `\League\OAuth2\Server\Grant\AuthCodeGrant`.

> ![NOTE]
> If you are using Laravel, the `AuthCodeGrant` is already registered for you by the service provider.

## Laravel Passport

You can use this package with Laravel Passport in 2 simple steps.

### 1.) add the service provider
```php
# config/app.php
'providers' => [
    /*
     * Package Service Providers...
     */
    OpenIDConnect\Laravel\PassportServiceProvider::class,
],
```

### 2.) create an entity
Create an entity class in `app/Entities/` named `IdentityEntity` or `UserEntity`. This entity is used to collect the claims.
```php
# app/Entities/IdentityEntity.php
namespace App\Entities;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use OpenIDConnect\Claims\Traits\WithClaims;
use OpenIDConnect\Interfaces\IdentityEntityInterface;

class IdentityEntity implements IdentityEntityInterface
{
    use EntityTrait;
    use WithClaims;

    /**
     * The user to collect the additional information for
     */
    protected User $user;

    /**
     * The identity repository creates this entity and provides the user id
     * @param mixed $identifier
     */
    public function setIdentifier($identifier): void
    {
        $this->identifier = $identifier;
        $this->user = User::findOrFail($identifier);
    }

    /**
     * When building the id_token, this entity's claims are collected
     */
    public function getClaims(): array
    {
        return [
            'email' => $this->user->email,
        ];
    }
}
```

### Publishing the config
In case you want to change the default scopes, add custom claim sets or change the repositories, you can publish the openid config using:
```sh
php artisan vendor:publish --tag=openid
```

### Discovery and JWKS

The Laravel Passport integration also provides:

- a discovery endpoint at `/.well-known/openid-configuration`.
- a JWKS endpoint at `/oauth/jwks`.

Those 2 endpoints are automatically added to the Laravel routes and can be disabled from the config (using
the `openid.routes.discovery` and `openid.routes.jwks` keys).

Laravel Passport does not provide a `userinfo` endpoint by default. If you provide one, you can add it to the 
discovery document by naming the route `openid.userinfo`.

```php
Route::get('/oauth/userinfo', 'YourController@userinfo')->middleware('xxx')->name('openid.userinfo');
```

### RP-Initiated Logout

An [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) end session
endpoint is available at `/oauth/logout`, letting a relying party end the user's session at the OP.
It is disabled by default; enable it with the `openid.routes.end_session` config key.

The endpoint always ends the local session. The request parameters only decide where the browser is
sent afterwards:

- `id_token_hint` — an id_token previously issued by this OP. Its signature is verified and its
  `aud` identifies the requesting client. Expiry is deliberately *not* checked, since by the time a
  user logs out their id_token has usually expired.
- `post_logout_redirect_uri` — only honoured when it exactly matches a URI registered by that
  client. Anything else falls back to `openid.end_session.default_redirect`.
- `state` — echoed back on the redirect, if one happens.
- `client_id` — accepted in place of `id_token_hint` only when
  `openid.end_session.require_id_token_hint` is set to `false`.

Registered URIs are read from a `post_logout_redirect_uris` attribute on the Passport client model.
Passport's schema has no such column, so add one:

```php
Schema::table('oauth_clients', function (Blueprint $table) {
    $table->json('post_logout_redirect_uris')->nullable();
});
```

```php
// on your client model
protected $casts = ['post_logout_redirect_uris' => 'array'];
```

Until that column exists nothing is registered, so no redirect is ever honoured — the endpoint logs
the user out and sends them to `default_redirect`. **Do not** substitute an implementation that
accepts the URI as given: that turns the endpoint into an open redirect on your identity provider's
origin.

#### Asking the user to confirm

The endpoint answers `GET`, and a `GET` carries no CSRF token, so by default any page on the internet
can end a user's session at the OP with nothing more than an `<img>` tag — and with it every SSO
session that session backs. Section 2 recommends prompting the user for this reason. Enable it with
`openid.end_session.confirm`.

When it's on, a logout request with a live session renders a confirmation page instead of acting.
The request is parked server side and the page posts back a one-time token; the parameters used are
the parked ones, not the resubmitted ones, so a tampered form can't swap in a different
`post_logout_redirect_uri` after the user has seen the page. Requests with no session to end skip
the prompt.

Restyle the page by publishing the views, or point `openid.end_session.confirmation_view` at your
own:

```sh
php artisan vendor:publish --tag=openid-views
```

For anything that isn't a Blade view — an Inertia page, a SPA route — bind
`LogoutConfirmationInterface` instead.

#### Replaceable pieces

- `SessionLogoutHandlerInterface` — what "logged out" means.
- `PostLogoutRedirectUriRepositoryInterface` — where registrations live.
- `LogoutConfirmationInterface` — how the user is asked to confirm.

The endpoint path is `openid.end_session.path`, in case `oauth/logout` is already taken in your app.

The spec requires the endpoint to accept `POST` as well as `GET`. A logout redirect arriving from
another origin carries no CSRF token, so exclude the route from CSRF verification if you want the
`POST` form to work:

```php
// bootstrap/app.php
$middleware->validateCsrfTokens(except: ['oauth/logout']);
```

The route is named `openid.end_session_endpoint`, which the discovery document picks up and publishes
as `end_session_endpoint` automatically.

## Support
Found a bug? Got a feature request?  [Create an issue](https://github.com/ronvanderheijden/openid-connect/issues).

## License
OpenID Connect is open source and licensed under [the MIT licence](https://github.com/ronvanderheijden/openid-connect/blob/master/LICENSE.txt).
