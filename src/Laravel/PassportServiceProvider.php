<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Illuminate\Encryption\Encrypter;
use Laravel\Passport;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Bridge\ClientRepository;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Nyholm\Psr7\Response;
use OpenIDConnect\ClaimExtractor;
use OpenIDConnect\Claims\ClaimSet;
use OpenIDConnect\Grant\AuthCodeGrant;
use OpenIDConnect\IdTokenResponse;
use OpenIDConnect\Interfaces\BackchannelLogoutClientRepositoryInterface;
use OpenIDConnect\Interfaces\LogoutConfirmationInterface;
use OpenIDConnect\Interfaces\PostLogoutRedirectUriRepositoryInterface;
use OpenIDConnect\Interfaces\SessionClientRegistryInterface;
use OpenIDConnect\Interfaces\SessionIdResolverInterface;
use OpenIDConnect\Interfaces\SessionLogoutHandlerInterface;

class PassportServiceProvider extends Passport\PassportServiceProvider
{
    public function register(): void
    {
        parent::register();

        $this->mergeConfigFrom(
            __DIR__ . '/config/openid.php',
            'openid',
        );

        // bindIf so an application can override either seam by binding its own
        // implementation before this provider registers.
        $this->app->bindIf(SessionLogoutHandlerInterface::class, SessionLogoutHandler::class);
        $this->app->bindIf(PostLogoutRedirectUriRepositoryInterface::class, PostLogoutRedirectUriRepository::class);
        $this->app->bindIf(LogoutConfirmationInterface::class, LogoutConfirmation::class);
        $this->app->bindIf(SessionClientRegistryInterface::class, SessionClientRegistry::class);
        $this->app->bindIf(
            BackchannelLogoutClientRepositoryInterface::class,
            BackchannelLogoutClientRepository::class,
        );

        // Resolved from the request rather than injected, because the container
        // binds `session` to the session manager and this needs the store the
        // current request is actually using.
        $this->app->bindIf(
            SessionIdResolverInterface::class,
            fn ($app) => new SessionIdResolver($app['session.store']),
        );
    }

    public function boot(): void
    {
        parent::boot();

        $this->publishes([
            __DIR__ . '/config/openid.php' => $this->app->configPath('openid.php'),
        ], ['openid', 'openid-config']);

        $this->loadViewsFrom(__DIR__ . '/views', 'openid');

        $this->publishes([
            __DIR__ . '/views' => $this->app->resourcePath('views/vendor/openid'),
        ], ['openid', 'openid-views']);

        // Published rather than loaded, so that an application not using
        // back-channel logout does not get a table it has no use for -- and so
        // that one that is can control when it lands.
        $this->publishes([
            __DIR__ . '/migrations' => $this->app->databasePath('migrations'),
        ], ['openid', 'openid-migrations']);

        $this->loadRoutesFrom(__DIR__ . '/routes/web.php');

        $tokens_can = config('openid.passport.tokens_can', null);
        if ($tokens_can) {
            Passport\Passport::tokensCan($tokens_can);
        }

        $this->registerClaimExtractor();
    }

    protected function makeAuthorizationServer(?ResponseTypeInterface $responseType = null): AuthorizationServer
    {
        $cryptKey = $this->makeCryptKey('private');
        $encryptionKey = Passport\Passport::tokenEncryptionKey(app(Encrypter::class));

        $responseType ??= new IdTokenResponse(
            app(config('openid.repositories.identity')),
            app(ClaimExtractor::class),
            Configuration::forSymmetricSigner(
                app(config('openid.signer')),
                InMemory::plainText($cryptKey->getKeyContents()),
            ),
            app(LaravelCurrentRequestService::class),
            $encryptionKey,
            JwksController::computeKidFromPublicKey(JwksController::getPublicKey()),
            $this->backchannelLogoutEnabled()
                ? app(SessionClientRegistryInterface::class)
                : null,
            // Pinned rather than derived from the request that happens to be
            // exchanging the code, so the `iss` in an id_token matches the one
            // discovery advertises and the one the end session endpoint expects
            // back in an id_token_hint.
            Issuer::resolve(),
        );

        return new AuthorizationServer(
            app(ClientRepository::class),
            app(AccessTokenRepository::class),
            app(config('openid.repositories.scope')),
            $cryptKey,
            $encryptionKey,
            $responseType,
        );
    }

    /**
     * Build the Auth Code grant instance.
     */
    protected function buildAuthCodeGrant(): AuthCodeGrant
    {
        return new AuthCodeGrant(
            $this->app->make(Passport\Bridge\AuthCodeRepository::class),
            $this->app->make(Passport\Bridge\RefreshTokenRepository::class),
            new \DateInterval('PT10M'),
            new Response(),
            $this->app->make(LaravelCurrentRequestService::class),
            // Null when back-channel logout is off, which is what keeps `sid`
            // out of id_tokens until the application opts in.
            $this->backchannelLogoutEnabled()
                ? $this->app->make(SessionIdResolverInterface::class)
                : null,
        );
    }

    /**
     * Whether the application has opted into Back-Channel Logout.
     */
    protected function backchannelLogoutEnabled(): bool
    {
        return (bool) config('openid.backchannel_logout.enabled', false);
    }

    public function registerClaimExtractor(): void
    {
        $this->app->singleton(ClaimExtractor::class, function () {
            $customClaimSets = config('openid.custom_claim_sets');

            $claimSets = array_map(function ($claimSet, $name) {
                return new ClaimSet($name, $claimSet);
            }, $customClaimSets, array_keys($customClaimSets));

            return new ClaimExtractor(...$claimSets);
        });
    }
}
