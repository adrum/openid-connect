<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use OpenIDConnect\Interfaces\PostLogoutRedirectUriRepositoryInterface;
use OpenIDConnect\Interfaces\SessionLogoutHandlerInterface;
use Throwable;

/**
 * OpenID Connect RP-Initiated Logout 1.0 end session endpoint.
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 *
 * The endpoint always ends the local session -- that is what the end-user came
 * here for, and no part of the request can be trusted to decide otherwise. The
 * request parameters only ever decide *where the browser goes next*, which is
 * why the redirect is gated on a registered value rather than taken as given.
 */
class EndSessionController
{
    private SessionLogoutHandlerInterface $logoutHandler;

    private PostLogoutRedirectUriRepositoryInterface $redirectUris;

    public function __construct(
        SessionLogoutHandlerInterface $logoutHandler,
        PostLogoutRedirectUriRepositoryInterface $redirectUris
    ) {
        $this->logoutHandler = $logoutHandler;
        $this->redirectUris = $redirectUris;
    }

    public function __invoke(Request $request): RedirectResponse
    {
        // Resolved before the session is destroyed so the two concerns stay
        // independent of each other.
        $clientId = $this->resolveClient($request);

        $this->logoutHandler->logout($request);

        $redirectUri = $this->resolvePostLogoutRedirectUri($request, $clientId);

        if ($redirectUri === null) {
            return redirect()->to((string) config('openid.end_session.default_redirect', '/'));
        }

        $state = $request->input('state');

        if (is_string($state) && $state !== '') {
            $redirectUri .= (strpos($redirectUri, '?') === false ? '?' : '&')
                . http_build_query(['state' => $state]);
        }

        return redirect()->away($redirectUri);
    }

    /**
     * Attribute the logout request to a client, or null if it cannot be
     * attributed to one.
     */
    private function resolveClient(Request $request): ?string
    {
        $idTokenHint = $request->input('id_token_hint');

        if (is_string($idTokenHint) && $idTokenHint !== '') {
            return $this->clientFromIdTokenHint($idTokenHint);
        }

        // Section 2 allows client_id to identify the RP on its own, but it is
        // an unauthenticated assertion: anyone can name any client and reach
        // that client's registered URIs. The registration check still applies,
        // so this is bounded rather than open, but it defaults to off.
        if (config('openid.end_session.require_id_token_hint', true)) {
            return null;
        }

        $clientId = $request->input('client_id');

        return is_string($clientId) && $clientId !== '' ? $clientId : null;
    }

    /**
     * Verify an id_token_hint and return the client it was issued to.
     */
    private function clientFromIdTokenHint(string $idToken): ?string
    {
        try {
            $configuration = $this->jwtConfiguration();

            $token = $configuration->parser()->parse($idToken);

            $verified = $configuration->validator()->validate(
                $token,
                new SignedWith($configuration->signer(), $configuration->verificationKey())
            );

            if (! $verified) {
                return null;
            }
        } catch (Throwable $e) {
            // A malformed or unverifiable hint is not fatal: the user is still
            // logged out, they just do not get redirected back to the RP.
            Log::debug('OIDC end session: id_token_hint could not be verified.', ['exception' => $e]);

            return null;
        }

        // exp is deliberately not checked. Section 2 describes the
        // id_token_hint as the token "previously issued by the OP to the RP",
        // and by the time a user logs out it has usually expired -- rejecting
        // expired hints would break the common case. Its value here is proof
        // of which client is asking, and the signature alone establishes that.
        $claims = $token->claims();

        if ($claims->get('iss') !== rtrim(url('/'), '/')) {
            return null;
        }

        $audience = $claims->get('aud');

        if (is_string($audience) && $audience !== '') {
            return $audience;
        }

        // A single-element array is the usual shape. More than one audience
        // leaves the requesting client ambiguous, so refuse rather than guess.
        if (is_array($audience) && count($audience) === 1 && is_string($audience[0])) {
            return $audience[0];
        }

        return null;
    }

    /**
     * The post_logout_redirect_uri to send the browser to, or null to fall back
     * to the OP's own landing page.
     */
    private function resolvePostLogoutRedirectUri(Request $request, ?string $clientId): ?string
    {
        $uri = $request->input('post_logout_redirect_uri');

        if (! is_string($uri) || $uri === '') {
            return null;
        }

        if ($clientId === null) {
            Log::warning('OIDC end session: post_logout_redirect_uri supplied but the request could not be attributed to a client.');

            return null;
        }

        if (! $this->redirectUris->isRegistered($clientId, $uri)) {
            Log::warning('OIDC end session: post_logout_redirect_uri is not registered for this client.', [
                'client_id' => $clientId,
            ]);

            return null;
        }

        return $uri;
    }

    /**
     * Mirrors how IdTokenResponse signs the id_token, so that whatever signed
     * it here verifies it.
     */
    private function jwtConfiguration(): Configuration
    {
        /** @var Signer $signer */
        $signer = app(config('openid.signer'));

        if ($signer instanceof Hmac) {
            $key = $this->keyFrom('passport.private_key', 'oauth-private.key');

            return Configuration::forSymmetricSigner($signer, $key);
        }

        $key = $this->keyFrom('passport.public_key', 'oauth-public.key');

        // The signing key is never used -- this configuration only verifies --
        // but forAsymmetricSigner requires one.
        return Configuration::forAsymmetricSigner($signer, $key, $key);
    }

    private function keyFrom(string $configKey, string $keyFile): InMemory
    {
        $key = str_replace('\\n', "\n", (string) config($configKey, ''));

        if ($key !== '') {
            return InMemory::plainText($key);
        }

        return InMemory::file(Passport::keyPath($keyFile));
    }
}
