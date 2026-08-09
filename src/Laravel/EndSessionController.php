<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use OpenIDConnect\Interfaces\LogoutConfirmationInterface;
use OpenIDConnect\Interfaces\PostLogoutRedirectUriRepositoryInterface;
use OpenIDConnect\Interfaces\SessionLogoutHandlerInterface;
use Symfony\Component\HttpFoundation\Response;
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
    /**
     * Where a pending, not-yet-confirmed logout request is parked.
     */
    private const CONFIRMATION_SESSION_KEY = 'openid_logout_confirmation';

    private SessionLogoutHandlerInterface $logoutHandler;

    private PostLogoutRedirectUriRepositoryInterface $redirectUris;

    private LogoutConfirmationInterface $confirmation;

    private PassportJwtConfiguration $jwt;

    public function __construct(
        SessionLogoutHandlerInterface $logoutHandler,
        PostLogoutRedirectUriRepositoryInterface $redirectUris,
        LogoutConfirmationInterface $confirmation,
        PassportJwtConfiguration $jwt
    ) {
        $this->logoutHandler = $logoutHandler;
        $this->redirectUris = $redirectUris;
        $this->confirmation = $confirmation;
        $this->jwt = $jwt;
    }

    public function __invoke(Request $request): Response
    {
        $confirmed = $this->pullConfirmedParameters($request);
        $parameters = $confirmed ?? $this->parametersFrom($request);

        // The hint is verified up front rather than after confirming, because
        // whether to confirm at all depends on what it turns out to say.
        $hint = $this->verifyIdTokenHint($parameters['id_token_hint']);

        // Resolved before the session is destroyed so the two concerns stay
        // independent of each other.
        $clientId = $this->resolveClient($parameters, $hint);

        if ($confirmed === null && $this->requiresConfirmation($request, $hint)) {
            // Park the client we resolved, so the view is looking at a value
            // the OP vouches for rather than one the caller asserted.
            $parameters['client_id'] = $clientId;

            return $this->requestConfirmation($request, $parameters);
        }

        $this->logoutHandler->logout($request);

        $redirectUri = $this->resolvePostLogoutRedirectUri($parameters, $clientId);

        if ($redirectUri === null) {
            return redirect()->to((string) config('openid.end_session.default_redirect', '/'));
        }

        $state = $parameters['state'];

        if (is_string($state) && $state !== '') {
            $redirectUri .= (strpos($redirectUri, '?') === false ? '?' : '&')
                . http_build_query(['state' => $state]);
        }

        return redirect()->away($redirectUri);
    }

    /**
     * The logout request parameters, as supplied by the RP.
     *
     * @return array<string, string|null>
     */
    private function parametersFrom(Request $request): array
    {
        $parameters = [];

        foreach (['id_token_hint', 'post_logout_redirect_uri', 'state', 'client_id'] as $name) {
            $value = $request->input($name);
            $parameters[$name] = is_string($value) && $value !== '' ? $value : null;
        }

        return $parameters;
    }

    /**
     * Whether the end-user should be asked before their session is ended.
     *
     * Section 2 makes this conditional rather than all-or-nothing:
     *
     *   "At the Logout Endpoint, the OP SHOULD ask the End-User whether to log
     *    out of the OP as well. Furthermore, the OP MUST ask the End-User this
     *    question if an id_token_hint was not provided or if the supplied ID
     *    Token does not belong to the current OP session with the RP and/or
     *    currently logged in End-User."
     *
     * So a verified hint for the signed-in user is the one case where skipping
     * the prompt is permitted -- which is also the case that matters for user
     * experience, since it is every legitimate RP-initiated logout. Everything
     * else is a MUST, including the drive-by <img src="...end_session"> that
     * arrives with no hint at all.
     *
     * @param array{client: string, subject: string|null}|null $hint
     */
    private function requiresConfirmation(Request $request, ?array $hint): bool
    {
        $mode = $this->confirmationMode();

        if ($mode === 'never') {
            return false;
        }

        if (! $request->hasSession()) {
            return false;
        }

        $guard = Auth::guard(config('openid.end_session.guard', 'web'));

        // Nothing to confirm when there is no session to end. Skipping the
        // prompt here also keeps crawlers and prefetchers off it.
        if (! $guard->check()) {
            return false;
        }

        if ($mode === 'always') {
            return true;
        }

        // 'unverified': prompt unless the hint is both valid and about the
        // person whose session is on the line.
        if ($hint === null || $hint['subject'] === null) {
            return true;
        }

        return ! hash_equals((string) $guard->id(), $hint['subject']);
    }

    /**
     * When to prompt: 'always', 'unverified' or 'never'.
     *
     * Booleans are accepted for the config to read naturally either way.
     */
    private function confirmationMode(): string
    {
        $configured = config('openid.end_session.confirm', 'unverified');

        if ($configured === true) {
            return 'always';
        }

        if ($configured === false) {
            return 'never';
        }

        return in_array($configured, ['always', 'unverified', 'never'], true)
            ? $configured
            : 'unverified';
    }

    /**
     * Park the request and ask the end-user to confirm it.
     *
     * @param array<string, string|null> $parameters
     */
    private function requestConfirmation(Request $request, array $parameters): Response
    {
        $token = bin2hex(random_bytes(32));

        $request->session()->put(self::CONFIRMATION_SESSION_KEY, [
            'token' => $token,
            'parameters' => $parameters,
        ]);

        return $this->confirmation->respond($request, $token, $parameters);
    }

    /**
     * The parked parameters, if this request is a valid confirmation of one.
     *
     * The parameters come back from the session rather than from the
     * submission, so the confirmed logout is the one the user was shown --
     * a tampered form cannot swap in a different post_logout_redirect_uri
     * after the fact.
     *
     * @return array<string, string|null>|null
     */
    private function pullConfirmedParameters(Request $request): ?array
    {
        if (! $request->hasSession()) {
            return null;
        }

        $submitted = $request->input('_openid_logout_confirmation');

        if (! is_string($submitted) || $submitted === '') {
            return null;
        }

        // Pulled unconditionally: a confirmation token is good for one attempt
        // whether or not it matches, so a wrong guess cannot be retried against
        // the same parked request.
        $parked = $request->session()->pull(self::CONFIRMATION_SESSION_KEY);

        if (! is_array($parked) || ! isset($parked['token'], $parked['parameters'])) {
            return null;
        }

        if (! is_string($parked['token']) || ! hash_equals($parked['token'], $submitted)) {
            return null;
        }

        return is_array($parked['parameters']) ? $parked['parameters'] : null;
    }

    /**
     * Attribute the logout request to a client, or null if it cannot be
     * attributed to one.
     *
     * @param array<string, string|null>                       $parameters
     * @param array{client: string, subject: string|null}|null $hint
     */
    private function resolveClient(array $parameters, ?array $hint): ?string
    {
        if ($hint !== null) {
            return $hint['client'];
        }

        // A hint that was supplied but did not verify attributes the request to
        // nobody. Falling back to client_id here would let a forged hint be
        // downgraded into an unauthenticated one.
        if ($parameters['id_token_hint'] !== null) {
            return null;
        }

        // Section 2 allows client_id to identify the RP on its own, but it is
        // an unauthenticated assertion: anyone can name any client and reach
        // that client's registered URIs. The registration check still applies,
        // so this is bounded rather than open, but it defaults to off.
        if (config('openid.end_session.require_id_token_hint', true)) {
            return null;
        }

        return $parameters['client_id'];
    }

    /**
     * Verify an id_token_hint, returning the client it was issued to and the
     * subject it was issued about, or null if it does not verify.
     *
     * @return array{client: string, subject: string|null}|null
     */
    private function verifyIdTokenHint(?string $idToken): ?array
    {
        if ($idToken === null) {
            return null;
        }

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

        $expectedIssuer = $this->expectedIssuer();

        if ($claims->get('iss') !== $expectedIssuer) {
            // Logged, because the likeliest cause is not an attack but a
            // scheme mismatch: url('/') follows the incoming request, so an OP
            // behind a TLS-terminating proxy without trusted proxies
            // configured reports http:// while its own id_tokens say https://.
            // Every hint then fails this check and single sign-out quietly
            // stops working. Pin openid.end_session.issuer to rule it out.
            Log::warning('OIDC end session: id_token_hint issuer does not match.', [
                'expected' => $expectedIssuer,
                'actual' => $claims->get('iss'),
            ]);

            return null;
        }

        $audience = $claims->get('aud');
        $client = null;

        if (is_string($audience) && $audience !== '') {
            $client = $audience;
        } elseif (is_array($audience) && count($audience) === 1 && is_string($audience[0])) {
            // A single-element array is the usual shape. More than one audience
            // leaves the requesting client ambiguous, so refuse rather than
            // guess.
            $client = $audience[0];
        }

        if ($client === null) {
            Log::warning('OIDC end session: id_token_hint has no usable audience.');

            return null;
        }

        $subject = $claims->get('sub');

        return [
            'client' => $client,
            // Carried so the caller can check the hint is about the person
            // whose session is about to end, not merely a well-formed token.
            'subject' => is_string($subject) || is_int($subject) ? (string) $subject : null,
        ];
    }

    /**
     * The post_logout_redirect_uri to send the browser to, or null to fall back
     * to the OP's own landing page.
     *
     * @param array<string, string|null> $parameters
     */
    private function resolvePostLogoutRedirectUri(array $parameters, ?string $clientId): ?string
    {
        $uri = $parameters['post_logout_redirect_uri'];

        if ($uri === null) {
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
     * The `iss` an id_token_hint must carry.
     *
     * Defaults to url('/'), which matches how IdTokenResponse derives the
     * issuer when minting the token -- but both follow the incoming request,
     * so they only agree when every request reaches the app with the same
     * scheme and host. Pin it when that is not guaranteed.
     */
    private function expectedIssuer(): string
    {
        $configured = config('openid.end_session.issuer');

        if (is_string($configured) && $configured !== '') {
            return rtrim($configured, '/');
        }

        return rtrim(url('/'), '/');
    }

    /**
     * Mirrors how IdTokenResponse signs the id_token, so that whatever signed
     * it here verifies it.
     */
    private function jwtConfiguration(): Configuration
    {
        return $this->jwt->forVerification();
    }
}
