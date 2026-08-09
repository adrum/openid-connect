<?php

declare(strict_types=1);

namespace OpenIDConnect;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use OpenIDConnect\Interfaces\CurrentRequestServiceInterface;
use OpenIDConnect\Interfaces\IdentityEntityInterface;
use OpenIDConnect\Interfaces\IdentityRepositoryInterface;
use OpenIDConnect\Interfaces\SessionClientRegistryInterface;

class IdTokenResponse extends BearerTokenResponse
{
    use CryptTrait;

    protected IdentityRepositoryInterface $identityRepository;

    protected ClaimExtractor $claimExtractor;

    private Configuration $config;
    private ?CurrentRequestServiceInterface $currentRequestService;
    private ?SessionClientRegistryInterface $sessionClientRegistry;

    /**
     * @param string|Key|null $encryptionKey
     */
    public function __construct(
        IdentityRepositoryInterface $identityRepository,
        ClaimExtractor $claimExtractor,
        Configuration $config,
        CurrentRequestServiceInterface $currentRequestService = null,
        $encryptionKey = null,
        ?SessionClientRegistryInterface $sessionClientRegistry = null,
    ) {
        $this->identityRepository = $identityRepository;
        $this->claimExtractor = $claimExtractor;
        $this->config = $config;
        $this->currentRequestService = $currentRequestService;
        $this->encryptionKey = $encryptionKey;
        $this->sessionClientRegistry = $sessionClientRegistry;
    }

    protected function getBuilder(
        AccessTokenEntityInterface $accessToken,
        IdentityEntityInterface $userEntity
    ): Builder {
        $dateTimeImmutableObject = new DateTimeImmutable();

        if ($this->currentRequestService) {
            $uri = $this->currentRequestService->getRequest()->getUri();
            $issuer = $uri->getScheme() . '://' . $uri->getHost() . ($uri->getPort() ? ':' . $uri->getPort() : '');
        } else {
            $issuer = 'https://' . $_SERVER['HTTP_HOST'];
        }

        return $this->config
            ->builder()
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->issuedBy($issuer)
            ->issuedAt($dateTimeImmutableObject)
            ->expiresAt($dateTimeImmutableObject->add(new DateInterval('PT1H')))
            ->relatedTo($userEntity->getIdentifier());
    }

    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        if (!$this->hasOpenIDScope(...$accessToken->getScopes())) {
            return [];
        }

        $user = $this->identityRepository->getByIdentifier(
            (string) $accessToken->getUserIdentifier(),
        );

        $builder = $this->getBuilder($accessToken, $user);

        $claims = $this->claimExtractor->extract(
            $accessToken->getScopes(),
            $user->getClaims(),
        );

        foreach ($claims as $claimName => $claimValue) {
            $builder = $builder->withClaim($claimName, $claimValue);
        }

        if ($this->currentRequestService) {
            // If the request contains a code, we look into the code to find the nonce.
            $body = $this->currentRequestService->getRequest()->getParsedBody();
            if (isset($body['code'])) {
                $authCodePayload = json_decode($this->decrypt($body['code']), true, 512, JSON_THROW_ON_ERROR);
                if (isset($authCodePayload['nonce'])) {
                    $builder = $builder->withClaim('nonce', $authCodePayload['nonce']);
                }

                // `sid` was put here by AuthCodeGrant at the authorization
                // endpoint, where the session existed. Note there is no
                // equivalent for the refresh token grant: a refreshed id_token
                // carries no `sid`, which is correct -- the OP session it named
                // may be long gone, and asserting otherwise would have relying
                // parties tracking a session that cannot be logged out.
                if (isset($authCodePayload['sid']) && is_string($authCodePayload['sid'])) {
                    $sessionId = $authCodePayload['sid'];

                    $builder = $builder->withClaim('sid', $sessionId);

                    // Recorded here rather than at the authorization endpoint
                    // because this is the point at which the client actually
                    // holds an id_token for the session. A client that started
                    // the flow but never exchanged its code has nothing to log
                    // out of, and notifying it would say more about the user
                    // than it is entitled to know.
                    if ($this->sessionClientRegistry !== null) {
                        $this->sessionClientRegistry->remember(
                            $sessionId,
                            $accessToken->getClient()->getIdentifier(),
                        );
                    }
                }
            }
        }

        $token = $builder->getToken(
            $this->config->signer(),
            $this->config->signingKey(),
        );

        return ['id_token' => $token->toString()];
    }

    private function hasOpenIDScope(ScopeEntityInterface ...$scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($scope->getIdentifier() === 'openid') {
                return true;
            }
        }
        return false;
    }
}
