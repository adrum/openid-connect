<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Laravel\Passport\Passport;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key\InMemory;

/**
 * Builds `lcobucci/jwt` configurations from Passport's keys.
 *
 * Both halves of single sign-out handle JWTs signed by this OP -- the end
 * session endpoint verifies an id_token_hint, the back-channel notifier signs
 * a logout token -- and both have to agree with how IdTokenResponse signs in
 * the first place. Keeping that agreement in one place means a change of
 * signer or key source cannot leave one of them behind, silently rejecting
 * every hint or emitting tokens no relying party can verify.
 */
class PassportJwtConfiguration
{
    /**
     * A configuration that can sign.
     */
    public function forSigning(): Configuration
    {
        $signer = $this->signer();

        if ($signer instanceof Hmac) {
            $key = $this->keyFrom('passport.private_key', 'oauth-private.key');

            return Configuration::forSymmetricSigner($signer, $key);
        }

        return Configuration::forAsymmetricSigner(
            $signer,
            $this->keyFrom('passport.private_key', 'oauth-private.key'),
            $this->keyFrom('passport.public_key', 'oauth-public.key'),
        );
    }

    /**
     * A configuration that can verify.
     */
    public function forVerification(): Configuration
    {
        $signer = $this->signer();

        if ($signer instanceof Hmac) {
            $key = $this->keyFrom('passport.private_key', 'oauth-private.key');

            return Configuration::forSymmetricSigner($signer, $key);
        }

        $key = $this->keyFrom('passport.public_key', 'oauth-public.key');

        // The signing key is never used -- this configuration only verifies --
        // but forAsymmetricSigner requires one.
        return Configuration::forAsymmetricSigner($signer, $key, $key);
    }

    private function signer(): Signer
    {
        /** @var Signer $signer */
        $signer = app(config('openid.signer'));

        return $signer;
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
