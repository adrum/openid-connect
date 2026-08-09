<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Laravel\Passport\Passport;

class JwksController
{
    public function __invoke() {
        $publicKey = self::getPublicKey();

        // Source: https://www.tuxed.net/fkooman/blog/json_web_key_set.html
        $keyInfo = openssl_pkey_get_details(openssl_pkey_get_public($publicKey));

        $n = self::base64UrlEncode($keyInfo['rsa']['n']);
        $e = self::base64UrlEncode($keyInfo['rsa']['e']);

        $jsonData = [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'kid' => self::computeKid($n, $e),
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'n' => $n,
                    'e' => $e,
                ],
            ],
        ];

        return response()->json($jsonData, 200, [], JSON_PRETTY_PRINT);
    }

    /**
     * Compute the JWK thumbprint used as the key id, per RFC 7638.
     */
    public static function computeKid(string $n, string $e): string
    {
        // RFC 7638 requires the required members only, lexicographically ordered, no whitespace.
        $thumbprintInput = json_encode(['e' => $e, 'kty' => 'RSA', 'n' => $n], JSON_UNESCAPED_SLASHES);

        return self::base64UrlEncode(hash('sha256', $thumbprintInput, true));
    }

    /**
     * Compute the key id for a PEM-encoded public key.
     */
    public static function computeKidFromPublicKey(string $publicKey): string
    {
        $keyInfo = openssl_pkey_get_details(openssl_pkey_get_public($publicKey));

        return self::computeKid(
            self::base64UrlEncode($keyInfo['rsa']['n']),
            self::base64UrlEncode($keyInfo['rsa']['e']),
        );
    }

    private static function base64UrlEncode(string $value): string
    {
        return rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($value)), '=');
    }

    public static function getPublicKey(): string {
        $publicKey = config('passport.public_key');

        if ($publicKey) {
            return str_replace('\\n', "\n", $publicKey);
        }

        return 'file://'.Passport::keyPath('oauth-public.key');
    }
}
