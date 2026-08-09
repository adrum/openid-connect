<?php

declare(strict_types=1);

namespace OpenIDConnect\Interfaces;

/**
 * Resolves an identifier for the OP session the current request belongs to.
 *
 * This is the `sid` claim of OpenID Connect Session Management: an opaque
 * value, unique per OP session, that lets a logout notification say *which*
 * session ended rather than merely which user did.
 *
 * It is resolved at the authorization endpoint, where the end-user's browser
 * and its session are present. By the time the id_token is minted at the token
 * endpoint the request is a back-channel call from the RP, with no session of
 * its own, so the value has to be carried across in the authorization code.
 */
interface SessionIdResolverInterface
{
    /**
     * The current session's identifier, or null when there is no session.
     */
    public function resolve(): ?string;
}
