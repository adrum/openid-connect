<?php

declare(strict_types=1);

namespace OpenIDConnect\Interfaces;

/**
 * Answers whether a post_logout_redirect_uri has been registered by a client.
 *
 * This is the control that keeps the end session endpoint from being an open
 * redirect, so the answer must come from data registered out of band with the
 * client -- never from the logout request itself.
 */
interface PostLogoutRedirectUriRepositoryInterface
{
    /**
     * @param string $clientIdentifier The client the logout request was attributed to.
     * @param string $uri              The post_logout_redirect_uri as supplied by the RP.
     */
    public function isRegistered(string $clientIdentifier, string $uri): bool;
}
