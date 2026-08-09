<?php

declare(strict_types=1);

namespace OpenIDConnect\Interfaces;

/**
 * Reads a client's Back-Channel Logout registration.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html
 */
interface BackchannelLogoutClientRepositoryInterface
{
    /**
     * Where this client wants logout tokens delivered, or null if it has
     * registered no endpoint -- in which case it is not notified at all.
     *
     * There is deliberately no counterpart for the spec's
     * `backchannel_logout_session_required` metadata. That flag lets a client
     * insist on a `sid`, and this OP only ever sends notifications that carry
     * one, so honouring it could never change an outcome.
     */
    public function logoutUriFor(string $clientIdentifier): ?string;
}
