<?php

declare(strict_types=1);

namespace OpenIDConnect\Interfaces;

/**
 * Records which clients took part in a given OP session.
 *
 * Back-Channel Logout has the OP notify the RPs that share the session being
 * ended. Without a record of who those are, the only options are to notify
 * every registered client on every logout -- which leaks the fact that a user
 * signed in somewhere to clients that were never involved, and scales with the
 * client list rather than the session -- or to notify nobody.
 *
 * Participation is recorded when an id_token carrying a `sid` is issued, which
 * is exactly the set of clients holding a session derived from this one.
 */
interface SessionClientRegistryInterface
{
    /**
     * Note that a client received an id_token for this session.
     *
     * Called once per token exchange, so implementations should be idempotent.
     */
    public function remember(string $sessionId, string $clientIdentifier): void;

    /**
     * The clients that took part in this session.
     *
     * @return string[]
     */
    public function clientsFor(string $sessionId): array;

    /**
     * Discard the record for a session, once its logout has been dispatched.
     */
    public function forget(string $sessionId): void;
}
