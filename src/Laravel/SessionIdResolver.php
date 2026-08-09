<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Illuminate\Contracts\Session\Session;
use OpenIDConnect\Interfaces\SessionIdResolverInterface;

/**
 * Default implementation: mint an opaque identifier once per session and keep
 * it in the session payload.
 *
 * Two things it deliberately is not:
 *
 * It is not the framework's session id. That value is the session cookie, and
 * the `sid` ends up inside id_tokens that relying parties store, log and pass
 * around -- an id_token leaked from any one RP would otherwise hand over a
 * live session cookie for the identity provider itself, which is a worse
 * outcome than the leak.
 *
 * It is not derived from the session id either, because Laravel regenerates
 * that on login and on any later `regenerate()`. A derived value would change
 * underneath a session that never ended, so the `sid` in an already-issued
 * id_token would stop matching and that relying party would never be told
 * about the logout. Session *data* survives regeneration, so storing it there
 * gives an identifier that lasts exactly as long as the session does.
 */
class SessionIdResolver implements SessionIdResolverInterface
{
    /**
     * Where the identifier lives in the session payload.
     */
    public const SESSION_KEY = 'openid_sid';

    public function __construct(private Session $session)
    {
    }

    public function resolve(): ?string
    {
        $existing = $this->session->get(self::SESSION_KEY);

        if (is_string($existing) && $existing !== '') {
            return $existing;
        }

        // Random rather than derived from anything: the identifier is handed to
        // every relying party in the session, so it should reveal nothing about
        // the user, the session or the OP's internals.
        $sid = bin2hex(random_bytes(16));

        $this->session->put(self::SESSION_KEY, $sid);

        return $sid;
    }
}
