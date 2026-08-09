<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use OpenIDConnect\Interfaces\SessionIdResolverInterface;
use OpenIDConnect\Interfaces\SessionLogoutHandlerInterface;

/**
 * Default implementation: log the user out of the configured guard, throw the
 * session away, and tell the relying parties that shared it.
 */
class SessionLogoutHandler implements SessionLogoutHandlerInterface
{
    public function __construct(
        private SessionIdResolverInterface $sessionIdResolver,
        private BackchannelLogoutNotifier $notifier,
    ) {
    }

    public function logout(Request $request): void
    {
        $guard = Auth::guard(config('openid.end_session.guard', 'web'));

        // Both read before anything is torn down: the session identifier is
        // about to be flushed, and the guard is about to forget who this is.
        $sessionId = $request->hasSession() ? $this->sessionIdResolver->resolve() : null;
        $subject = $guard->check() ? (string) $guard->id() : null;

        if ($guard instanceof StatefulGuard) {
            $guard->logout();
        }

        if ($request->hasSession()) {
            // invalidate() flushes the data and cycles the session id; the CSRF
            // token has to be regenerated separately or the next form post from
            // this browser fails.
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        // Last, so a slow or failing notification cannot leave the local
        // session standing. By this point the user is logged out here whatever
        // happens next, which is what they actually asked for -- the relying
        // parties are a promise this OP makes to them, not a precondition of
        // keeping the one it made to the user.
        $this->notifier->notify($sessionId, $subject);
    }
}
