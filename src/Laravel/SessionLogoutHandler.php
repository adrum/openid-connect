<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use OpenIDConnect\Interfaces\SessionLogoutHandlerInterface;

/**
 * Default implementation: log the user out of the configured guard and throw
 * the session away.
 */
class SessionLogoutHandler implements SessionLogoutHandlerInterface
{
    public function logout(Request $request): void
    {
        $guard = Auth::guard(config('openid.end_session.guard', 'web'));

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
    }
}
