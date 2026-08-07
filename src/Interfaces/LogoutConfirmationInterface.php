<?php

declare(strict_types=1);

namespace OpenIDConnect\Interfaces;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Asks the end-user to confirm that they really want to log out.
 *
 * RP-Initiated Logout 1.0 section 2 recommends this, and the reason is worth
 * spelling out: the end session endpoint answers GET, and a GET carries no
 * CSRF token, so without a prompt any page on the internet can end a user's
 * session at the OP with nothing more than an <img> tag -- and with it every
 * SSO session that session backs.
 *
 * A default implementation renders a view. Replace this binding to return
 * something else entirely (an Inertia response, a redirect into a SPA route).
 *
 * @param string $token       Must be submitted back as `_openid_logout_confirmation`.
 * @param array  $parameters  The logout request, for display -- already stored server side.
 */
interface LogoutConfirmationInterface
{
    /**
     * @param array<string, string|null> $parameters
     */
    public function respond(Request $request, string $token, array $parameters): Response;
}
