<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Illuminate\Http\Request;
use OpenIDConnect\Interfaces\LogoutConfirmationInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Default implementation: render a view with a form that posts the
 * confirmation token back to the end session endpoint.
 */
class LogoutConfirmation implements LogoutConfirmationInterface
{
    /**
     * @param array<string, string|null> $parameters
     */
    public function respond(Request $request, string $token, array $parameters): Response
    {
        return response()->view(
            (string) config('openid.end_session.confirmation_view', 'openid::logout-confirm'),
            [
                'token' => $token,
                'parameters' => $parameters,
                'action' => route('openid.end_session_endpoint'),
            ]
        );
    }
}
