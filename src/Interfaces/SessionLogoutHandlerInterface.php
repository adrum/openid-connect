<?php

declare(strict_types=1);

namespace OpenIDConnect\Interfaces;

use Illuminate\Http\Request;

/**
 * Ends the end-user's local login session at the OP.
 *
 * What "logged out" means is application policy -- which guard, whether other
 * devices are signed out too, what session state survives -- so this package
 * only defines the seam. A default Laravel implementation is bound for you and
 * can be replaced by binding this interface in your own service provider.
 */
interface SessionLogoutHandlerInterface
{
    public function logout(Request $request): void;
}
