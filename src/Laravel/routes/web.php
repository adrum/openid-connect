<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use OpenIDConnect\Laravel\DiscoveryController;
use OpenIDConnect\Laravel\EndSessionController;
use OpenIDConnect\Laravel\JwksController;

if (config('openid.routes.jwks', true)) {
    Route::get('/oauth/jwks', JwksController::class)
        ->name('openid.jwks');
}

if (config('openid.routes.discovery', true)) {
    Route::get('/.well-known/openid-configuration', DiscoveryController::class)
        ->name('openid.discovery');
}

if (config('openid.routes.end_session', false)) {
    // Section 2 requires both GET and POST. Unlike the other two routes this
    // one needs the session middleware, since ending the session is the whole
    // point -- and note that POST therefore has to be excluded from CSRF
    // verification by the application, because a logout redirect arriving from
    // another origin carries no token.
    Route::middleware(config('openid.end_session.middleware', ['web']))
        ->match(['get', 'post'], config('openid.end_session.path', 'oauth/logout'), EndSessionController::class)
        ->name('openid.end_session_endpoint');
}
