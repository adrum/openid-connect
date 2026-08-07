<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ __('Log out') }}</title>
</head>
<body>
    <main>
        <h1>{{ __('Log out') }}</h1>

        <p>{{ __('Do you want to end your session?') }}</p>

        <form method="POST" action="{{ $action }}">
            {{-- Harmless when the route is excluded from CSRF verification,
                 which it has to be for RP-initiated POST requests to work. The
                 confirmation token below is what actually ties this submission
                 to the request that produced this page. --}}
            @csrf
            <input type="hidden" name="_openid_logout_confirmation" value="{{ $token }}">
            <button type="submit">{{ __('Log out') }}</button>
        </form>
    </main>
</body>
</html>
