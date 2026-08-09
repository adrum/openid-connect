<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>{{ config('app.name') }} &mdash; {{ __('Sign out') }}</title>

    {{-- Deliberately self-contained. A package view cannot assume the host
         application has a build step, a CSS framework, or a layout to extend,
         so this ships as plain CSS that renders the same anywhere. Publish it
         with `--tag=openid-views` to restyle, or point
         openid.end_session.confirmation_view at your own view. --}}
    <style>
        :root {
            color-scheme: light dark;
            --bg: #f8fafc;
            --card: #ffffff;
            --text: #0f172a;
            --muted: #64748b;
            --border: #e2e8f0;
            --accent: #1e293b;
            --accent-text: #ffffff;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #0b1120;
                --card: #111827;
                --text: #f1f5f9;
                --muted: #94a3b8;
                --border: #1f2937;
                --accent: #e2e8f0;
                --accent-text: #0f172a;
            }
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
            background: var(--bg);
            color: var(--text);
            font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto,
                "Helvetica Neue", Arial, sans-serif;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }

        .card {
            width: 100%;
            max-width: 24rem;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 2rem;
            box-shadow: 0 1px 2px rgba(15, 23, 42, .04), 0 8px 24px rgba(15, 23, 42, .06);
            text-align: center;
        }

        .app {
            font-size: .75rem;
            font-weight: 600;
            letter-spacing: .08em;
            text-transform: uppercase;
            color: var(--muted);
            margin: 0 0 1.25rem;
        }

        h1 {
            font-size: 1.25rem;
            font-weight: 600;
            margin: 0 0 .5rem;
        }

        p {
            margin: 0 0 1.75rem;
            color: var(--muted);
            font-size: .9375rem;
        }

        button {
            display: block;
            width: 100%;
            padding: .625rem 1rem;
            font: inherit;
            font-weight: 600;
            font-size: .9375rem;
            color: var(--accent-text);
            background: var(--accent);
            border: 1px solid transparent;
            border-radius: .5rem;
            cursor: pointer;
        }

        button:hover { opacity: .9; }

        button:focus-visible,
        .secondary:focus-visible {
            outline: 2px solid var(--accent);
            outline-offset: 2px;
        }

        .secondary {
            display: inline-block;
            margin-top: 1rem;
            font-size: .875rem;
            color: var(--muted);
            text-decoration: none;
        }

        .secondary:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <main class="card">
        <p class="app">{{ config('app.name') }}</p>

        <h1>{{ __('Sign out?') }}</h1>

        <p>{{ __('This will end your session and sign you out of applications that use this account.') }}</p>

        <form method="POST" action="{{ $action }}">
            {{-- Harmless when the route is excluded from CSRF verification,
                 which it has to be for RP-initiated POST requests to work. The
                 confirmation token below is what ties this submission to the
                 request that produced this page. --}}
            @csrf
            <input type="hidden" name="_openid_logout_confirmation" value="{{ $token }}">

            <button type="submit">{{ __('Sign out') }}</button>
        </form>

        {{-- Declining stays here. RP-Initiated Logout defines no error channel
             back to the relying party -- post_logout_redirect_uri means "the
             logout happened", so sending a declined request there would tell
             the RP something untrue. --}}
        <a class="secondary" href="{{ url('/') }}">{{ __('Stay signed in') }}</a>
    </main>
</body>
</html>
