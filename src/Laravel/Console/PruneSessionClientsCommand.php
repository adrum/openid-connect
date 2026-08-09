<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel\Console;

use Illuminate\Console\Command;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Carbon;

/**
 * Clears session/client records that no live session can still refer to.
 *
 * The registry is emptied for a session when that session is logged out, which
 * covers the tidy case and only the tidy case. Most sessions are not logged
 * out -- they are abandoned, and expire on their own -- so without this the
 * table only ever grows, and keeps a record of who signed in to what, and
 * when, for as long as the database lives.
 */
class PruneSessionClientsCommand extends Command
{
    protected $signature = 'openid:prune-session-clients
                            {--hours= : Delete records older than this many hours}';

    protected $description = 'Delete back-channel logout session records for sessions that have expired';

    public function handle(ConnectionInterface $connection): int
    {
        $hours = $this->option('hours') !== null
            ? (int) $this->option('hours')
            : $this->defaultHours();

        $cutoff = Carbon::now()->subHours(max(1, $hours));

        $deleted = $connection
            ->table((string) config('openid.backchannel_logout.table', 'oidc_session_clients'))
            ->where('updated_at', '<', $cutoff)
            ->delete();

        $this->info(sprintf(
            'Pruned %d session record(s) last touched before %s.',
            $deleted,
            $cutoff->toDateTimeString(),
        ));

        return self::SUCCESS;
    }

    /**
     * Derived from the session lifetime, with a wide margin.
     *
     * A record outliving its session is harmless -- the logout it would drive
     * finds nothing to end. A record deleted while its session is still alive
     * is not: that relying party silently stops being told about logouts. So
     * the default errs long, and the margin absorbs a session extended by
     * activity right up to the edge of its lifetime.
     */
    private function defaultHours(): int
    {
        $minutes = (int) config('session.lifetime', 120);

        return max(1, (int) ceil($minutes / 60)) * 2;
    }
}
