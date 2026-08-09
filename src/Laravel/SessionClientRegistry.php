<?php

declare(strict_types=1);

namespace OpenIDConnect\Laravel;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Carbon;
use OpenIDConnect\Interfaces\SessionClientRegistryInterface;

/**
 * Default implementation: a table mapping OP sessions to the clients that
 * received an id_token for them.
 *
 * Publish and run the package migration to create it:
 *
 *     php artisan vendor:publish --tag=openid-migrations
 */
class SessionClientRegistry implements SessionClientRegistryInterface
{
    public function __construct(private ConnectionInterface $connection)
    {
    }

    public function remember(string $sessionId, string $clientIdentifier): void
    {
        $now = Carbon::now();

        // Upsert rather than insert: a client that goes through the flow again
        // within the same session -- a second authorization for a wider scope,
        // say -- should refresh the row, not collide with it or duplicate it.
        $this->query()->upsert(
            [[
                'session_id' => $sessionId,
                'client_id' => $clientIdentifier,
                'created_at' => $now,
                'updated_at' => $now,
            ]],
            ['session_id', 'client_id'],
            ['updated_at'],
        );
    }

    /**
     * @return string[]
     */
    public function clientsFor(string $sessionId): array
    {
        /** @var string[] $clients */
        $clients = $this->query()
            ->where('session_id', $sessionId)
            ->pluck('client_id')
            ->all();

        return $clients;
    }

    public function forget(string $sessionId): void
    {
        $this->query()->where('session_id', $sessionId)->delete();
    }

    private function query(): \Illuminate\Database\Query\Builder
    {
        return $this->connection->table(
            (string) config('openid.backchannel_logout.table', 'oidc_session_clients'),
        );
    }
}
