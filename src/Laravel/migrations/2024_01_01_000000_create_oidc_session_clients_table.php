<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Which clients took part in which OP session.
 *
 * Back-Channel Logout notifies the relying parties that share the session
 * being ended. Without this record the only choices are to notify every
 * registered client on every logout -- which tells clients that were never
 * involved that this user signed in somewhere, and grows with the client list
 * rather than the session -- or to notify nobody.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create($this->table(), function (Blueprint $table): void {
            $table->id();

            // The `sid` claim, not the framework's session id. Indexed because
            // every logout looks the session up by it.
            $table->string('session_id', 128)->index();

            $table->string('client_id');

            // Rows are written per token exchange, and a client may go through
            // the flow more than once in a session -- a second authorization
            // for a wider scope, say. The pair is what is unique, and the
            // upsert in SessionClientRegistry relies on this index existing.
            $table->unique(['session_id', 'client_id']);

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists($this->table());
    }

    private function table(): string
    {
        return (string) config('openid.backchannel_logout.table', 'oidc_session_clients');
    }
};
