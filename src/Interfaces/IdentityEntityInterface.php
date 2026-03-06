<?php

declare(strict_types=1);

namespace OpenIDConnect\Interfaces;

use League\OAuth2\Server\Entities\UserEntityInterface as OAuth2UserEntityInterface;

interface IdentityEntityInterface extends OAuth2UserEntityInterface
{
    public function getIdentifier(): string;

    /**
     * @return array<string, mixed>
     */
    public function getClaims(): array;
}
