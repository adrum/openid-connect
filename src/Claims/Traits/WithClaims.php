<?php

declare(strict_types=1);

namespace OpenIDConnect\Claims\Traits;

trait WithClaims
{
    /** @var array<array-key, mixed> */
    protected array $claims;

    /**
     * @return array<array-key, mixed>
     */
    public function getClaims(): array
    {
        return $this->claims;
    }

    /**
     * @param array<array-key, mixed> $claims
     */
    public function setClaims(array $claims): void
    {
        $this->claims = $claims;
    }
}
