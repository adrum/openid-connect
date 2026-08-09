<?php

declare(strict_types=1);

namespace OpenIDConnect\Claims;

interface Claimable
{
    /**
     * Implementations disagree on the shape: a ClaimSet holds a list of claim names,
     * an identity holds a name => value map whose values are not all strings.
     *
     * @return array<array-key, mixed>
     */
    public function getClaims(): array;
}
