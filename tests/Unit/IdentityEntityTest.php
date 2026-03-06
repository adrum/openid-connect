<?php

declare(strict_types=1);

namespace OpenIDConnect\Tests\Unit;

use OpenIDConnect\Entities\IdentityEntity;
use PHPUnit\Framework\TestCase;

class IdentityEntityTest extends TestCase
{
    public function test_identity_entity_has_get_claims_method()
    {
        $this->assertTrue(method_exists(new IdentityEntity(), 'getClaims'));
    }

    public function test_identity_entity_get_claims_returns_array()
    {
        $entity = new IdentityEntity();
        $this->assertIsArray($entity->getClaims());
    }

    public function test_identity_entity_has_identifier_property()
    {
        $this->assertTrue(property_exists(new IdentityEntity(), 'identifier'));
    }

    public function test_identity_entity_has_get_identifier_method()
    {
        $this->assertTrue(method_exists(new IdentityEntity(), 'getIdentifier'));
    }

    public function test_identity_entity_has_set_identifier_method()
    {
        $this->assertTrue(method_exists(new IdentityEntity(), 'setIdentifier'));
    }
}
