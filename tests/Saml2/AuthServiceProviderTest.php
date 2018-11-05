<?php

namespace Tests\Saml2;

use Mockery as m;
use Tests\TestCase;

/**
 * Class AuthServiceProviderTest
 *
 * @package Aacotroneo\Saml2
 */
class AuthServiceProviderTest extends TestCase
{
    public function tearDown()
    {
        m::close();
    }

    public function testSimpleMock()
    {
        $this->assertTrue(true);
    }

    // TODO add tests for service provider
}
 