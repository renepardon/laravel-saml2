<?php

namespace Aacotroneo\Saml2\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * Class Saml2Auth
 *
 * @package Aacotroneo\Saml2\Facades
 */
class Saml2Auth extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return \Aacotroneo\Saml2\Saml2Auth::class;
    }
} 