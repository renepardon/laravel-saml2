<?php

namespace Aacotroneo\Saml2\Events;

use Aacotroneo\Saml2\Saml2Auth;
use Aacotroneo\Saml2\Saml2User;

/**
 * Class Saml2LoginEvent
 *
 * @package Aacotroneo\Saml2\Events
 */
class Saml2LoginEvent
{
    /**
     * @var Saml2User
     */
    protected $user;

    /**
     * @var Saml2Auth
     */
    protected $auth;

    /**
     * @param Saml2User $user
     * @param Saml2Auth $auth
     */
    public function __construct(Saml2User $user, Saml2Auth $auth)
    {
        $this->user = $user;
        $this->auth = $auth;
    }

    /**
     * @return Saml2User
     */
    public function getSaml2User()
    {
        return $this->user;
    }

    /**
     * @return Saml2Auth
     */
    public function getSaml2Auth()
    {
        return $this->auth;
    }
}
