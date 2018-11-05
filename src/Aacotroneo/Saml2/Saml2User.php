<?php

namespace Aacotroneo\Saml2;

use Illuminate\Contracts\Routing\UrlGenerator;
use OneLogin\Saml2\Auth;

/**
 * A simple class that represents the user that 'came' inside the saml2 assertion
 * Class Saml2User
 *
 * @package Aacotroneo\Saml2
 */
class Saml2User
{
    /**
     * @var Auth
     */
    protected $auth;

    /**
     * Saml2User constructor.
     *
     * @param Auth $auth
     */
    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * @return string User Id retrieved from assertion processed this request
     */
    public function getUserId(): string
    {
        $auth = $this->auth;

        return $auth->getNameId();
    }

    /**
     * @return array attributes retrieved from assertion processed this request
     */
    public function getAttributes(): array
    {
        $auth = $this->auth;

        return $auth->getAttributes();
    }

    /**
     * @return string the saml assertion processed this request
     */
    public function getRawSamlAssertion(): string
    {
        return app('request')->input('SAMLResponse'); //just this request
    }

    /**
     * @return mixed
     */
    public function getIntendedUrl()
    {
        $relayState = app('request')->input('RelayState'); //just this request
        $url = app(UrlGenerator::class);

        if ($relayState && $url->full() != $relayState) {
            return $relayState;
        }
    }

    /**
     * Parse the saml attributes and adds it to this user
     *
     * @param array $attributes Array of properties which need to be parsed, like this ['email' => 'urn:oid:0.9.2342.19200300.100.1.3']
     */
    public function parseAttributes(array $attributes = [])
    {
        foreach ($attributes as $propertyName => $samlAttribute) {
            $this->parseUserAttribute($samlAttribute, $propertyName);
        }
    }

    /**
     * Parses a SAML property and adds this property to this user or returns the value
     *
     * @param string $samlAttribute
     * @param string $propertyName
     *
     * @return array|null
     */
    public function parseUserAttribute(?string $samlAttribute = null, ?string $propertyName = null): ?array
    {
        if (empty($samlAttribute)) {
            return null;
        }

        if (empty($propertyName)) {
            return $this->getAttribute($samlAttribute);
        }

        return $this->{$propertyName} = $this->getAttribute($samlAttribute);
    }

    /**
     * Returns the requested SAML attribute
     *
     * @param string $name The requested attribute of the user.
     *
     * @return array|null Requested SAML attribute ($name).
     */
    public function getAttribute(string $name): ?array
    {
        $auth = $this->auth;

        return $auth->getAttribute($name);
    }

    /**
     * @return null|string
     */
    public function getSessionIndex(): ?string
    {
        return $this->auth->getSessionIndex();
    }

    /**
     * @return string
     */
    public function getNameId(): string
    {
        return $this->auth->getNameId();
    }
}
