<?php

namespace Aacotroneo\Saml2;

use Aacotroneo\Saml2\Events\Saml2LogoutEvent;
use Exception;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Error;
use Psr\Log\InvalidArgumentException;

/**
 * Class Saml2Auth
 *
 * @package Aacotroneo\Saml2
 */
class Saml2Auth
{
    /**
     * @var Auth
     */
    protected $auth;

    /**
     * @todo remove?
     */
    protected $samlAssertion;

    /**
     * @param Auth $auth
     */
    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Check if a valid user was fetched from the SAML assertion
     *
     * @return bool
     */
    public function isAuthenticated(): bool
    {
        $auth = $this->auth;

        return $auth->isAuthenticated();
    }

    /**
     * The user info from the assertion
     *
     * @return Saml2User
     */
    public function getSaml2User(): Saml2User
    {
        return new Saml2User($this->auth);
    }

    /**
     * The ID of the last message processed
     *
     * @return string
     */
    public function getLastMessageId(): string
    {
        return $this->auth->getLastMessageId();
    }

    /**
     * Initiate a saml2 login flow. It will redirect! Before calling this, check if user is
     * authenticated (here in saml2). That would be true when the assertion was received this request.
     *
     * @param string|null $returnTo        The target URL the user should be returned to after login.
     * @param array       $parameters      Extra parameters to be added to the GET
     * @param bool        $forceAuthn      When true the AuthNReuqest will set the ForceAuthn='true'
     * @param bool        $isPassive       When true the AuthNReuqest will set the Ispassive='true'
     * @param bool        $stay            True if we want to stay (returns the url string) False to redirect
     * @param bool        $setNameIdPolicy When true the AuthNReuqest will set a nameIdPolicy element
     *
     * @return null|string If $stay is True, it return a string with the SLO URL + LogoutRequest + parameters
     * @throws Error
     */
    public function login(
        ?string $returnTo = null,
        array $parameters = [],
        bool $forceAuthn = false,
        bool $isPassive = false,
        bool $stay = false,
        bool $setNameIdPolicy = true
    ): ?string {
        $auth = $this->auth;

        return $auth->login($returnTo, $parameters, $forceAuthn, $isPassive, $stay, $setNameIdPolicy);
    }

    /**
     * Initiate a saml2 logout flow. It will close session on all other SSO services. You should close
     * local session if applicable.
     *
     * @param string|null $returnTo            The target URL the user should be returned to after logout.
     * @param string|null $nameId              The NameID that will be set in the LogoutRequest.
     * @param string|null $sessionIndex        The SessionIndex (taken from the SAML Response in the SSO process).
     * @param string|null $nameIdFormat        The NameID Format will be set in the LogoutRequest.
     * @param bool        $stay                True if we want to stay (returns the url string) False to redirect
     * @param string|null $nameIdNameQualifier The NameID NameQualifier will be set in the LogoutRequest.
     *
     * @return string|null If $stay is True, it return a string with the SLO URL + LogoutRequest + parameters
     *
     * @throws Error
     */
    public function logout(
        ?string $returnTo = null,
        ?string $nameId = null,
        ?string $sessionIndex = null,
        ?string $nameIdFormat = null,
        bool $stay = false,
        ?string $nameIdNameQualifier = null
    ): ?string {
        $auth = $this->auth;

        return $auth->logout($returnTo, [], $nameId, $sessionIndex, $stay, $nameIdFormat, $nameIdNameQualifier);
    }

    /**
     * Process a Saml response (assertion consumer service)
     *
     * When errors are encountered, it returns an array with proper description
     *
     * @return array|null
     * @throws Error
     * @throws \OneLogin\Saml2\ValidationError
     */
    public function acs(): ?array
    {
        $auth = $this->auth;

        $auth->processResponse();

        $errors = $auth->getErrors();

        if (!empty($errors)) {
            return $errors;
        }

        if (!$auth->isAuthenticated()) {
            return ['error' => 'Could not authenticate'];
        }

        return null;
    }

    /**
     * Process a Saml response (assertion consumer service)
     * returns an array with errors if it can not logout
     *
     * @param bool $retrieveParametersFromServer
     *
     * @return array
     * @throws Error
     */
    public function sls(bool $retrieveParametersFromServer = false): array
    {
        $auth = $this->auth;

        // destroy the local session by firing the Logout event
        $keep_local_session = false;
        $session_callback = function () {
            event(new Saml2LogoutEvent());
        };

        $auth->processSLO($keep_local_session, null, $retrieveParametersFromServer, $session_callback);

        $errors = (array)$auth->getErrors();

        return $errors;
    }

    /**
     * Show metadata about the local sp. Use this to configure your saml2 IDP
     *
     * @return string XML string representing metadata
     * @throws Error
     * @throws Exception
     */
    public function getMetadata(): string
    {
        $auth = $this->auth;
        $settings = $auth->getSettings();
        $metadata = $settings->getSPMetadata();
        $errors = $settings->validateMetadata($metadata);

        if (empty($errors)) {
            return $metadata;
        } else {
            throw new InvalidArgumentException(
                'Invalid SP metadata: ' . implode(', ', $errors),
                Error::METADATA_SP_INVALID
            );
        }
    }

    /**
     * Get the last error reason from \OneLogin_Saml2_Auth, useful for error debugging.
     *
     * @see Auth::getLastErrorReason()
     * @return string
     */
    public function getLastErrorReason(): string
    {
        return $this->auth->getLastErrorReason();
    }
}
