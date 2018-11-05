<?php

namespace Aacotroneo\Saml2\Http\Controllers;

use Aacotroneo\Saml2\Events\Saml2LoginEvent;
use Aacotroneo\Saml2\Saml2Auth;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

/**
 * Class Saml2Controller
 *
 * @package Aacotroneo\Saml2\Http\Controllers
 */
class Saml2Controller extends Controller
{
    /**
     * @var Saml2Auth
     */
    protected $saml2Auth;

    /**
     * @param Saml2Auth $saml2Auth
     */
    public function __construct(Saml2Auth $saml2Auth)
    {
        $this->saml2Auth = $saml2Auth;
    }

    /**
     * Generate local sp metadata
     *
     * @return \Illuminate\Contracts\Routing\ResponseFactory|\Symfony\Component\HttpFoundation\Response
     * @throws \OneLogin\Saml2\Error
     */
    public function metadata()
    {
        $metadata = $this->saml2Auth->getMetadata();

        return response($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    /**
     * Process an incoming saml2 assertion request.
     * Fires 'Saml2LoginEvent' event if a valid user is Found
     *
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector
     * @throws \OneLogin\Saml2\Error
     * @throws \OneLogin\Saml2\ValidationError
     */
    public function acs()
    {
        $errors = $this->saml2Auth->acs();

        if (!empty($errors)) {
            logger()->error('Saml2 error_detail', ['error' => $this->saml2Auth->getLastErrorReason()]);
            session()->flash('saml2_error_detail', [$this->saml2Auth->getLastErrorReason()]);

            logger()->error('Saml2 error', $errors);
            session()->flash('saml2_error', $errors);
            return redirect(config('saml2_settings.errorRoute'));
        }

        $user = $this->saml2Auth->getSaml2User();

        event(new Saml2LoginEvent($user, $this->saml2Auth));

        $redirectUrl = $user->getIntendedUrl();

        if ($redirectUrl !== null) {
            return redirect($redirectUrl);
        } else {
            return redirect(config('saml2_settings.loginRoute'));
        }
    }

    /**
     * Process an incoming saml2 logout request
     *
     * Fires 'saml2.logoutRequestReceived' event if its valid.
     * This means the user logged out of the SSO infrastructure, you 'should' log him out locally too.
     *
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector
     * @throws \OneLogin\Saml2\Error
     * @throws Exception
     */
    public function sls()
    {
        $error = $this->saml2Auth->sls(config('saml2_settings.retrieveParametersFromServer'));

        if (!empty($error)) {
            throw new Exception("Could not log out");
        }

        return redirect(config('saml2_settings.logoutRoute')); //may be set a configurable default
    }

    /**
     * This initiates a logout request across all the SSO infrastructure.
     *
     * @param Request $request
     *
     * @throws \OneLogin\Saml2\Error
     */
    public function logout(Request $request)
    {
        //will actually end up in the sls endpoint
        $this->saml2Auth->logout(
            $request->query('returnTo'),
            $request->query('nameId'),
            $request->query('sessionIndex')
        );

        //does not return
    }

    /**
     * This initiates a login request
     *
     * @return null|string
     * @throws \OneLogin\Saml2\Error
     */
    public function login(): ?string
    {
        $this->saml2Auth->login(config('saml2_settings.loginRoute'));
    }
}
