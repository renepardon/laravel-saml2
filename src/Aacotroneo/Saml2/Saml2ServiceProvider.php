<?php

namespace Aacotroneo\Saml2;

use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Utils;

/**
 * Class Saml2ServiceProvider
 *
 * @package Aacotroneo\Saml2
 */
class Saml2ServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        if (config('saml2_settings.useRoutes', false) == true) {
            include __DIR__ . '/../../routes.php';
        }

        $this->publishes([
            __DIR__ . '/../../config/saml2_settings.php' => config_path('saml2_settings.php'),
        ]);

        if (config('saml2_settings.proxyVars', false)) {
            Utils::setProxyVars(true);
        }
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerOneLoginInContainer();

        $this->app->singleton(Saml2Auth::class, function ($app) {
            return new Saml2Auth($app[Auth::class]);
        });
    }

    protected function registerOneLoginInContainer()
    {
        $this->app->singleton(Auth::class, function ($app) {
            $config = config('saml2_settings');

            if (empty($config['sp']['entityId'])) {
                $config['sp']['entityId'] = URL::route('saml_metadata');
            }

            if (empty($config['sp']['assertionConsumerService']['url'])) {
                $config['sp']['assertionConsumerService']['url'] = URL::route('saml_acs');
            }

            if (!empty($config['sp']['singleLogoutService']) &&
                empty($config['sp']['singleLogoutService']['url'])) {
                $config['sp']['singleLogoutService']['url'] = URL::route('saml_sls');
            }

            if (strpos($config['sp']['privateKey'], 'file://') === 0) {
                $config['sp']['privateKey'] = $this->extractPkeyFromFile($config['sp']['privateKey']);
            }

            if (strpos($config['sp']['x509cert'], 'file://') === 0) {
                $config['sp']['x509cert'] = $this->extractCertFromFile($config['sp']['x509cert']);
            }

            if (strpos($config['idp']['x509cert'], 'file://') === 0) {
                $config['idp']['x509cert'] = $this->extractCertFromFile($config['idp']['x509cert']);
            }

            return new Auth($config);
        });
    }

    /**
     * @param string $path
     *
     * @return string
     * @throws \Exception
     */
    protected function extractPkeyFromFile(string $path): string
    {
        $res = openssl_get_privatekey($path);

        if (empty($res)) {
            throw new \Exception('Could not read private key-file at path \'' . $path . '\'');
        }

        openssl_pkey_export($res, $pkey);
        openssl_pkey_free($res);

        return $this->extractOpensslString($pkey, 'PRIVATE KEY');
    }

    /**
     * @param string $keyString
     * @param string $delimiter
     *
     * @return string
     */
    protected function extractOpensslString(string $keyString, string $delimiter): string
    {
        $keyString = str_replace(["\r", "\n"], "", $keyString);
        $regex = '/-{5}BEGIN(?:\s|\w)+' . $delimiter . '-{5}\s*(.+?)\s*-{5}END(?:\s|\w)+' . $delimiter . '-{5}/m';

        preg_match($regex, $keyString, $matches);

        return empty($matches[1]) ? '' : $matches[1];
    }

    /**
     * @param string $path
     *
     * @return string
     * @throws \Exception
     */
    protected function extractCertFromFile(string $path): string
    {
        $res = openssl_x509_read(file_get_contents($path));

        if (empty($res)) {
            throw new \Exception('Could not read X509 certificate-file at path \'' . $path . '\'');
        }

        openssl_x509_export($res, $cert);
        openssl_x509_free($res);

        return $this->extractOpensslString($cert, 'CERTIFICATE');
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides(): array
    {
        return [];
    }
}
