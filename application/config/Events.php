<?php

namespace Config;

use App\Config\Services;
use CodeIgniter\Exceptions\FrameworkException;
use MX\CI;
use CodeIgniter\Events\Events;

/*
 * --------------------------------------------------------------------
 * Application Events
 * --------------------------------------------------------------------
 * Events allow you to tap into the execution of the program without
 * modifying or extending core files. This file provides a central
 * location to define your events, though they can always be added
 * at run-time, also, if needed.
 *
 * You create code that can execute by subscribing to events with
 * the 'on()' method. This accepts any form of callable, including
 * Closures, that will be executed when the event is triggered.
 *
 * Example:
 *      Events::on('create', [$myInstance, 'myMethod']);
 */

Events::on('pre_controller', static function () {
    if (ENVIRONMENT !== 'testing') {
        if (ini_get('zlib.output_compression')) {
            throw FrameworkException::forEnabledZlibOutputCompression();
        }

        while (ob_get_level() > 0) {
            ob_end_flush();
        }

        ob_start(static fn ($buffer) => $buffer);
    }

    /*
     * --------------------------------------------------------------------
     * Debug Toolbar Listeners.
     * --------------------------------------------------------------------
     * If you delete, they will no longer be collected.
     */
    if (CI_DEBUG && ! is_cli()) {
        Events::on('DBQuery', 'CodeIgniter\Debug\Toolbar\Collectors\Database::collect');
        Services::toolbar()->respond();
    }

    /*
     * --------------------------------------------------------------------
     * FusionCMS Listeners.
     * --------------------------------------------------------------------
     * Validate module and minimum required version. | Handle cookie login.
     */

    // SKIP! Template class not found!
    if(!isset(CI::$APP->template))
        return;

    // Module: Initialize
    $module = [
        'name' => CI::$APP->template->getModuleName(),
        'data' => CI::$APP->template->getModuleData()
    ];

    // Module: Disabled
    if(!isset($module['data']['enabled']) || (isset($module['data']['enabled']) && !$module['data']['enabled']))
        show_404($module['name'], false);

    // Module: Patch | Set min_required_version
    if(!isset($module['data']['min_required_version']))
        $module['data']['min_required_version'] = CI::$APP->config->item('FusionCMSVersion');

    // Module: Requires higher FusionCMS version
    if(version_compare($module['data']['min_required_version'], CI::$APP->config->item('FusionCMSVersion'), '>'))
        show_error(str_replace(['$1', '$2', '$3'], [$module['name'], $module['data']['min_required_version'], 'https://github.com/FusionWowCMS/FusionCMS'], 'The module <b>$1</b> requires FusionCMS v$2, Please update at $3'));

    // Events files: Find modules Events files
    if($eventFiles = glob(rtrim(str_replace(['\\', '/'], DIRECTORY_SEPARATOR, realpath(APPPATH)), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'modules' . DIRECTORY_SEPARATOR . '*' . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'Event.' . pathinfo(__FILE__, PATHINFO_EXTENSION)))
    {
        // Events files: Loop through
        foreach($eventFiles as $eventFile)
        {
            require_once($eventFile);
        }
    }

    // SKIP! No need to go any further!
    if(!isset(CI::$APP->user))
        return;

    // Remember-me cookie login: only when the user is not signed in yet
    if(!CI::$APP->user->isOnline())
    {
        // Username: Read cookie
        $username = CI::$APP->input->cookie('fcms_username');

        // Password: Read cookie
        $password = CI::$APP->input->cookie('fcms_password');

        // Password: Emulator Uses SRP6 Encryption | Fix for HTTP_COOKIE Error
        if($password && column('account', 'verifier') && column('account', 'salt') && CI::$APP->config->item('account_encryption') != 'SPH')
            $password = urldecode(preg_replace('~.(?:fcms_password=([^;]+))?~', '$1', @$_SERVER['HTTP_COOKIE'])); // Thanks to M3 (Asterixobelix)

        // Hooray! Username and Password found!
        if($username && $password)
        {
            // User: Set details
            $user = CI::$APP->user->setUserDetails($username, $password);

            // Redirect: Initialize
            $redirect = true;

            // Redirect: False
            if(in_array(strtolower(str_replace(CI::$APP->config->item('controller_suffix') ?? '', '', CI::$APP->router->fetch_module())), ['api']))
                $redirect = false;

            if($user == 0 && $redirect)
                redirect(str_replace(base_url(), '', current_url()) ?? CI::$APP->router->default_controller);
        }
    }

    /*
     * --------------------------------------------------------------------
     * Two-Factor Authentication (TOTP).
     * --------------------------------------------------------------------
     * Enforced in pre_controller so it runs before EVERY controller action,
     * including AJAX/JSON endpoints, and can not be bypassed by calling an
     * action method that never renders a view.
     */
    if(CI::$APP->user->isOnline())
    {
        // Module of the requested action
        $dirModule = strtolower((string)CI::$APP->router->fetch_module());

        // The whole "auth" module is pre-2FA plumbing (login, captcha, 2FA
        // entry/verification and logout) and must stay reachable without a code.
        if($dirModule !== 'auth')
        {
            // Account's stored TOTP secret vs. the one verified in this session
            $accountTotp = CI::$APP->external_account_model->getTotpSecret();
            $sessionTotp = CI::$APP->user->getTotpSecret();

            if($accountTotp !== '' && $sessionTotp !== $accountTotp)
            {
                // AJAX/JSON request: reject it, do not execute the action
                if(CI::$APP->input->is_ajax_request())
                {
                    http_response_code(403);
                    die(json_encode(['status' => 'error', 'message' => 'Two-factor authentication required']));
                }

                // Normal request: send the user to the 2FA verification page
                redirect(CI::$APP->template->page_url . 'auth/security');
            }
        }
    }
});
