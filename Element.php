<?php

namespace attitude\Elements;

use \attitude\Elements\Singleton_Prototype;

class Boot_Element extends Singleton_Prototype
{
    protected function __construct()
    {
        return $this->init();
    }

    private function init()
    {
        $this->security();
        $this->request();
        $this->stdin();

        define('BOOT_HAS_PASSED', true);

        return $this;
    }

    /**
     * Boot sequence with some basic security
     *
     * @author: Martin Adamko <@martin_adamko>
     * @since: v0.1.0
     *
     */
    private function security()
    {
        if (!isset($_SERVER['SCHEME'])) {
            $_SERVER['SCHEME'] = 'HTTP';
        }

        $is_attack = false;

        // Block bad requests
        if(strstr($_SERVER['REQUEST_URI'], '../')) {
            $is_attack = 'Possible Attack: Using ../ in request_uri is forbiudden.';
        }

        /*
         * Block Bad Queries
         * Plugin URI: http://perishablepress.com/press/2009/12/22/protect-wordpress-against-malicious-url-requests/
         * Description: Protect WordPress Against Malicious URL Requests
         * Author URI: http://perishablepress.com/
         * Author: Perishable Press
         * Version: 1.0
         */
        if (strlen($_SERVER['REQUEST_URI']) > 255) {
            $is_attack = 'Possible Attack: Too long REQUEST_URI';
        }
        if (stripos($_SERVER['REQUEST_URI'], "eval(")) {
            $is_attack = 'Possible Attack: Using eval() in REQUEST_URI is forbidden';
        }
        if (stripos($_SERVER['REQUEST_URI'], "CONCAT")) {
            $is_attack = 'Possible Attack: Using CONCAT in REQUEST_URI is forbidden';
        }
        if (stripos($_SERVER['REQUEST_URI'], "UNION+SELECT")) {
            $is_attack = 'Possible Attack: Using UNION+SELECT in REQUEST_URI is forbidden';
        }
        if (stripos($_SERVER['REQUEST_URI'], "base64")) {
            $is_attack = 'Possible Attack: Using base64 in REQUEST_URI is forbidden';
        }

        if ($is_attack) {
            // @TODO: Collect some more information
            trigger_error($is_attack, E_USER_ERROR);
        }

        // Check the Authorization
        $all_headers = apache_request_headers();
        $_SERVER['Authorization'] = isset($all_headers['Authorization']) ? $all_headers['Authorization'] : '';

        // Just log first version
        trigger_error('Authorization: '.$_SERVER['Authorization'], E_USER_NOTICE);
    }

    /**
     * Modify REQUEST_URI
     *
     * Unifies incomming HTTP request with environment requirements:
     *
     * - removes search query from REQUEST_URI (part after `?`)
     * - creates array of REQUEST_FRAGMENT (part after `#`) by spliting with `|`
     * - creates REQUEST_URI_ARRAY by spliting REQUEST_URI with '/'
     * - sets pseudo accept using file extension
     * - canges each '-' to '_' by default
     *
     * @author: Martin Adamko <@martin_adamko>
     * @since: v0.1.0
     *
     */
    private function request()
    {
        $_SERVER['REQUEST_URI_ORIGINAL'] = $_SERVER['REQUEST_URI'];

        if (DependencyContainer::get('Boot::dashesToUnderscores', false)) {
            // Translate '-' as '_'
            $_SERVER['REQUEST_URI'] = str_replace('-', '_', $_SERVER['REQUEST_URI']);
        }

        if (DependencyContainer::get('Boot::decodeSpecialCharacters', true)) {
            // Decode spacial characters
            $_SERVER['REQUEST_URI'] = urldecode($_SERVER['REQUEST_URI']);
        }

        if (DependencyContainer::get('Boot::setupRequestFragment', true)) {
            // Set URI fragments
            if (strstr($_SERVER['REQUEST_URI'], '#')) {
                list($_SERVER['REQUEST_URI'], $_SERVER['REQUEST_FRAGMENT']) = explode('#', $_SERVER['REQUEST_URI']);
                $_SERVER['REQUEST_FRAGMENT'] = explode('|', $_SERVER['REQUEST_FRAGMENT']);
            }
        }

        // There is $_SERVER['QUERY_STRING'] available, remove ?query from SERVER_URI.
        if (strstr($_SERVER['REQUEST_URI'], '?')) {
            list($_SERVER['REQUEST_URI']) = explode('?', $_SERVER['REQUEST_URI']);
        }

        // Remove trailing slash by default
        $_SERVER['REQUEST_URI'] = rtrim($_SERVER['REQUEST_URI'], '/');
        $_SERVER['REQUEST_URI'] = empty($_SERVER['REQUEST_URI']) ? '/' : $_SERVER['REQUEST_URI'];

        // Create custom $_SERVER global
        $_SERVER['REQUEST_URI_ARRAY'] = explode('/', trim($_SERVER['REQUEST_URI'], '/'));

        // SET PSEUDO ACCEPT ///////////////////////////////////////////////////////////

        if (strstr($_SERVER['REQUEST_URI'], '.')) {
            $ext = get_file_extension($_SERVER['REQUEST_URI']);
            if (!empty($ext) && !strstr($ext, '/')) {
                $_SERVER['REQUEST_URI'] = get_file_filename($_SERVER['REQUEST_URI']);
                $_SERVER['HTTP_ACCEPT'] = "*/{$ext};";
            }
        }

        if( !isset($_SERVER['HTTP_ACCEPT'])) {
            $_SERVER['HTTP_ACCEPT'] = '*/html;';
        }

        // Beautify
        ksort($_SERVER);
    }

    /**
     * Handles request input data by various methods
     *
     * @author: Martin Adamko <@martin_adamko>
     * @since: v0.1.0
     *
     */
    private function stdin()
    {
        if (isset($_SERVER['argv'][0])) {
            parse_str($_SERVER['argv'][0], $_SERVER['argv']);
        }

        // Check against allowed/defined HTTP/1.1 methods
        if (!isset($_SERVER['REQUEST_METHOD']) || !in_array($_SERVER['REQUEST_METHOD'], array('GET', 'POST', 'PUT', 'HEAD', 'OPTIONS', 'DELETE'))) {
            trigger_error('Requested method is not allowed', E_USER_ERROR);
        }

        // Unify with CLI created constant
        if (!defined('STDIN')) {
            define('STDIN', fopen("php://input", "r"));
        }

        $global = '_'.$_SERVER['REQUEST_METHOD'];

        if (empty($GLOBALS[$global])) {
            while ($data = trim(fgets(STDIN))) {
                if (isset($_SERVER['CONTENT_TYPE']) && $_SERVER['CONTENT_TYPE']==='application/x-www-form-urlencoded') {
                    parse_str($data, $data);
                } else {
                    $data = json_decode($data, true);
                }

                if(is_array($data)) {
                    $GLOBALS[$global] = array_merge($GLOBALS[$global], $data);
                }
            }
        }

        fclose(STDIN);
    }
}
