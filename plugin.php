<?php
/**
 * Plugin Name: REST Sessions
 * Description: Log in and out with cookie authentication.
 * Author: Human Made
 * Author URI: https://humanmade.com/
 * Version: 0.1
 */

namespace REST_Sessions;

require __DIR__ . '/inc/class-session-controller.php';

add_action( 'rest_api_init', function () {
	$controller = new Session_Controller();
	$controller->register_routes();
} );
