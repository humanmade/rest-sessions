<?php

namespace REST_Sessions;

use WP_Error;
use WP_REST_Controller;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WP_Session_Tokens;

class Session_Controller extends WP_REST_Controller {
	const NONCE_ACTION = 'wp_rest_sessions';

	/**
	 * The namespace of this controller's route.
	 *
	 * @var string
	 */
	protected $namespace = 'sessions/v0';

	/**
	 * Register routes for authentication.
	 */
	public function register_routes() {
		register_rest_route( $this->namespace, '/sessions', [
			[
				'methods'  => WP_REST_Server::CREATABLE,
				'callback' => [ $this, 'create_item' ],
				'args'     => [
					'username' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => null,
						'validate_callback' => null,
					],
					'password' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => null,
						'validate_callback' => null,
					],
					'auth_nonce' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => null,
						'validate_callback' => [ $this, 'check_nonce' ],
					],
					'remember' => [
						'type'    => 'boolean',
						'default' => false,
					],
				],
			],
		] );
		register_rest_route( $this->namespace, '/sessions/current', [
			[
				'methods' => WP_REST_Server::DELETABLE,
				'callback' => [ $this, 'delete_item' ],
				'permission_callback' => [ $this, 'check_authentication' ],
			],
		] );
	}

	/**
	 * Check user authentication.
	 *
	 * @return bool True if user is logged in, false otherwise.
	 */
	public function check_authentication() {
		return is_user_logged_in();
	}

	/**
	 * Log a user in.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return mixed REST response.
	 */
	public function create_item( $request ) {
		if ( is_user_logged_in() ) {
			return new WP_Error(
				'appregistry.auth.already_logged_in',
				'You are already logged in'
			);
		}

		$cookie = null;
		$store_logged_in_cookie = function ( $value ) use ( &$cookie ) {
			$cookie = $value;
			return $value;
		};
		add_action( 'set_logged_in_cookie', $store_logged_in_cookie );

		$user = wp_signon( [
			'user_login'    => $request['username'],
			'user_password' => $request['password'],
			'remember'      => $request['remember'],
		] );

		remove_action( 'set_logged_in_cookie', $store_logged_in_cookie );

		if ( is_wp_error( $user ) ) {
			return $user;
		}

		$_COOKIE[ LOGGED_IN_COOKIE ] = $cookie;
		wp_set_current_user( $user->ID );

		$token = wp_get_session_token();
		if ( empty( $token ) ) {
			return new WP_Error();
		}

		$response = $this->prepare_item_for_response( $token, $request );
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$response->set_status( 201 );
		return $response;
	}

	/**
	 * Prepare a session for API response.
	 *
	 * @param string $id Session token ID.
	 * @return WP_REST_Response|WP_Error Response if token is valid, error otherwise.
	 */
	public function prepare_item_for_response( $id, $request ) {
		$user = wp_get_current_user();
		$session = WP_Session_Tokens::get_instance( $user->ID )->get( $id );
		if ( empty( $session ) ) {
			return new WP_Error();
		}

		$data = [
			'id'         => $id,
			'created'    => date( 'c', $session['login'] ),
			'expiration' => date( 'c', $session['expiration'] ),
			'ip'         => $session['ip'],
			'user_agent' => $session['ua'],
			'nonce'      => wp_create_nonce( 'wp_rest' ),
		];
		$response = new WP_REST_Response( $data );
		$response->add_link(
			'author',
			rest_url( sprintf( '/wp/v2/users/%d?context=edit', $user->ID ) ),
			[
				'embeddable' => true,
			]
		);
		return $response;
	}

	/**
	 * Delete a session.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return mixed Response data.
	 */
	public function delete_item( $request ) {
		$token = wp_get_session_token();
		if ( empty( $token ) ) {
			return new WP_Error();
		}

		$response = $this->prepare_item_for_response( $token, $request );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$data = $response->get_data();
		$data = [
			'deleted'  => true,
			'previous' => $data,
		];
		$response->set_data( $data );

		wp_clear_auth_cookie();
		WP_Session_Tokens::get_instance( get_current_user_id() )->destroy( $token );

		return $response;
	}

	/**
	 * Check the nonce parameter.
	 *
	 * @param mixed $value Supplied nonce value.
	 * @return boolean|WP_Error True if valid, error otherwise.
	 */
	public static function check_nonce( $value ) {
		if ( ! is_string( $value ) ) {
			return new WP_Error(
				'appregistry.auth.invalid_nonce_type',
				'Nonce must be a string'
			);
		}

		if ( wp_verify_nonce( $value, static::NONCE_ACTION ) ) {
			return true;
		}

		return new WP_Error(
			'appregistry.auth.invalid_nonce',
			'Invalid authentication nonce'
		);
	}

	/**
	 * Get the current nonce value.
	 *
	 * @return string Nonce value.
	 */
	public static function get_nonce() {
		return wp_create_nonce( static::NONCE_ACTION );
	}
}
