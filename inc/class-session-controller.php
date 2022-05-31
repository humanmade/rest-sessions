<?php

namespace REST_Sessions;

use Two_Factor_Core;
use WP_Error;
use WP_REST_Controller;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WP_Session_Tokens;
use WP_User;

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
					'2fa' => [
						'type' => 'object',
						'properties' => [
							'provider' => [
								'type' => 'string',
								'enum' => [
									'email',
									'totp',
									'backup_codes',
								],
							],
							'code' => [
								'type' => 'string',
							],
						],
						'required' => false,
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

		// Remove 2fa plugin from hooking into the login action, as it will output HTML if a 2FA code etc is not found.
		// We do our own 2fa checking.
		remove_action( 'wp_login', 'Two_Factor_Core::wp_login' );

		$user = wp_signon( [
			'user_login'    => $request['username'],
			'user_password' => $request['password'],
			'remember'      => $request['remember'],
		] );

		remove_action( 'set_logged_in_cookie', $store_logged_in_cookie );

		if ( is_wp_error( $user ) ) {
			return $user;
		}


		// If the 2FA plugin is active, validate the 2fa part of the request.
		if ( class_exists( 'Two_Factor_Core' ) ) {
			$valid_2fa = $this->validate_2fa( $request, $user );

			if ( is_wp_error( $valid_2fa ) ) {
				return $valid_2fa;
			}
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
	 * Validate the 2fa related portion of create session reuest.
	 *
	 * @param WP_REST_Request $request
	 * @param WP_User $user
	 * @return WP_Error|null
	 */
	protected function validate_2fa( $request, WP_User $user ) : ?WP_Error {
		if ( ! Two_Factor_Core::is_user_using_two_factor( $user->ID ) ) {
			return null;
		}


		$user_providers = Two_Factor_Core::get_enabled_providers_for_user( $user );
		$provider_name_map = [
			'email' => 'Two_Factor_Email',
			'totp' => 'Two_Factor_Totp',
			'backup_codes' => 'Two_Factor_Backup_Codes',
		];

		$user_providers_public_names = [];
		foreach ( $user_providers as $provider ) {
			$user_providers_public_names[] = array_search( $provider, $provider_name_map );
		}

		$error = new WP_Error( '2fa_required', 'Please provide your 2FA code.', [
			'status' => 401,
			'2fa_providers' => $user_providers_public_names,
		] );


		$provider = $provider_name_map[ $request['2fa']['provider'] ];

		// Validate provider / value if it's been passed.
		if ( ! empty( $request['2fa']['provider'] ) && ! empty( $request['2fa']['value'] ) ) {
			if ( ! in_array( $provider, $user_providers, true ) ) {
				$error->add( 'invalid_2fa_provider', 'User does not have this provider enabled.' );
			}
			$providers = Two_Factor_Core::get_providers();

			switch ( $provider ) {
				case 'Two_Factor_Email':
					$valid = $providers[ $provider ]->validate_token( $user->ID, $request['2fa']['value'] );
					// Valid email token, all good!
					if ( $valid === true ) {
						return null;
					}
					$error->add( 'invalid_2fa_value', 'The email code you provided was not valid.' );
					break;
				case 'Two_Factor_Totp':
					$key = get_user_meta( $user->ID, $provider::SECRET_META_KEY, true );
					$valid = $providers[ $provider ]->is_valid_authcode( $key, $request['2fa']['value'] );
					if ( $valid === true ) {
						return null;
					}
					$error->add( 'invalid_2fa_value', 'The one-time code you provided was not valid.' );
					break;
				case 'Two_Factor_Backup_Codes':
					$valid = $providers[ $provider ]->validate_code( $user, $request['2fa']['value'] );
					if ( $valid === true ) {
						return null;
					}
					$error->add( 'invalid_2fa_value', 'The backup code you provided was not valid.' );
					break;
			}
		}

		return $error;

		//self::show_two_factor_login( $user );
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
