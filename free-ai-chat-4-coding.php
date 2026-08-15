<?php
/**
 * Plugin Name: Free MLP AI Chat (https://ptero.pro)
 * Plugin URI:  https://ptero.pro
 * Description: code with free ai chat at https://ptero.pro/ (no premium plans)
 * Version:     1.6.0
 * Author:      AmineKHD
 * License:     GPL v2 

/**
 * Main plugin class.
 */
class MLP_AI_Chat {

	private static $instance = null;

	public static function instance() {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		register_activation_hook( __FILE__, array( $this, 'activate' ) );
		register_deactivation_hook( __FILE__, array( $this, 'deactivate' ) );

		// Run the table/column migration for sites that had an earlier
		// version active (activation hooks don't re-fire on plugin update).
		add_action( 'plugins_loaded', array( $this, 'maybe_upgrade_db' ) );

		add_action( 'admin_notices', array( $this, 'maybe_show_missing_key_notice' ) );
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
		add_shortcode( 'mlp_ai_chat', array( $this, 'render_shortcode' ) );


		add_action( 'wp_head', array( $this, 'render_twitter_card_meta' ) );

		add_action( 'admin_menu', array( $this, 'register_admin_page' ) );
		add_action( 'admin_post_mlp_ai_toggle_disabled', array( $this, 'handle_toggle_disabled' ) );
		add_action( 'admin_post_mlp_ai_toggle_model', array( $this, 'handle_toggle_model' ) );

	
		add_action( 'init', array( $this, 'maybe_auto_login_guest' ), 1 );
	}


	public function maybe_auto_login_guest() {
		if ( is_user_logged_in() ) {
			return;
		}
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return;
		}
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return;
		}
		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
			return;
		}

		if ( ! empty( $_POST['log'] ) || ! empty( $_POST['pwd'] ) || ! empty( $_POST['testcookie'] ) ) {
			return;
		}
	
		if ( headers_sent() ) {
			return;
		}

		$user = wp_signon(
			array(
				'user_login'    => MLP_AI_CHAT_GUEST_USER,
				'user_password' => defined('MLP_AI_CHAT_GUEST_PASS') ? MLP_AI_CHAT_GUEST_PASS : '',
				'remember'      => false,
			),
			$this->request_is_https()
		);

		if ( ! is_wp_error( $user ) ) {
			wp_set_current_user( $user->ID );
		}
	}


	private function request_is_https() {
		if ( is_ssl() ) {
			return true;
		}
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && 'https' === strtolower( wp_unslash( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) ) {
			return true;
		}
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_SSL'] ) && 'on' === strtolower( wp_unslash( $_SERVER['HTTP_X_FORWARDED_SSL'] ) ) ) {
			return true;
		}
		return false;
	}


	private function ensure_guest_user_exists() {
		if ( get_user_by( 'login', MLP_AI_CHAT_GUEST_USER ) ) {
			return;
		}

		wp_insert_user(
			array(
				'user_login'   => MLP_AI_CHAT_GUEST_USER,
				'user_pass'    => defined('MLP_AI_CHAT_GUEST_PASS') ? MLP_AI_CHAT_GUEST_PASS : wp_generate_password(24, true, true),
				'user_email'   => 'guest+' . wp_generate_password( 8, false ) . '@example.invalid',
				'display_name' => 'Guest',
				'role'         => 'subscriber',
			)
		);
	}


	public function activate() {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();
		$guests_table     = $wpdb->prefix . 'mlp_ai_guests';

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';


		$sql3 = "CREATE TABLE $guests_table (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			guest_token VARCHAR(64) NOT NULL,
			username VARCHAR(60) NOT NULL DEFAULT '',
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY guest_token (guest_token)
		) $charset_collate;";

		dbDelta( $sql3 );

		add_option( 'mlp_ai_chat_total_requests', 0, '', false );
		add_option( 'mlp_ai_chat_disabled', '0', '', false );
		add_option( 'mlp_ai_chat_model_disabled', array(), '', false );
		add_option( 'mlp_ai_chat_model_status', array(), '', false );
		add_option( 'mlp_ai_chat_model_feedback', array(), '', false );

		$this->ensure_guest_user_exists();

		wp_clear_scheduled_hook( 'mlp_ai_chat_prune_stale' );
		$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}mlp_ai_messages" );
		$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}mlp_ai_conversations" );

		update_option( 'mlp_ai_chat_db_version', MLP_AI_CHAT_VERSION );
	}

	public function deactivate() {
		wp_clear_scheduled_hook( 'mlp_ai_chat_prune_stale' );
	}


	public function maybe_upgrade_db() {
		if ( get_option( 'mlp_ai_chat_db_version' ) === MLP_AI_CHAT_VERSION ) {
			return;
		}
		$this->activate();
	}

	public function maybe_show_missing_key_notice() {
		$msgs = array();
		if ( ! defined( 'MLP_TOKENHARBOR_KEY' ) || ! MLP_TOKENHARBOR_KEY ) {
			$msgs[] = 'Please define <code>MLP_TOKENHARBOR_KEY</code> in your wp-config.php with your Token Harbor API key (looks like <code>thk_live_…</code>, from the <a href="https://tokenharbor.ai/dashboard" target="_blank" rel="noopener">Token Harbor dashboard</a>).';
		}
		if ( ! defined( "MLP_AI_RNTMSH-Route01-PASS" ) || ! constant( "MLP_AI_RNTMSH-Route01-PASS" ) ) {
			$msgs[] = 'Please define <code>MLP_AI_RNTMSH-Route01-PASS</code> in your wp-config.php with your RNTM.sh Route01 API key to enable the RNTM.sh Route01 (Free) model.';
		}
		if ( ! defined( 'MLP_AI_CHAT_GUEST_PASS' ) || ! MLP_AI_CHAT_GUEST_PASS ) {
			$msgs[] = 'Please define <code>MLP_AI_CHAT_GUEST_PASS</code> in your wp-config.php with a secure random password for the shared guest account.';
		}
		if ( $msgs ) {
			echo '<div class="notice notice-error"><p><strong>MLP AI Chat:</strong> ' . implode( ' ', $msgs ) . '</p></div>';
		}
	}

	public function register_admin_page() {
		add_menu_page(
			'AI Chat',
			'AI Chat',
			'read',
			'chat-ai-chat',
			array( $this, 'render_admin_page' ),
			'dashicons-format-chat',
			30
		);

		add_submenu_page(
			'chat-ai-chat',
			'AI Chat Dashboard',
			'Dashboard',
			'manage_options',
			'chat-ai-chat-dashboard',
			array( $this, 'render_dashboard_page' )
		);
	}

	public function render_admin_page() {
		echo '<div class="wrap"><h1 style="margin-bottom:10px;">AI Chat</h1>';
		echo $this->render_shortcode( array() );
		echo '</div>';
	}

	
	public function handle_toggle_disabled() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'You do not have permission to do this.' );
		}
		check_admin_referer( 'mlp_ai_toggle_disabled' );

		$new_state = $this->is_ai_disabled() ? '0' : '1';
		update_option( 'mlp_ai_chat_disabled', $new_state );

		wp_safe_redirect( add_query_arg( 'mlp_toggled', '1', wp_get_referer() ? wp_get_referer() : admin_url( 'admin.php?page=chat-ai-chat-dashboard' ) ) );
		exit;
	}

	
	public function handle_toggle_model() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'You do not have permission to do this.' );
		}
		check_admin_referer( 'mlp_ai_toggle_model' );

		$model_id = isset( $_POST['model_id'] ) ? sanitize_text_field( wp_unslash( $_POST['model_id'] ) ) : '';
		if ( $model_id ) {
			$this->toggle_model_disabled( $model_id );
		}

		wp_safe_redirect( add_query_arg( 'mlp_toggled', '1', wp_get_referer() ? wp_get_referer() : admin_url( 'admin.php?page=chat-ai-chat-dashboard' ) ) );
		exit;
	}

	public function render_dashboard_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'You do not have permission to access this page.' );
		}

		$data       = $this->get_admin_dashboard_data();
		$toggle_url = wp_nonce_url(
			add_query_arg( 'action', 'mlp_ai_toggle_disabled', admin_url( 'admin-post.php' ) ),
			'mlp_ai_toggle_disabled'
		);
		$state_colors = array(
			'online'       => '#00a32a',
			'rate_limited' => '#dba617',
			'blocked'      => '#d63638',
			'error'        => '#d63638',
			'offline'      => '#787c82',
			'disabled'     => '#d63638',
			'unknown'      => '#787c82',
		);
		?>
		<div class="wrap">
			<h1 style="margin-bottom:20px;">AI Chat Dashboard</h1>
			<p>This same dashboard is also built into the chat itself — open the chat and look for <strong>Administration</strong> in the sidebar.</p>

			<?php if ( isset( $_GET['mlp_toggled'] ) ) : ?>
				<div class="notice notice-success is-dismissible"><p>Setting updated.</p></div>
			<?php endif; ?>

			<div style="display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px;">
				<div style="background:#fff; border:1px solid #dcdcde; border-radius:6px; padding:20px; min-width:220px; flex:1;">
					<div style="font-size:13px; color:#646970; text-transform:uppercase; letter-spacing:.03em; margin-bottom:8px;">AI Status</div>
					<div style="font-size:22px; font-weight:600; color:<?php echo $data['disabled'] ? '#d63638' : '#00a32a'; ?>;">
						<?php echo $data['disabled'] ? 'Disabled' : 'Enabled'; ?>
					</div>
				</div>
				<div style="background:#fff; border:1px solid #dcdcde; border-radius:6px; padding:20px; min-width:220px; flex:1;">
					<div style="font-size:13px; color:#646970; text-transform:uppercase; letter-spacing:.03em; margin-bottom:8px;">Total Requests</div>
					<div style="font-size:22px; font-weight:600;"><?php echo esc_html( number_format_i18n( $data['total_requests'] ) ); ?></div>
				</div>
				<div style="background:#fff; border:1px solid #dcdcde; border-radius:6px; padding:20px; min-width:220px; flex:1;">
					<div style="font-size:13px; color:#646970; text-transform:uppercase; letter-spacing:.03em; margin-bottom:8px;">New Users Today</div>
					<div style="font-size:22px; font-weight:600;"><?php echo esc_html( number_format_i18n( $data['new_today'] ) ); ?></div>
				</div>
				<div style="background:#fff; border:1px solid #dcdcde; border-radius:6px; padding:20px; min-width:220px; flex:1;">
					<div style="font-size:13px; color:#646970; text-transform:uppercase; letter-spacing:.03em; margin-bottom:8px;">All Users</div>
					<div style="font-size:22px; font-weight:600;"><?php echo esc_html( number_format_i18n( $data['all_users'] ) ); ?></div>
					<div style="font-size:12px; color:#646970; margin-top:4px;">Visitors who set a name to use the AI chat.</div>
				</div>
			</div>

			<div style="background:#fff; border:1px solid #dcdcde; border-radius:6px; padding:20px; max-width:640px; margin-bottom:24px;">
				<h2 style="margin-top:0;">Global Controls</h2>
				<p>When disabled, sending new messages is blocked for every visitor (logged in or not), for every model.</p>
				<form method="post" action="<?php echo esc_url( $toggle_url ); ?>">
					<button type="submit" class="button <?php echo $data['disabled'] ? 'button-primary' : 'button-secondary'; ?>">
						<?php echo $data['disabled'] ? 'Re-enable AI Chat' : 'Disable AI Chat'; ?>
					</button>
				</form>
			</div>

			<div style="background:#fff; border:1px solid #dcdcde; border-radius:6px; padding:20px; max-width:820px;">
				<h2 style="margin-top:0;">Models</h2>
				<table class="widefat striped" style="max-width:780px;">
					<thead><tr><th>Model</th><th>Status</th><th>Last checked</th><th>👍 Likes</th><th>👎 Dislikes</th><th></th></tr></thead>
					<tbody>
					<?php foreach ( $data['models'] as $m ) :
						$model_toggle_url = wp_nonce_url(
							add_query_arg( array( 'action' => 'mlp_ai_toggle_model', 'model_id' => $m['id'] ), admin_url( 'admin-post.php' ) ),
							'mlp_ai_toggle_model'
						);
						?>
						<tr>
							<td><?php echo esc_html( $m['label'] ); ?></td>
							<td>
								<span style="display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; background:<?php echo esc_attr( $state_colors[ $m['state'] ] ); ?>;"></span>
								<?php echo esc_html( $m['state_label'] ); ?>
								<?php if ( $m['message'] ) : ?><div style="font-size:11px; color:#787c82;"><?php echo esc_html( $m['message'] ); ?></div><?php endif; ?>
							</td>
							<td><?php echo $m['last_checked'] ? esc_html( human_time_diff( strtotime( $m['last_checked'] ), current_time( 'timestamp' ) ) ) . ' ago' : '—'; ?></td>
							<td style="color:#00a32a; font-weight:600;"><?php echo esc_html( number_format_i18n( $m['likes'] ) ); ?></td>
							<td style="color:#d63638; font-weight:600;"><?php echo esc_html( number_format_i18n( $m['dislikes'] ) ); ?></td>
							<td>
								<form method="post" action="<?php echo esc_url( $model_toggle_url ); ?>">
									<button type="submit" class="button button-small"><?php echo $m['disabled'] ? 'Enable' : 'Disable'; ?></button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}


	private function get_admin_dashboard_data() {
		global $wpdb;
		$guests_table = $wpdb->prefix . 'mlp_ai_guests';

		$today_start = current_time( 'Y-m-d' ) . ' 00:00:00';
		$new_today   = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM $guests_table WHERE first_seen >= %s", $today_start )
		);
		$all_users = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $guests_table" );

		$state_labels = array(
			'online'       => 'Online',
			'rate_limited' => 'Rate Limited',
			'blocked'      => 'Blocked',
			'error'        => 'Error',
			'offline'      => 'Offline',
			'disabled'     => 'Disabled',
			'unknown'      => 'Unknown (not used yet)',
		);

		$models        = unserialize( MLP_AI_CHAT_MODELS );
		$status_map    = $this->get_model_status_map();
		$disabled_map  = $this->get_model_disabled_map();
		$feedback_map  = $this->get_model_feedback_map();
		$models_out    = array();

		foreach ( $models as $id => $cfg ) {
			$is_disabled  = ! empty( $disabled_map[ $id ] );
			$has_key      = defined( $cfg['key_const'] ) && constant( $cfg['key_const'] );
			$row          = isset( $status_map[ $id ] ) ? $status_map[ $id ] : array();
			$state        = isset( $row['state'] ) ? $row['state'] : 'unknown';
			$fb           = isset( $feedback_map[ $id ] ) ? $feedback_map[ $id ] : array();

			if ( $is_disabled ) {
				$state = 'disabled';
			} elseif ( ! $has_key ) {
				$state = 'offline';
			}

			$models_out[] = array(
				'id'           => $id,
				'label'        => $cfg['label'],
				'configured'   => $has_key,
				'disabled'     => $is_disabled,
				'state'        => $state,
				'state_label'  => isset( $state_labels[ $state ] ) ? $state_labels[ $state ] : ucfirst( $state ),
				'message'      => $is_disabled ? 'Disabled by admin' : ( ! $has_key ? 'API key not configured' : ( isset( $row['message'] ) ? $row['message'] : '' ) ),
				'last_checked' => isset( $row['last_checked'] ) ? $row['last_checked'] : '',
				'likes'        => isset( $fb['likes'] ) ? (int) $fb['likes'] : 0,
				'dislikes'     => isset( $fb['dislikes'] ) ? (int) $fb['dislikes'] : 0,
			);
		}

		return array(
			'disabled'       => $this->is_ai_disabled(),
			'total_requests' => (int) get_option( 'mlp_ai_chat_total_requests', 0 ),
			'new_today'      => $new_today,
			'all_users'      => $all_users,
			'models'         => $models_out,
		);
	}

	/* -----------------------------------------------------------------
	 * REST API
	 * --------------------------------------------------------------- */

	public function register_routes() {
	

		register_rest_route(
			'mlp/v1',
			'/chat',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'rest_chat' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
			)
		);

		register_rest_route(
			'mlp/v1',
			'/chat-stream',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'rest_chat_stream' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
			)
		);


		register_rest_route(
			'mlp/v1',
			'/status',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'rest_status' ),
					'permission_callback' => '__return_true',
				),
			)
		);

	
		register_rest_route(
			'mlp/v1',
			'/feedback',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'rest_feedback' ),
					'permission_callback' => array( $this, 'permission_check' ),
				),
			)
		);

		register_rest_route(
			'mlp/v1',
			'/admin/status',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( $this, 'rest_admin_status' ),
					'permission_callback' => array( $this, 'permission_check_admin' ),
				),
			)
		);
		register_rest_route(
			'mlp/v1',
			'/admin/toggle-global',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'rest_admin_toggle_global' ),
					'permission_callback' => array( $this, 'permission_check_admin' ),
				),
			)
		);
		register_rest_route(
			'mlp/v1',
			'/admin/toggle-model',
			array(
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'rest_admin_toggle_model' ),
					'permission_callback' => array( $this, 'permission_check_admin' ),
				),
			)
		);

	}

	public function permission_check() {

		return true;
	}

	
	private function resolve_identity( WP_REST_Request $request ) {
		$user_id = get_current_user_id();

		if ( $user_id ) {
			return array( 'user_id' => $user_id, 'guest_token' => '' );
		}

		$raw_token   = $request->get_header( 'x-mlp-guest-token' );
		$guest_token = preg_replace( '/[^a-zA-Z0-9]/', '', (string) $raw_token );
		$guest_token = substr( $guest_token, 0, 64 );

		$raw_username = $request->get_header( 'x-mlp-guest-username' );
		if ( $guest_token && $raw_username ) {
			$this->upsert_guest( $guest_token, sanitize_text_field( $raw_username ) );
		}

		return array( 'user_id' => 0, 'guest_token' => $guest_token );
	}


	public function permission_check_admin() {
		return current_user_can( 'manage_options' );
	}

	
	private function upsert_guest( $guest_token, $username ) {
		global $wpdb;
		$table = $wpdb->prefix . 'mlp_ai_guests';
		$now   = current_time( 'mysql' );
		$username = mb_substr( $username, 0, 60 );

		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO $table (guest_token, username, first_seen, last_seen) VALUES (%s, %s, %s, %s)
				 ON DUPLICATE KEY UPDATE username = VALUES(username), last_seen = VALUES(last_seen)",
				$guest_token,
				$username,
				$now,
				$now
			)
		);
	}

	private function is_ai_disabled() {
		return get_option( 'mlp_ai_chat_disabled', '0' ) === '1';
	}


	private function increment_total_requests() {
		$current = (int) get_option( 'mlp_ai_chat_total_requests', 0 );
		update_option( 'mlp_ai_chat_total_requests', $current + 1 );
	}

	public function rest_status( WP_REST_Request $request ) {
		return rest_ensure_response( array(
			'disabled'       => $this->is_ai_disabled(),
			'disabled_models' => array_keys( array_filter( $this->get_model_disabled_map() ) ),
		) );
	}


	public function rest_feedback( WP_REST_Request $request ) {
		$model_id = sanitize_text_field( (string) $request->get_param( 'model_id' ) );
		$type     = (string) $request->get_param( 'type' );
		$action   = (string) $request->get_param( 'action' );

		$models = unserialize( MLP_AI_CHAT_MODELS );
		if ( ! $model_id || ! isset( $models[ $model_id ] ) ) {
			return new WP_Error( 'mlp_bad_model', 'Unknown model.', array( 'status' => 400 ) );
		}
		if ( ! in_array( $type, array( 'like', 'dislike' ), true ) ) {
			return new WP_Error( 'mlp_bad_type', "type must be 'like' or 'dislike'.", array( 'status' => 400 ) );
		}
		$delta = ( 'remove' === $action ) ? -1 : 1;

		$counts = $this->adjust_model_feedback( $model_id, $type, $delta );

		return rest_ensure_response( array(
			'model_id' => $model_id,
			'likes'    => (int) $counts['likes'],
			'dislikes' => (int) $counts['dislikes'],
		) );
	}


	private function get_model_disabled_map() {
		$map = get_option( 'mlp_ai_chat_model_disabled', array() );
		return is_array( $map ) ? $map : array();
	}

	private function is_model_disabled( $model_id ) {
		$map = $this->get_model_disabled_map();
		return ! empty( $map[ $model_id ] );
	}

	private function toggle_model_disabled( $model_id ) {
		$map               = $this->get_model_disabled_map();
		$map[ $model_id ]  = empty( $map[ $model_id ] );
		update_option( 'mlp_ai_chat_model_disabled', $map );
		return $map[ $model_id ];
	}

	private function get_model_status_map() {
		$map = get_option( 'mlp_ai_chat_model_status', array() );
		return is_array( $map ) ? $map : array();
	}


	private function get_model_feedback_map() {
		$map = get_option( 'mlp_ai_chat_model_feedback', array() );
		return is_array( $map ) ? $map : array();
	}


	private function adjust_model_feedback( $model_id, $type, $delta ) {
		$map = $this->get_model_feedback_map();
		if ( ! isset( $map[ $model_id ] ) ) {
			$map[ $model_id ] = array( 'likes' => 0, 'dislikes' => 0 );
		}
		$key = ( 'dislike' === $type ) ? 'dislikes' : 'likes';
		$current = isset( $map[ $model_id ][ $key ] ) ? (int) $map[ $model_id ][ $key ] : 0;
		$map[ $model_id ][ $key ] = max( 0, $current + $delta );
		update_option( 'mlp_ai_chat_model_feedback', $map );
		return $map[ $model_id ];
	}


	private function set_model_status( $model_id, $state, $message = '' ) {
		$map              = $this->get_model_status_map();
		$map[ $model_id ] = array(
			'state'        => $state,
			'message'      => $message,
			'last_checked' => current_time( 'mysql' ),
		);
		update_option( 'mlp_ai_chat_model_status', $map );
	}


	private function classify_api_failure( $http_code, $message ) {
		if ( $http_code === 429 || stripos( $message, 'rate limit' ) !== false || stripos( $message, 'quota' ) !== false ) {
			return array( 'rate_limited', 'Rate limited by provider' . ( $message ? ': ' . $message : '' ) );
		}
		if ( $http_code === 401 || $http_code === 403 ) {
			return array( 'blocked', 'API key rejected/blocked by provider' . ( $message ? ': ' . $message : '' ) );
		}
		if ( $http_code === 0 || ! $http_code ) {
			return array( 'offline', $message ? $message : 'Could not reach the provider' );
		}
		return array( 'error', $message ? $message : ( 'HTTP ' . $http_code ) );
	}

	public function rest_admin_status( WP_REST_Request $request ) {
		return rest_ensure_response( $this->get_admin_dashboard_data() );
	}

	public function rest_admin_toggle_global( WP_REST_Request $request ) {
		$new_state = $this->is_ai_disabled() ? '0' : '1';
		update_option( 'mlp_ai_chat_disabled', $new_state );
		return rest_ensure_response( $this->get_admin_dashboard_data() );
	}

	public function rest_admin_toggle_model( WP_REST_Request $request ) {
		$params   = $request->get_json_params();
		$model_id = isset( $params['model_id'] ) ? sanitize_text_field( $params['model_id'] ) : '';
		$models   = unserialize( MLP_AI_CHAT_MODELS );

		if ( ! $model_id || ! isset( $models[ $model_id ] ) ) {
			return new WP_Error( 'unknown_model', 'Unknown model: ' . $model_id, array( 'status' => 400 ) );
		}

		$this->toggle_model_disabled( $model_id );
		return rest_ensure_response( $this->get_admin_dashboard_data() );
	}

	
	private function get_api_key_for_model( $model_id ) {
		$models = unserialize( MLP_AI_CHAT_MODELS );

		if ( ! isset( $models[ $model_id ] ) ) {
			return new WP_Error( 'unknown_model', 'Unknown model: ' . $model_id, array( 'status' => 400 ) );
		}

		$key_const = $models[ $model_id ]['key_const'];

		if ( ! defined( $key_const ) || ! constant( $key_const ) ) {
			return new WP_Error( 'no_api_key', 'API key constant ' . $key_const . ' is not configured in wp-config.php.', array( 'status' => 500 ) );
		}

		return constant( $key_const );
	}

	
	private function get_api_url_for_model( $model_id ) {
		$models = unserialize( MLP_AI_CHAT_MODELS );

		if ( isset( $models[ $model_id ]['api_url'] ) && $models[ $model_id ]['api_url'] ) {
			return $models[ $model_id ]['api_url'];
		}

		return MLP_AI_CHAT_API_URL;
	}

	private function get_api_model_for_model( $model_id ) {
		$models = unserialize( MLP_AI_CHAT_MODELS );

		if ( isset( $models[ $model_id ]['api_model'] ) && $models[ $model_id ]['api_model'] ) {
			return $models[ $model_id ]['api_model'];
		}

		return $model_id;
	}

	
	private function sanitize_model( $raw ) {
		$models = unserialize( MLP_AI_CHAT_MODELS );
		$id     = sanitize_text_field( (string) $raw );
		return isset( $models[ $id ] ) ? $id : MLP_AI_CHAT_DEFAULT_MODEL;
	}

	private function model_supports_images( $model_id ) {
		$models = unserialize( MLP_AI_CHAT_MODELS );
		return ! isset( $models[ $model_id ]['supports_images'] ) || (bool) $models[ $model_id ]['supports_images'];
	}

	private function build_api_messages_from_history( $history, $allow_images = true ) {
		$messages = array(
			array(
				'role'    => 'system',
				'content' =>
					"You are a helpful, friendly AI assistant. When a request involves writing or changing code, don't jump straight to a wall of finished code. Work the way an experienced pair-programmer talks out loud:\n" .
					"1. Briefly state your plan in plain sentences first (what you're about to build or change and why), 1-4 short sentences.\n" .
					"2. As you work, narrate what you're doing in short, natural lines — e.g. \"Setting up the structure...\", \"Adding the click handler...\", \"Hmm, that will break on empty input — fixing it...\", \"Double-checking the edge cases...\". Keep each line short so it reads like a running commentary, not an essay. Never fabricate progress on work you have not actually done.\n" .
					"3. Only after that narration, output the finished code in a single fenced code block per file. Always label the fence with the language and the real filename separated by a colon, e.g. ```php:chat-widget.php or ```js:app.js — never leave a code block unlabeled and never split one file's code across multiple fences.\n" .
					"4. Close with one short sentence confirming what you made, e.g. \"Done — chat-widget.php is ready.\" Do not restate or re-paste the code after the fence.\n" .
					"For quick answers, one-liners, or anything that isn't a file-sized piece of code, skip this structure and just answer directly and concisely.",
			),
		);

		if ( ! is_array( $history ) ) {
			return $messages;
		}

		foreach ( $history as $turn ) {
			if ( ! is_array( $turn ) ) {
				continue;
			}
			$role = isset( $turn['role'] ) && $turn['role'] === 'assistant' ? 'assistant' : 'user';
			$text = isset( $turn['text'] ) ? sanitize_textarea_field( (string) $turn['text'] ) : '';
			$atts = ( isset( $turn['attachments'] ) && is_array( $turn['attachments'] ) )
				? $this->sanitize_attachments( $turn['attachments'] )
				: array();

			$messages[] = array(
				'role'    => $role,
				'content' => $this->build_message_content( $text, $atts, $allow_images ),
			);
		}

		return $messages;
	}

	public function rest_chat( WP_REST_Request $request ) {
		if ( $this->is_ai_disabled() ) {
			return new WP_Error( 'ai_disabled', 'The AI chat has been temporarily disabled by the site administrator.', array( 'status' => 503 ) );
		}

		$this->resolve_identity( $request ); // Records/updates the guest name for admin stats, nothing else.
		$params = $request->get_json_params();

		$message     = isset( $params['message'] ) ? sanitize_textarea_field( $params['message'] ) : '';
		$attachments = ( isset( $params['attachments'] ) && is_array( $params['attachments'] ) )
			? $this->sanitize_attachments( $params['attachments'] )
			: array();
		$history     = isset( $params['history'] ) ? $params['history'] : array();

		$model = $this->sanitize_model( isset( $params['model'] ) ? $params['model'] : '' );

		if ( $this->is_model_disabled( $model ) ) {
			return new WP_Error( 'model_disabled', 'This model has been disabled by the site administrator.', array( 'status' => 503 ) );
		}

		$api_key = $this->get_api_key_for_model( $model );

		if ( empty( $message ) && empty( $attachments ) ) {
			return new WP_Error( 'empty_message', 'Message cannot be empty.', array( 'status' => 400 ) );
		}

		if ( is_wp_error( $api_key ) ) {
			return $api_key;
		}

		$messages = $this->build_api_messages_from_history( $history, $this->model_supports_images( $model ) );
		// Make sure the latest turn (with its attachments) is included even
		// if the client didn't append it to history itself.
		$messages[] = array( 'role' => 'user', 'content' => $this->build_message_content( $message, $attachments, $this->model_supports_images( $model ) ) );

		$api_url     = $this->get_api_url_for_model( $model );
		$api_model   = $this->get_api_model_for_model( $model );
		$ai_response = $this->call_chat_api( $messages, $api_model, $api_key, $api_url );

		if ( is_wp_error( $ai_response ) ) {
			$err_data = $ai_response->get_error_data();
			$err_code = ( is_array( $err_data ) && isset( $err_data['status'] ) ) ? (int) $err_data['status'] : 0;
			list( $state, $status_msg ) = $this->classify_api_failure( $err_code, $ai_response->get_error_message() );
			$this->set_model_status( $model, $state, $status_msg );
			return $ai_response;
		}

		$this->set_model_status( $model, 'online', '' );
		$this->increment_total_requests();

		return rest_ensure_response(
			array(
				'reply' => $ai_response['text'],
			)
		);
	}


	public function rest_chat_stream( WP_REST_Request $request ) {
		if ( $this->is_ai_disabled() ) {
			return new WP_Error( 'ai_disabled', 'The AI chat has been temporarily disabled by the site administrator.', array( 'status' => 503 ) );
		}

		$this->resolve_identity( $request ); // Records/updates the guest name for admin stats, nothing else.
		$params = $request->get_json_params();

		$message     = isset( $params['message'] ) ? sanitize_textarea_field( $params['message'] ) : '';
		$attachments = ( isset( $params['attachments'] ) && is_array( $params['attachments'] ) )
			? $this->sanitize_attachments( $params['attachments'] )
			: array();
		$history     = isset( $params['history'] ) ? $params['history'] : array();
		$conversation_id = isset( $params['conversation_id'] ) ? sanitize_text_field( (string) $params['conversation_id'] ) : '';

		$model = $this->sanitize_model( isset( $params['model'] ) ? $params['model'] : '' );

		if ( $this->is_model_disabled( $model ) ) {
			return new WP_Error( 'model_disabled', 'This model has been disabled by the site administrator.', array( 'status' => 503 ) );
		}

		$api_key = $this->get_api_key_for_model( $model );

		if ( empty( $message ) && empty( $attachments ) ) {
			return new WP_Error( 'empty_message', 'Message cannot be empty.', array( 'status' => 400 ) );
		}
		if ( is_wp_error( $api_key ) ) {
			return $api_key;
		}

		$messages   = $this->build_api_messages_from_history( $history, $this->model_supports_images( $model ) );
		$messages[] = array( 'role' => 'user', 'content' => $this->build_message_content( $message, $attachments, $this->model_supports_images( $model ) ) );

		$api_url = $this->get_api_url_for_model( $model );
		$api_model = $this->get_api_model_for_model( $model );

	
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 );
		}
		ignore_user_abort( true );

		while ( ob_get_level() ) {
			ob_end_clean();
		}
		header( 'Content-Type: text/event-stream; charset=utf-8' );
		header( 'Cache-Control: no-cache' );
		header( 'X-Accel-Buffering: no' );
		header( 'Connection: keep-alive' );

		$full_text     = '';
		$thinking_text = '';
		$sse_buffer    = '';
		$raw_body      = '';
		$usage_tokens  = 0;

		$ch = curl_init();
		curl_setopt_array( $ch, array(
			CURLOPT_URL        => $api_url,
			CURLOPT_POST       => true,
			CURLOPT_HTTPHEADER => array(
				'Content-Type: application/json',
				'Authorization: Bearer ' . $api_key,
			),
			CURLOPT_POSTFIELDS    => wp_json_encode( array(
				'model'    => $api_model,
				'messages' => $messages,
				'stream'   => true,
			) ),
			CURLOPT_WRITEFUNCTION => function ( $ch, $data ) use ( &$full_text, &$thinking_text, &$sse_buffer, &$raw_body, &$usage_tokens ) {
		
				if ( connection_aborted() ) {
					return 0;
				}

				$raw_body   .= $data;
				$sse_buffer .= $data;
				$lines       = explode( "\n", $sse_buffer );
				$sse_buffer  = array_pop( $lines );

				foreach ( $lines as $line ) {
					$line = trim( $line );
					if ( strpos( $line, 'data: ' ) !== 0 ) {
						continue;
					}
					$json = substr( $line, 6 );
					if ( $json === '[DONE]' ) {
						continue;
					}
					$chunk = json_decode( $json, true );
					if ( ! is_array( $chunk ) ) {
						continue;
					}

					if ( isset( $chunk['usage']['total_tokens'] ) ) {
						$usage_tokens = (int) $chunk['usage']['total_tokens'];
					}

					$delta = isset( $chunk['choices'][0]['delta'] ) ? $chunk['choices'][0]['delta'] : array();

					$thinking_token = isset( $delta['reasoning_content'] ) ? (string) $delta['reasoning_content'] : '';
					if ( $thinking_token !== '' ) {
						$thinking_text .= $thinking_token;
						echo 'data: ' . wp_json_encode( array( 'thinking' => $thinking_token ) ) . "\n\n";
						flush();
					}

					$token = isset( $delta['content'] ) ? (string) $delta['content'] : '';
					if ( $token !== '' ) {
						$full_text .= $token;
						echo 'data: ' . wp_json_encode( array( 'token' => $token ) ) . "\n\n";
						flush();
					}
				}
				return strlen( $data );
			},
		
			CURLOPT_TIMEOUT        => 0,
			CURLOPT_CONNECTTIMEOUT => 30,
			
			CURLOPT_LOW_SPEED_LIMIT => 1,
			CURLOPT_LOW_SPEED_TIME  => 300,
			CURLOPT_SSL_VERIFYPEER => true,
		) );

		curl_exec( $ch );
		$curl_error = curl_error( $ch );
		$http_code  = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		curl_close( $ch );

		if ( $curl_error || ( $full_text === '' && $thinking_text === '' ) ) {
			$msg = $curl_error;
			if ( ! $msg ) {
				$decoded = json_decode( trim( $raw_body ), true );
				if ( is_array( $decoded ) && isset( $decoded['error']['message'] ) ) {
					$msg = 'API error: ' . $decoded['error']['message'];
				} elseif ( is_array( $decoded ) && isset( $decoded['message'] ) ) {
					$msg = 'API error: ' . $decoded['message'];
				} elseif ( $http_code >= 400 ) {
					$msg = 'API returned HTTP ' . $http_code . '. Response: ' . wp_strip_all_tags( substr( $raw_body, 0, 300 ) );
				} else {
					$msg = 'No response received from AI (HTTP ' . $http_code . ').';
				}
			}
			list( $state, $status_msg ) = $this->classify_api_failure( $http_code, $msg );
			$this->set_model_status( $model, $state, $status_msg );
			echo 'data: ' . wp_json_encode( array( 'error' => $msg ) ) . "\n\n";
			flush();
			exit;
		}

		$this->set_model_status( $model, 'online', '' );
		$this->increment_total_requests();

	
		$done_payload = array( 'done' => true, 'conversation_id' => $conversation_id );
		echo 'data: ' . wp_json_encode( $done_payload ) . "\n\n";
		flush();
		exit;
	}

	
	private function sanitize_attachments( $attachments ) {
		$clean         = array();
		$max_count     = 4;
		$max_data_len  = 6 * 1024 * 1024;

		foreach ( $attachments as $att ) {
			if ( count( $clean ) >= $max_count ) {
				break;
			}
			if ( ! is_array( $att ) || empty( $att['data'] ) || ! is_string( $att['data'] ) ) {
				continue;
			}

			$data = $att['data'];

			if ( ! preg_match( '#^data:(image|video|audio|application|text)/[a-zA-Z0-9.+-]+;base64,[A-Za-z0-9+/=]+$#', $data ) ) {
				continue;
			}
			if ( strlen( $data ) > $max_data_len ) {
				continue;
			}

			$clean[] = array(
				'name' => isset( $att['name'] ) ? sanitize_file_name( $att['name'] ) : 'file',
				'type' => isset( $att['type'] ) ? sanitize_text_field( $att['type'] ) : 'application/octet-stream',
				'size' => isset( $att['size'] ) ? (int) $att['size'] : 0,
				'data' => $data,
			);
		}

		return $clean;
	}

	private function is_text_attachment( $att ) {
		$mime = strtolower( isset( $att['type'] ) ? $att['type'] : '' );
		$name = strtolower( isset( $att['name'] ) ? $att['name'] : '' );
		$ext  = pathinfo( $name, PATHINFO_EXTENSION );

		if ( strpos( $mime, 'text/' ) === 0 ) {
			return true;
		}

		$text_app_mimes = array(
			'application/json', 'application/javascript', 'application/ecmascript',
			'application/xml', 'application/xhtml+xml', 'application/x-yaml',
			'application/x-sh', 'application/x-httpd-php', 'application/x-php',
			'application/sql', 'application/graphql', 'application/ld+json',
		);
		if ( in_array( $mime, $text_app_mimes, true ) ) {
			return true;
		}

		$text_exts = array(
			'php', 'php3', 'php4', 'php5', 'phtml',
			'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx',
			'py', 'rb', 'java', 'kt', 'go', 'rs', 'swift',
			'c', 'cpp', 'cc', 'cxx', 'h', 'hpp',
			'cs', 'vb', 'fs', 'scala', 'clj', 'ex', 'exs',
			'sh', 'bash', 'zsh', 'fish',
			'sql', 'graphql', 'gql',
			'html', 'htm', 'xhtml',
			'xml', 'svg', 'xsl', 'xslt',
			'css', 'scss', 'sass', 'less',
			'json', 'jsonc', 'json5',
			'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf', 'env',
			'md', 'mdx', 'rst', 'txt', 'log', 'csv', 'tsv',
			'dockerfile', 'makefile',
		);
		return in_array( $ext, $text_exts, true );
	}

	private function decode_text_attachment( $data_url, $max_bytes = 204800 ) {
		$comma = strpos( $data_url, ',' );
		if ( $comma === false ) {
			return null;
		}
		$b64     = substr( $data_url, $comma + 1 );
		$decoded = base64_decode( $b64, true );
		if ( $decoded === false ) {
			return null;
		}
		if ( strpos( $decoded, "\x00" ) !== false ) {
			return null;
		}
		if ( strlen( $decoded ) > $max_bytes ) {
			$decoded = substr( $decoded, 0, $max_bytes )
				. "\n\n[... file truncated at " . number_format( $max_bytes / 1024 ) . " KB ...]";
		}
		return $decoded;
	}

	/**
	 * Builds the API-ready `content` value (plain string, or a multimodal
	 * content-parts array when images are attached) for one chat turn.
	 * Takes text/attachments directly — the client sends them already
	 * structured, since nothing is stored as a JSON blob server-side
	 * anymore.
	 */
	private function build_message_content( $text, $attachments, $allow_images = true ) {
		$text        = (string) $text;
		$attachments = is_array( $attachments ) ? $attachments : array();

		if ( empty( $attachments ) ) {
			return ( $text !== '' ) ? $text : '(no message text)';
		}

		$image_atts  = array();
		$text_atts   = array();
		$binary_atts = array();

		foreach ( $attachments as $att ) {
			$mime = isset( $att['type'] ) ? $att['type'] : '';
			if ( strpos( $mime, 'image/' ) === 0 && ! empty( $att['data'] ) ) {
				if ( $allow_images ) {
					$image_atts[] = $att;
				} else {
					// This model doesn't accept image content parts — fall
					// back to a text note instead of sending image_url and
					// triggering a 400 from the upstream API.
					$binary_atts[] = $att;
				}
			} elseif ( $this->is_text_attachment( $att ) && ! empty( $att['data'] ) ) {
				$text_atts[] = $att;
			} else {
				$binary_atts[] = $att;
			}
		}

		$text_block = $text;

		foreach ( $text_atts as $att ) {
			$file_content = $this->decode_text_attachment( $att['data'] );
			$filename     = isset( $att['name'] ) ? $att['name'] : 'file';
			if ( $file_content !== null ) {
				$text_block .= "\n\n--- File: " . $filename . " ---\n" . $file_content . "\n--- End of " . $filename . " ---";
			} else {
				$text_block .= "\n\n[Could not decode file: " . $filename . "]";
			}
		}

		if ( ! empty( $binary_atts ) ) {
			$names       = array_map( function( $a ) { return isset( $a['name'] ) ? $a['name'] : 'file'; }, $binary_atts );
			$text_block .= "\n\n[User also attached binary file(s): " . implode( ', ', $names ) . "]";
		}

		$text_block = trim( $text_block );

		if ( empty( $image_atts ) ) {
			return ( $text_block !== '' ) ? $text_block : '(attachment only)';
		}

		$content_parts = array();

		if ( $text_block !== '' ) {
			$content_parts[] = array( 'type' => 'text', 'text' => $text_block );
		}

		foreach ( $image_atts as $img ) {
			$content_parts[] = array(
				'type'      => 'image_url',
				'image_url' => array( 'url' => $img['data'] ),
			);
		}

		if ( empty( array_filter( $content_parts, function( $p ) { return $p['type'] === 'text'; } ) ) ) {
			array_unshift( $content_parts, array( 'type' => 'text', 'text' => 'Please describe what you see in the image(s).' ) );
		}

		return $content_parts;
	}


	private function call_chat_api( $messages, $model, $api_key, $api_url ) {
		$body = array(
			'model'    => $model,
			'messages' => $messages,
			'stream'   => false,
		);

		$response = wp_remote_post(
			$api_url,
			array(
				'timeout' => 90,
				'headers' => array(
					'Content-Type'  => 'application/json',
					'Authorization' => 'Bearer ' . $api_key,
				),
				'body' => wp_json_encode( $body ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'api_error', 'Could not reach the AI API: ' . $response->get_error_message(), array( 'status' => 500 ) );
		}

		$code          = wp_remote_retrieve_response_code( $response );
		$response_body = wp_remote_retrieve_body( $response );
		$data          = json_decode( $response_body, true );

		if ( $code < 200 || $code >= 300 ) {
			$err_msg = isset( $data['error']['message'] ) ? $data['error']['message'] : 'Unknown API error (HTTP ' . $code . ').';
			return new WP_Error( 'api_error', $err_msg, array( 'status' => 500 ) );
		}

		if ( ! isset( $data['choices'][0]['message']['content'] ) ) {
			return new WP_Error( 'api_error', 'Unexpected response format from the AI API.', array( 'status' => 500 ) );
		}

		return array(
			'text'  => $data['choices'][0]['message']['content'],
			'usage' => isset( $data['usage'] ) ? $data['usage'] : array(),
		);
	}


	public function render_twitter_card_meta() {
		if ( ! is_singular() ) {
			return;
		}

		$post = get_queried_object();
		if ( ! ( $post instanceof WP_Post ) || ! has_shortcode( $post->post_content, 'mlp_ai_chat' ) ) {
			return;
		}

		$title = get_the_title( $post );
		if ( '' === $title ) {
			$title = get_bloginfo( 'name' );
		}

		$description = get_the_excerpt( $post );
		if ( '' === $description ) {
			$description = wp_trim_words( wp_strip_all_tags( $post->post_content ), 30 );
		}
		if ( '' === trim( $description ) ) {
			$description = get_bloginfo( 'description' );
		}

		?>
		<meta name="twitter:card" content="summary_large_image">
		<meta name="twitter:title" content="<?php echo esc_attr( $title ); ?>">
		<meta name="twitter:description" content="<?php echo esc_attr( $description ); ?>">
		<?php
	}

	public function render_shortcode( $atts ) {
		$rest_url   = esc_url_raw( rest_url( 'mlp/v1' ) );
		$nonce      = wp_create_nonce( 'wp_rest' );
		$user_id    = get_current_user_id();
		$can_manage = current_user_can( 'manage_options' );

		// Build JS-safe model list from PHP config.
		$models_raw = unserialize( MLP_AI_CHAT_MODELS );
		$js_models  = array();
		foreach ( $models_raw as $id => $cfg ) {
			$js_models[] = array(
				'id'              => $id,
				'label'           => $cfg['label'],
				'supports_images' => ! isset( $cfg['supports_images'] ) || (bool) $cfg['supports_images'],
				'logo'            => ! empty( $cfg['logo'] ) ? $cfg['logo'] : '',
			);
		}

		ob_start();
		?>
		<div id="chat-ai-chat-fullpage" class="chat-ai-chat-fullpage">
			<div id="chat-username-modal" class="chat-username-modal" data-hidden="1">
				<div class="chat-username-modal-box">
					<img class="chat-username-modal-logo" src="https://ptero.pro/wp-content/uploads/2026/07/cropped-cropped-logo.png" alt="Logo">
					<h2>Welcome</h2>
					<p>Pick a name to use the AI chat. It's saved on this device so your conversations are here next time.</p>
					<input type="text" id="chat-username-input" class="chat-username-input" maxlength="30" placeholder="Your name" autocomplete="off">
					<div id="chat-username-error" class="chat-username-error"></div>
					<button id="chat-username-submit" class="chat-username-submit" type="button">Start Chatting</button>
				</div>
			</div>
			<div id="chat-new-models-modal" class="chat-new-models-modal" data-hidden="1">
				<div class="chat-new-models-box">
					<button id="chat-new-models-close" class="chat-new-models-close" type="button" aria-label="Close">&times;</button>
					<h2>New Models</h2>
					<p>Start a fresh chat with one of the latest AI models.</p>
					<div class="chat-new-models-list">
						<?php foreach ( $models_raw as $model_id => $model_cfg ) : ?>
							<?php if ( isset( $model_cfg['provider'] ) && 'xkiro' === $model_cfg['provider'] ) : ?>
							<div class="chat-new-models-item">
								<?php if ( ! empty( $model_cfg['logo'] ) ) : ?>
								<img class="chat-new-models-item-logo" src="<?php echo esc_url( $model_cfg['logo'] ); ?>" alt="<?php echo esc_attr( $model_cfg['label'] ); ?>">
								<?php endif; ?>
								<div class="chat-new-models-item-label"><?php echo esc_html( $model_cfg['label'] ); ?></div>
								<button class="chat-new-models-start-btn" type="button" data-model-id="<?php echo esc_attr( $model_id ); ?>">Start Chat</button>
							</div>
							<?php endif; ?>
						<?php endforeach; ?>
					</div>
					<p class="chat-new-models-footnote">ptero.pro is a non-profit — these new models will always be free. Powered by <a href="https://pterocos.eu.org" target="_blank" rel="noopener noreferrer">pterocos.eu.org</a>.</p>
				</div>
			</div>
			<div id="chat-ai-chat-app" class="chat-ai-chat-app">
				<div id="chat-sidebar-backdrop" class="chat-sidebar-backdrop"></div>
				<div class="chat-sidebar" id="chat-sidebar">
					<div class="chat-sidebar-logo">
						<img src="https://ptero.pro/wp-content/uploads/2026/08/cropped-Pterocos-2.png" alt="Logo">
					</div>
					<button id="chat-new-models-btn" class="chat-new-models-btn" type="button">✨ New Models</button>
					<button id="chat-new-chat-btn" class="chat-new-chat-btn">+ New Chat</button>
					<div class="chat-conv-search-wrap">
						<svg class="chat-conv-search-icon" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
						<input type="text" id="chat-conv-search" class="chat-conv-search" placeholder="Search chats..." autocomplete="off">
						<button type="button" id="chat-conv-search-clear" class="chat-conv-search-clear" title="Clear search" hidden>&times;</button>
					</div>
					<div id="chat-conversation-list" class="chat-conversation-list"></div>
					<?php if ( $can_manage ) : ?>
					<div class="chat-sidebar-divider"></div>
					<button id="chat-admin-room-btn" class="chat-room-btn" type="button">
						<span class="chat-room-btn-icon" aria-hidden="true">&#9881;</span> Administration
					</button>
					<?php endif; ?>
					<p class="chat-sidebar-disclaimer">Ptero.pro is completely free to use and will always be free — we will not add premium plans. Powered by <a href="https://pterocos.eu.org" target="_blank" rel="noopener noreferrer">pterocos.eu.org</a>.</p>
				</div>
				<div class="chat-main" id="chat-chat-view">
					<div id="chat-disabled-banner" class="chat-disabled-banner">The AI chat has been temporarily disabled by the site administrator.</div>
					<div class="chat-chat-header">
						<div class="chat-header-left">
							<button id="chat-menu-btn" class="chat-menu-btn" type="button" aria-label="Open menu" aria-controls="chat-sidebar" aria-expanded="false">
								<span></span><span></span><span></span>
							</button>
							<span id="chat-current-title">New Chat</span>
						</div>
						<div class="chat-header-right">
							<div class="chat-model-picker" id="chat-model-picker">
								<button type="button" class="chat-model-picker-trigger" id="chat-model-picker-trigger" title="Choose AI model" aria-haspopup="listbox" aria-expanded="false">
									<span class="chat-model-picker-trigger-icon" id="chat-model-picker-trigger-icon"></span>
									<span class="chat-model-picker-trigger-label" id="chat-model-picker-trigger-label">Choose model</span>
									<svg class="chat-model-picker-chevron" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"></polyline></svg>
								</button>
								<div class="chat-model-picker-panel" id="chat-model-picker-panel" role="listbox" tabindex="-1" hidden>
									<div class="chat-model-picker-panel-title">Select a model</div>
									<?php
									foreach ( $models_raw as $model_id => $model_cfg ) :
										$mlp_logo        = ! empty( $model_cfg['logo'] ) ? $model_cfg['logo'] : '';
										$mlp_is_paid     = ! empty( $model_cfg['is_paid'] );
										$mlp_clean_label = trim( preg_replace( '/\s*\(free\)\s*$/i', '', $model_cfg['label'] ) );
									?>
									<div class="chat-model-picker-option" role="option" aria-selected="false" data-model-id="<?php echo esc_attr( $model_id ); ?>" data-label="<?php echo esc_attr( $mlp_clean_label ); ?>" tabindex="-1">
										<span class="chat-model-picker-option-icon">
											<?php if ( $mlp_logo ) : ?>
											<img src="<?php echo esc_url( $mlp_logo ); ?>" alt="" loading="lazy">
											<?php else : ?>
											<span class="chat-model-picker-option-icon-fallback"><?php echo esc_html( strtoupper( substr( $mlp_clean_label, 0, 1 ) ) ); ?></span>
											<?php endif; ?>
										</span>
										<span class="chat-model-picker-option-text">
											<span class="chat-model-picker-option-label"><?php echo esc_html( $mlp_clean_label ); ?></span>
										</span>
										<?php if ( ! $mlp_is_paid ) : ?>
										<span class="chat-model-picker-option-badge">Free</span>
										<?php endif; ?>
										<svg class="chat-model-picker-option-check" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"></polyline></svg>
									</div>
									<?php endforeach; ?>
								</div>
								<select id="chat-model-select" class="chat-model-select-native" title="Choose AI model" aria-hidden="true" tabindex="-1">
									<?php foreach ( $models_raw as $model_id => $model_cfg ) :
										$mlp_native_label = trim( preg_replace( '/\s*\(free\)\s*$/i', '', $model_cfg['label'] ) );
									?>
										<option value="<?php echo esc_attr( $model_id ); ?>" data-logo="<?php echo esc_attr( ! empty( $model_cfg['logo'] ) ? $model_cfg['logo'] : '' ); ?>" data-label="<?php echo esc_attr( $mlp_native_label ); ?>"><?php echo esc_html( $mlp_native_label ); ?></option>
									<?php endforeach; ?>
								</select>
							</div>
						</div>
					</div>
					<div id="chat-messages" class="chat-messages">
						<div class="chat-empty-state">
							<h2>AI Chat</h2>
							<p>Start a conversation below.</p>
						</div>
					</div>
					<div class="chat-input-wrap">
						<div id="chat-attach-preview" class="chat-attach-preview"></div>
						<div id="chat-input-area" class="chat-input-area">
							<div class="chat-attach-wrap">
								<button id="chat-attach-btn" class="chat-attach-btn" title="Attach" type="button" aria-haspopup="true" aria-expanded="false">
									<span class="chat-icon-plus" aria-hidden="true"></span>
								</button>
								<div id="chat-attach-menu" class="chat-attach-menu" hidden>
									<button type="button" class="chat-attach-menu-item" id="chat-attach-menu-image">
										<span class="chat-attach-menu-icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"></rect><circle cx="9" cy="9" r="2"></circle><path d="M21 15l-5-5L5 21"></path></svg></span>
										<span>Add image</span>
									</button>
									<button type="button" class="chat-attach-menu-item" id="chat-attach-menu-file">
										<span class="chat-attach-menu-icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></span>
										<span>Add file</span>
									</button>
								</div>
							</div>
							<input type="file" id="chat-image-input" class="chat-file-input" accept="image/*" multiple hidden>
							<input type="file" id="chat-file-input" class="chat-file-input" accept=".pdf,.doc,.docx,.txt,video/*,audio/*" multiple hidden>
							<textarea id="chat-input" class="chat-input" placeholder="Message the AI..." rows="1"></textarea>
							<button id="chat-send-btn" class="chat-send-btn" title="Send">
								<span class="chat-icon-send" aria-hidden="true"></span>
								<span class="chat-icon-stop" aria-hidden="true" style="display:none;"></span>
							</button>
						</div>
						<div id="chat-drop-hint" class="chat-drop-hint">
							<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
							<span>Drop files to attach</span>
						</div>
					</div>
				</div>
				<?php if ( $can_manage ) : ?>
				<div class="chat-main chat-admin-view" id="chat-admin-view" data-hidden="1">
					<div class="chat-admin-header">
						<div class="chat-header-left">
							<button id="chat-admin-menu-btn" class="chat-menu-btn" type="button" aria-label="Open menu" aria-controls="chat-sidebar" aria-expanded="false">
								<span></span><span></span><span></span>
							</button>
							<span>Administration</span>
						</div>
						<button id="chat-admin-refresh-btn" class="chat-admin-refresh-btn" type="button">Refresh</button>
					</div>
					<div class="chat-admin-body" id="chat-admin-body">
						<div class="chat-admin-stats" id="chat-admin-stats"></div>
						<div class="chat-admin-section">
							<div class="chat-admin-section-head">
								<h3>Global Controls</h3>
							</div>
							<p class="chat-admin-note">When disabled, no visitor can send messages to any model.</p>
							<button id="chat-admin-toggle-global-btn" class="chat-admin-toggle-btn" type="button">Disable AI Chat</button>
						</div>
						<div class="chat-admin-section">
							<div class="chat-admin-section-head">
								<h3>Models</h3>
							</div>
							<div id="chat-admin-models" class="chat-admin-models"></div>
						</div>
					</div>
				</div>
				<?php endif; ?>
				<!-- Code Editor Sidebar (Monaco) -->
				<div id="chat-code-sidebar" class="chat-code-sidebar" data-hidden="1">
					<div class="chat-code-sidebar-header">
						<div class="chat-code-sidebar-title-wrap">
							<span id="chat-code-sidebar-icon" class="chat-code-sidebar-icon">&#128196;</span>
							<span id="chat-code-sidebar-title">Code Editor</span>
						</div>
						<button id="chat-code-sidebar-close" class="chat-code-sidebar-close" type="button" title="Close">&times;</button>
					</div>
					<div id="chat-code-sidebar-editor" class="chat-code-sidebar-editor"></div>
					<div class="chat-code-sidebar-footer">
						<button id="chat-code-sidebar-download" class="chat-code-sidebar-download" type="button">
							<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
							Download File
						</button>
					</div>
				</div>
			</div>
		</div>

		<style>
			html.chat-fullpage-active,
			html.chat-fullpage-active body {
				overflow: hidden !important;
				height: 100% !important;
			}
			[data-mlp-hidden="1"] { display: none !important; }
			.chat-ai-chat-fullpage {
				position: fixed;
				top: 0; left: 0; right: 0; bottom: 0;
				width: 100vw; height: 100vh;
				height: 100dvh; /* accounts for mobile browser address/toolbar chrome */
				z-index: 2147483000;
				background: #ffffff;
				margin: 0; padding: 0;
			}
			.chat-ai-chat-app {
				display: flex;
				width: 100%; height: 100%;
				border: none; border-radius: 0;
				overflow: hidden;
				font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
				background: #ffffff;
			}
			.chat-sidebar {
				width: 260px; min-width: 260px;
				background: #202123; color: #ececf1;
				display: flex; flex-direction: column;
				padding: 10px; box-sizing: border-box;
			}
			.chat-sidebar-logo {
				display: flex; align-items: center; justify-content: center;
				padding: 6px 0 14px 0;
			}
			.chat-sidebar-logo img {
				max-width: 140px; max-height: 48px; width: auto; height: auto;
				object-fit: contain;
			}
			.chat-username-modal {
				position: absolute; inset: 0; z-index: 10;
				display: flex; align-items: center; justify-content: center;
				background: rgba(32,33,35,0.72);
				font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
			}
			.chat-username-modal[data-hidden="1"] { display: none; }
			.chat-username-modal-box {
				background: #ffffff; border-radius: 12px; padding: 32px 28px;
				width: 340px; max-width: 90vw; box-sizing: border-box;
				text-align: center; box-shadow: 0 12px 40px rgba(0,0,0,0.25);
			}
			.chat-username-modal-logo { max-width: 120px; max-height: 42px; object-fit: contain; margin-bottom: 14px; }
			.chat-username-modal-box h2 { margin: 0 0 8px 0; font-size: 20px; color: #202123; }
			.chat-username-modal-box p { margin: 0 0 18px 0; font-size: 13px; color: #6e6e80; line-height: 1.4; }
			.chat-username-input {
				width: 100%; box-sizing: border-box; padding: 10px 12px;
				border: 1px solid #d9d9e3; border-radius: 8px; font-size: 14px; margin-bottom: 6px;
			}
			.chat-username-input:focus { outline: none; border-color: #10a37f; }
			.chat-username-error { color: #d63638; font-size: 12px; min-height: 16px; margin-bottom: 10px; text-align: left; }
			.chat-username-submit {
				width: 100%; background: #10a37f; color: #fff; border: none;
				padding: 11px 12px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer;
			}
			.chat-username-submit:hover { background: #0d8f6e; }
			.chat-new-models-btn {
				display: block; width: 100%; box-sizing: border-box;
				margin: 0 0 8px 0; padding: 10px 12px;
				background: linear-gradient(135deg, #10a37f, #0d8f6e);
				color: #fff; border: none; border-radius: 8px;
				font-size: 14px; font-weight: 600; cursor: pointer; text-align: left;
			}
			.chat-new-models-btn:hover { filter: brightness(1.08); }
			.chat-new-models-modal {
				position: absolute; inset: 0; z-index: 11;
				display: flex; align-items: center; justify-content: center;
				background: rgba(32,33,35,0.72);
				font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
			}
			.chat-new-models-modal[data-hidden="1"] { display: none; }
			.chat-new-models-box {
				position: relative;
				background: #ffffff; border-radius: 12px; padding: 32px 28px;
				width: 380px; max-width: 90vw; box-sizing: border-box;
				text-align: center; box-shadow: 0 12px 40px rgba(0,0,0,0.25);
			}
			.chat-new-models-box h2 { margin: 0 0 8px 0; font-size: 20px; color: #202123; }
			.chat-new-models-box p { margin: 0 0 18px 0; font-size: 13px; color: #6e6e80; line-height: 1.4; }
			.chat-new-models-close {
				position: absolute; top: 10px; right: 12px;
				background: none; border: none; font-size: 22px; line-height: 1;
				color: #8e8ea0; cursor: pointer; padding: 4px;
			}
			.chat-new-models-close:hover { color: #202123; }
			.chat-new-models-list { display: flex; flex-direction: column; gap: 10px; }
			.chat-new-models-item {
				display: flex; align-items: center; justify-content: space-between; gap: 12px;
				border: 1px solid #e5e5ea; border-radius: 8px; padding: 12px 14px;
				text-align: left;
			}
			.chat-new-models-item-label { font-size: 13px; font-weight: 600; color: #202123; flex: 1 1 auto; }
			.chat-new-models-item-logo {
				flex-shrink: 0; width: 28px; height: 28px; object-fit: contain; border-radius: 6px;
			}
			.chat-new-models-footnote {
				margin: 18px 0 0 0 !important; font-size: 12px; color: #8e8ea0; line-height: 1.4;
			}
			.chat-new-models-footnote a { color: #10a37f; text-decoration: none; }
			.chat-new-models-footnote a:hover { text-decoration: underline; }
			.chat-new-models-start-btn {
				flex-shrink: 0; background: #10a37f; color: #fff; border: none;
				padding: 8px 14px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer;
			}
			.chat-new-models-start-btn:hover { background: #0d8f6e; }
			.chat-disabled-banner {
				display: none; background: #fff3cd; color: #7a5b00; font-size: 13px;
				padding: 8px 16px; text-align: center; border-bottom: 1px solid #ffe08a;
			}
			.chat-disabled-banner[data-show="1"] { display: block; }
			.chat-new-chat-btn {
				background: transparent;
				border: 1px solid #565869; color: #ececf1;
				padding: 10px 12px; border-radius: 6px;
				cursor: pointer; text-align: left; font-size: 14px; margin-bottom: 10px;
			}
			.chat-new-chat-btn:hover { background: #2b2c2f; }
			.chat-conv-search-wrap {
				position: relative; display: flex; align-items: center;
				margin-bottom: 10px; flex-shrink: 0;
			}
			.chat-conv-search-icon {
				position: absolute; left: 9px; color: #8e8ea0; pointer-events: none; flex-shrink: 0;
			}
			.chat-sidebar .chat-conv-search,
			.chat-conv-search {
				width: 100%; background: #202123 !important; border: 1px solid #565869; color: #ececf1 !important;
				border-radius: 6px; padding: 8px 28px 8px 30px; font-size: 13px; font-family: inherit;
				outline: none; box-sizing: border-box; -webkit-text-fill-color: #ececf1;
			}
			.chat-conv-search::placeholder,
			.chat-conv-search::-webkit-input-placeholder { color: #8e8ea0 !important; opacity: 1; }
			.chat-conv-search:-webkit-autofill,
			.chat-conv-search:-webkit-autofill:hover,
			.chat-conv-search:-webkit-autofill:focus {
				-webkit-text-fill-color: #ececf1 !important;
				-webkit-box-shadow: 0 0 0px 1000px #202123 inset !important;
				box-shadow: 0 0 0px 1000px #202123 inset !important;
				caret-color: #ececf1;
			}
			.chat-conv-search:focus { border-color: #10a37f; }
			.chat-conv-search-clear {
				position: absolute; right: 6px; background: none; border: none; color: #8e8ea0;
				cursor: pointer; font-size: 15px; line-height: 1; padding: 4px 5px; border-radius: 4px;
			}
			.chat-conv-search-clear:hover { color: #ececf1; background: #2b2c2f; }
			.chat-conv-empty-search { padding: 12px 10px; font-size: 12.5px; color: #8e8ea0; text-align: center; }
			.chat-conversation-list { flex: 1; overflow-y: auto; }
			.chat-conv-item {
				padding: 10px; border-radius: 6px; cursor: pointer;
				font-size: 13px; white-space: nowrap; overflow: hidden;
				text-overflow: ellipsis; margin-bottom: 4px;
				display: flex; justify-content: space-between; align-items: center; gap: 6px;
			}
			.chat-conv-item:hover { background: #2b2c2f; }
			.chat-conv-item.active { background: #343541; }
			.chat-conv-title { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
			.chat-conv-delete { opacity: 0; background: none; border: none; color: #ececf1; cursor: pointer; font-size: 13px; }
			.chat-conv-item:hover .chat-conv-delete { opacity: 0.7; }
			.chat-conv-delete:hover { opacity: 1 !important; color: #ff6b6b; }

			/* ── Mobile sidebar drawer (hamburger + backdrop) ────────────── */
			/* Inert on desktop; activated inside the max-width:768px query below. */
			.chat-menu-btn {
				display: none;
				flex-direction: column; align-items: center; justify-content: center;
				gap: 4px; width: 36px; height: 36px; padding: 0;
				border: none; background: transparent; border-radius: 6px;
				cursor: pointer; flex-shrink: 0; -webkit-tap-highlight-color: transparent;
			}
			.chat-menu-btn span { display: block; width: 18px; height: 2px; background: #333; border-radius: 2px; }
			.chat-menu-btn:hover { background: rgba(0,0,0,0.06); }
			.chat-header-left { display: flex; align-items: center; gap: 8px; min-width: 0; }
			.chat-sidebar-backdrop {
				display: none;
				position: fixed; inset: 0; background: rgba(0,0,0,0.45);
				z-index: 199; opacity: 0; transition: opacity 0.2s ease;
			}
			.chat-sidebar-backdrop.open { display: block; opacity: 1; }

			.chat-main { flex: 1; display: flex; flex-direction: column; background: #ffffff; min-width: 0; }
			.chat-chat-header {
				padding: 12px 18px; border-bottom: 1px solid #eee;
				font-weight: 600; display: flex; justify-content: space-between;
				align-items: center; font-size: 14px; color: #333; gap: 10px;
			}
			#chat-current-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
			.chat-header-right { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }

			/* The real <select> stays in the DOM (fully functional — value,
			   options, disabled state, change events) but is visually
			   replaced by the .chat-model-picker widget below. */
			.chat-model-select-native {
				position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
				overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
			}

			.chat-model-picker { position: relative; }
			.chat-model-picker-trigger {
				display: flex; align-items: center; gap: 7px;
				font-size: 12.5px; font-family: inherit; font-weight: 500;
				background: #f7f7f8; border: 1px solid #e2e2e5;
				border-radius: 999px; padding: 4px 12px 4px 6px;
				color: #383941; cursor: pointer; outline: none;
				transition: background 0.15s, border-color 0.15s, box-shadow 0.15s;
				max-width: 220px;
			}
			.chat-model-picker-trigger:hover { background: #eeeef0; border-color: #d3d3d8; }
			.chat-model-picker-trigger:focus-visible { border-color: #10a37f; box-shadow: 0 0 0 3px rgba(16,163,127,0.15); }
			.chat-model-picker-trigger[aria-expanded="true"] { background: #eeeef0; border-color: #10a37f; box-shadow: 0 0 0 3px rgba(16,163,127,0.15); }
			.chat-model-picker-trigger:disabled { opacity: 0.55; cursor: not-allowed; }
			.chat-model-picker-trigger-icon {
				width: 22px; height: 22px; border-radius: 50%; flex-shrink: 0;
				display: flex; align-items: center; justify-content: center;
				background: #fff; border: 1px solid #e5e5e8; overflow: hidden;
			}
			.chat-model-picker-trigger-icon img { width: 100%; height: 100%; object-fit: cover; display: block; }
			.chat-model-picker-trigger-icon .chat-model-picker-option-icon-fallback { font-size: 10px; }
			.chat-model-picker-trigger-label {
				overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0;
			}
			.chat-model-picker-chevron { flex-shrink: 0; color: #8a8a94; transition: transform 0.15s; }
			.chat-model-picker-trigger[aria-expanded="true"] .chat-model-picker-chevron { transform: rotate(180deg); color: #10a37f; }

			.chat-model-picker-panel {
				position: absolute; top: calc(100% + 8px); right: 0; z-index: 60;
				width: 280px; max-height: 340px; overflow-y: auto;
				background: #fff; border: 1px solid #e5e5e8; border-radius: 14px;
				box-shadow: 0 12px 32px rgba(20,20,30,0.14), 0 2px 8px rgba(20,20,30,0.06);
				padding: 6px; animation: chatModelPanelIn 0.14s ease-out;
			}
			@keyframes chatModelPanelIn {
				from { opacity: 0; transform: translateY(-4px) scale(0.98); }
				to   { opacity: 1; transform: translateY(0) scale(1); }
			}
			.chat-model-picker-panel[hidden] { display: none; }
			.chat-model-picker-panel-title {
				font-size: 11px; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase;
				color: #9a9aa4; padding: 8px 10px 6px;
			}
			.chat-model-picker-option {
				display: flex; align-items: center; gap: 10px;
				padding: 8px 10px; border-radius: 10px; cursor: pointer;
				transition: background 0.12s;
			}
			.chat-model-picker-option:hover,
			.chat-model-picker-option.is-active { background: #f2f7f5; }
			.chat-model-picker-option[aria-disabled="true"] { opacity: 0.45; cursor: not-allowed; }
			.chat-model-picker-option[aria-disabled="true"]:hover { background: transparent; }
			.chat-model-picker-option-icon {
				width: 32px; height: 32px; border-radius: 50%; flex-shrink: 0;
				display: flex; align-items: center; justify-content: center;
				background: #fff; border: 1px solid #ececef; overflow: hidden;
			}
			.chat-model-picker-option-icon img { width: 100%; height: 100%; object-fit: cover; display: block; }
			.chat-model-picker-option-icon-fallback {
				font-size: 13px; font-weight: 700; color: #10a37f;
			}
			.chat-model-picker-option-text { display: flex; flex-direction: column; min-width: 0; flex: 1 1 auto; }
			.chat-model-picker-option-label {
				font-size: 13.5px; font-weight: 600; color: #202123;
				overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
			}
			.chat-model-picker-option-badge {
				flex-shrink: 0; font-size: 10px; font-weight: 700; letter-spacing: 0.02em;
				color: #10a37f; background: rgba(16,163,127,0.12);
				border-radius: 999px; padding: 2px 8px; text-transform: uppercase;
			}
			.chat-model-picker-option-check { flex-shrink: 0; color: #10a37f; opacity: 0; }
			.chat-model-picker-option[aria-selected="true"] .chat-model-picker-option-check { opacity: 1; }
			.chat-model-picker-option[aria-selected="true"] .chat-model-picker-option-label { color: #10a37f; }

			.chat-messages { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 16px; }
			.chat-empty-state { margin: auto; text-align: center; color: #999; }
			.chat-msg {
				max-width: 85%;
				display: flex;
				align-items: flex-start;
				gap: 10px;
				padding: 0;
				background: transparent;
				border-radius: 0;
				font-size: 14px;
				line-height: 1.5;
			}
			.chat-msg.user { align-self: flex-end; flex-direction: row-reverse; }
			.chat-msg.assistant { align-self: flex-start; }
			.chat-msg.typing { align-self: flex-start; }

			.chat-msg-avatar {
				width: 32px; height: 32px;
				border-radius: 50%;
				object-fit: cover;
				flex-shrink: 0;
				margin-top: 4px;
				animation: mlpAvatarFloat 3s ease-in-out infinite, mlpAvatarGlow 2.5s ease-in-out infinite;
			}
			.chat-msg-avatar-wrap {
				display: flex; flex-direction: column; align-items: center;
				flex-shrink: 0; gap: 2px;
			}
			.chat-msg-avatar-name {
				font-size: 10px; font-weight: 600; color: #6e6e80;
				max-width: 62px; text-align: center; line-height: 1.2;
				white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
			}
			.chat-msg-avatar-tooltip {
				position: absolute;
				z-index: 9999;
				background: #1a1a1a;
				color: #fff;
				font-size: 12px;
				font-weight: 500;
				padding: 6px 10px;
				border-radius: 6px;
				box-shadow: 0 4px 14px rgba(0,0,0,0.25);
				white-space: nowrap;
				pointer-events: none;
				animation: mlpTooltipIn 0.12s ease-out;
			}
			@keyframes mlpTooltipIn {
				from { opacity: 0; transform: translateY(-4px); }
				to   { opacity: 1; transform: translateY(0); }
			}
			@keyframes mlpAvatarFloat {
				0%, 100% { transform: translateY(0); }
				50% { transform: translateY(-4px); }
			}
			@keyframes mlpAvatarGlow {
				0%, 100% { box-shadow: 0 0 0 0 rgba(16, 163, 127, 0.35); }
				50% { box-shadow: 0 0 12px 4px rgba(16, 163, 127, 0.15); }
			}

			.chat-msg-content {
				padding: 10px 14px;
				border-radius: 12px;
				white-space: normal;
				word-wrap: break-word;
				min-width: 0;
			}
			.chat-msg.user .chat-msg-content {
				background: #10a37f;
				color: #fff;
				border-bottom-right-radius: 2px;
			}
			.chat-msg.assistant .chat-msg-content {
				background: #f2f2f2;
				color: #222;
				border-bottom-left-radius: 2px;
			}
			.chat-msg.typing .chat-msg-content {
				background: #f2f2f2;
				color: #999;
				border-bottom-left-radius: 2px;
				padding: 12px 16px;
			}

			/* ── Message feedback (like/dislike) ─────────────────────────── */
			.chat-feedback-bar {
				display: flex; align-items: center; gap: 4px;
				margin-top: 8px;
			}
			.chat-feedback-btn {
				display: flex; align-items: center; justify-content: center;
				width: 26px; height: 26px; padding: 0;
				background: transparent; border: none; border-radius: 6px;
				color: #8e8ea0; cursor: pointer;
				transition: background 0.12s, color 0.12s, transform 0.08s;
			}
			.chat-feedback-btn:hover { background: rgba(0,0,0,0.06); color: #444; }
			.chat-feedback-btn:active { transform: scale(0.9); }
			.chat-feedback-btn.like.active { color: #00a32a; background: rgba(0,163,42,0.12); }
			.chat-feedback-btn.dislike.active { color: #d63638; background: rgba(214,54,56,0.12); }
			.chat-feedback-btn svg { display: block; }

			/* ── Code Blocks with Copy Button ───────────────────────────── */
			.chat-code-block {
				margin: 8px 0;
				border-radius: 10px;
				overflow: hidden;
				background: #1e1e2e;
				border: 1px solid #2d2d3d;
				max-width: 100%;
			}
			.chat-code-block-header {
				display: flex;
				align-items: center;
				justify-content: space-between;
				padding: 8px 14px;
				background: #252536;
				border-bottom: 1px solid #2d2d3d;
			}
			.chat-code-block-lang {
				font-size: 11px;
				font-weight: 600;
				color: #8b8b9a;
				text-transform: lowercase;
				font-family: "SFMono-Regular", Consolas, Menlo, monospace;
			}
			.chat-code-block-actions {
				display: flex;
				gap: 6px;
			}
			.chat-code-block-btn {
				background: rgba(255,255,255,0.06);
				border: 1px solid rgba(255,255,255,0.08);
				color: #a0a0b0;
				border-radius: 5px;
				padding: 4px 10px;
				font-size: 11px;
				cursor: pointer;
				transition: all 0.15s;
				display: flex;
				align-items: center;
				gap: 4px;
			}
			.chat-code-block-btn:hover {
				background: rgba(255,255,255,0.12);
				color: #fff;
			}
			.chat-code-block-btn.copied {
				background: rgba(16, 163, 127, 0.2);
				color: #10a37f;
				border-color: rgba(16, 163, 127, 0.3);
			}
			.chat-code-block-body {
				padding: 12px 16px;
				overflow-x: auto;
				max-height: 480px;
				overflow-y: auto;
			}
			.chat-code-block-body pre {
				margin: 0;
				padding: 0;
				background: transparent;
				font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
				font-size: 13px;
				line-height: 1.6;
				color: #d4d4d4;
				white-space: pre;
				word-wrap: normal;
			}
			.chat-code-block-body code {
				background: transparent;
				padding: 0;
				border-radius: 0;
				font-size: inherit;
				color: inherit;
			}

			/* ── File cards (large files -> Monaco sidebar) ───────────── */
			.chat-file-card {
				display: flex;
				align-items: center;
				justify-content: space-between;
				gap: 12px;
				background: #fff;
				border: 1px solid #e0e0e0;
				border-radius: 10px;
				padding: 10px 14px;
				max-width: 420px;
				transition: border-color 0.15s, box-shadow 0.15s;
			}
			.chat-file-card:hover {
				border-color: #10a37f;
				box-shadow: 0 2px 8px rgba(16, 163, 127, 0.08);
			}
			.chat-file-card-main {
				display: flex;
				align-items: center;
				gap: 10px;
				min-width: 0;
				flex: 1;
			}
			.chat-file-card-icon {
				width: 36px; height: 36px;
				border-radius: 8px;
				background: #eafaf4;
				color: #10a37f;
				display: flex;
				align-items: center;
				justify-content: center;
				flex-shrink: 0;
			}
			.chat-file-card-info {
				min-width: 0;
				flex: 1;
			}
			.chat-file-card-name {
				font-size: 13px;
				font-weight: 600;
				color: #222;
				overflow: hidden;
				text-overflow: ellipsis;
				white-space: nowrap;
			}
			.chat-file-card-meta {
				font-size: 11px;
				color: #888;
				margin-top: 1px;
			}
			.chat-file-card-btn {
				background: #10a37f;
				color: #fff;
				border: none;
				border-radius: 6px;
				padding: 6px 14px;
				font-size: 12px;
				font-weight: 600;
				cursor: pointer;
				flex-shrink: 0;
				transition: background 0.15s;
			}
			.chat-file-card-btn:hover { background: #0d8a6a; }
			.chat-artifact-card { margin: 8px 0; cursor: pointer; max-width: 380px; }
			.chat-artifact-card:focus-visible { outline: 2px solid #10a37f; outline-offset: 2px; }

			/* ── Monaco Code Sidebar ────────────────────────────────────── */
			.chat-code-sidebar {
				position: absolute;
				top: 0; right: 0;
				width: 55%; min-width: 420px; max-width: 720px;
				height: 100%;
				background: #1e1e2e;
				z-index: 100;
				display: flex; flex-direction: column;
				transform: translateX(100%);
				transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1);
				box-shadow: -8px 0 32px rgba(0,0,0,0.4);
				border-left: 1px solid #333;
			}
			.chat-code-sidebar[data-hidden="0"] { transform: translateX(0); }
			.chat-code-sidebar-header {
				display: flex;
				align-items: center;
				justify-content: space-between;
				padding: 12px 18px;
				background: #252536;
				border-bottom: 1px solid #333;
				flex-shrink: 0;
			}
			.chat-code-sidebar-title-wrap {
				display: flex;
				align-items: center;
				gap: 10px;
				min-width: 0;
			}
			.chat-code-sidebar-icon {
				font-size: 18px;
				line-height: 1;
			}
			.chat-code-sidebar-title {
				font-size: 14px;
				font-weight: 600;
				color: #ececf1;
				overflow: hidden;
				text-overflow: ellipsis;
				white-space: nowrap;
			}
			.chat-code-sidebar-close {
				background: none;
				border: none;
				color: #888;
				font-size: 22px;
				cursor: pointer;
				width: 32px; height: 32px;
				display: flex;
				align-items: center;
				justify-content: center;
				border-radius: 6px;
				transition: background 0.15s, color 0.15s;
			}
			.chat-code-sidebar-close:hover {
				background: rgba(255,255,255,0.08);
				color: #fff;
			}
			.chat-code-sidebar-editor {
				flex: 1;
				min-height: 0;
				overflow: hidden;
			}
			.chat-code-sidebar-footer {
				padding: 12px 18px;
				background: #252536;
				border-top: 1px solid #333;
				display: flex;
				justify-content: flex-end;
				flex-shrink: 0;
			}
			.chat-code-sidebar-download {
				display: flex;
				align-items: center;
				gap: 6px;
				background: #10a37f;
				color: #fff;
				border: none;
				border-radius: 8px;
				padding: 8px 16px;
				font-size: 13px;
				font-weight: 600;
				cursor: pointer;
				transition: background 0.15s;
			}
			.chat-code-sidebar-download:hover { background: #0d8a6a; }
			.chat-code-sidebar-download svg {
				width: 14px; height: 14px;
			}

			@media (max-width: 768px) {
				.chat-ai-chat-app { position: relative; overflow: hidden; }

				/* Sidebar becomes an off-canvas drawer instead of squeezing the chat. */
				.chat-menu-btn { display: flex; }
				.chat-sidebar {
					position: fixed; top: 0; left: 0; bottom: 0;
					width: 82%; max-width: 300px; min-width: 0;
					z-index: 200;
					transform: translateX(-100%);
					transition: transform 0.28s cubic-bezier(0.4, 0, 0.2, 1);
					box-shadow: 4px 0 24px rgba(0,0,0,0.35);
					padding-top: calc(10px + env(safe-area-inset-top));
					padding-bottom: calc(10px + env(safe-area-inset-bottom));
				}
				.chat-sidebar.open { transform: translateX(0); }

				.chat-chat-header, .chat-admin-header {
					padding: 10px 12px;
					padding-top: calc(10px + env(safe-area-inset-top));
				}
				#chat-current-title { max-width: 42vw; }
				.chat-model-picker-trigger {
					font-size: 11px; padding: 3px 10px 3px 5px; max-width: 40vw;
				}
				.chat-model-picker-trigger-icon { width: 20px; height: 20px; }
				.chat-model-picker-panel {
					position: fixed; top: auto; bottom: 0; left: 0; right: 0;
					width: auto; max-height: 60vh; border-radius: 16px 16px 0 0;
					padding-bottom: calc(6px + env(safe-area-inset-bottom));
				}

				.chat-messages { padding: 14px 12px; gap: 12px; }
				.chat-msg { max-width: 92%; }
				.chat-msg-avatar { width: 28px; height: 28px; }
				.chat-msg-content { padding: 9px 12px; font-size: 14.5px; }

				.chat-input-area { padding: 10px 12px; gap: 8px; }
				.chat-input-wrap { padding-bottom: env(safe-area-inset-bottom); }
				/* 16px prevents iOS Safari from auto-zooming the page on focus. */
				.chat-input { font-size: 16px; padding: 10px 12px; max-height: 120px; }
				.chat-send-btn, .chat-attach-btn { width: 40px; height: 40px; flex-shrink: 0; }
				.chat-attach-preview { padding: 0 12px; }

				/* No hover on touch devices, so keep delete/remove controls reachable. */
				.chat-conv-delete { opacity: 0.6; }
				.chat-attach-chip { max-width: 42vw; }

				.chat-admin-body { padding: 14px; }
				.chat-admin-stats { gap: 8px; }
				.chat-admin-stat-card { min-width: 44%; padding: 12px 14px; }
				.chat-admin-model-row { flex-wrap: wrap; }

				.chat-username-modal-box { width: 88vw; padding: 26px 20px; }

				.chat-code-sidebar {
					width: 100%;
					min-width: auto;
					max-width: none;
				}
			}

			@media (max-width: 420px) {
				.chat-admin-stat-card { min-width: 100%; }
				#chat-current-title { max-width: 34vw; }
			}

			.chat-input-wrap { position: relative; border-top: 1px solid #eee; }
			.chat-input-area { display: flex; align-items: flex-end; gap: 10px; padding: 14px 18px; }
			.chat-input {
				flex: 1; resize: none; border: 1px solid #ddd; border-radius: 8px;
				padding: 10px 12px; font-size: 14px; font-family: inherit; max-height: 140px; outline: none;
			}
			.chat-input:focus { border-color: #10a37f; }
			.chat-send-btn {
				display: flex; align-items: center; justify-content: center;
				background: #10a37f; color: #fff; border: none; border-radius: 8px;
				width: 40px; height: 40px; font-size: 16px; cursor: pointer; flex-shrink: 0;
			}
			.chat-send-btn:disabled { background: #a7d9c9; cursor: not-allowed; }
			.chat-send-btn:hover:not(:disabled) { background: #0d8a6a; }

			.chat-attach-btn {
				display: flex; align-items: center; justify-content: center;
				width: 40px; height: 40px; border-radius: 8px; border: 1px solid #ddd;
				background: #fff; color: #555; cursor: pointer; flex-shrink: 0;
				transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease, transform 0.1s ease;
			}
			.chat-attach-btn:hover { background: #eafaf4; border-color: #10a37f; color: #10a37f; }
			.chat-attach-btn:active { transform: scale(0.94); }
			.chat-attach-btn[aria-expanded="true"] { background: #eafaf4; border-color: #10a37f; color: #10a37f; }
			.chat-file-input { display: none; }

			.chat-attach-wrap { position: relative; flex-shrink: 0; }
			.chat-attach-menu {
				position: absolute; bottom: calc(100% + 8px); left: 0; z-index: 20;
				background: #fff; border: 1px solid #e5e5e5; border-radius: 10px;
				box-shadow: 0 6px 20px rgba(0,0,0,0.12); padding: 6px; min-width: 168px;
				display: flex; flex-direction: column; gap: 2px;
				animation: mlpChipIn 0.12s ease;
			}
			.chat-attach-menu[hidden] { display: none; }
			.chat-attach-menu-item {
				display: flex; align-items: center; gap: 10px; width: 100%;
				background: none; border: none; text-align: left; cursor: pointer;
				padding: 9px 10px; border-radius: 7px; font-size: 13.5px; color: #333;
				font-family: inherit;
			}
			.chat-attach-menu-item:hover { background: #f2f9f6; color: #10a37f; }
			.chat-attach-menu-icon { display: flex; align-items: center; justify-content: center; color: #666; flex-shrink: 0; }
			.chat-attach-menu-item:hover .chat-attach-menu-icon { color: #10a37f; }
			.chat-attach-menu-item.disabled,
			.chat-attach-menu-item[disabled] { opacity: 0.4; cursor: not-allowed; pointer-events: none; }

			.chat-attach-preview { display: flex; flex-wrap: wrap; gap: 8px; padding: 0 18px; }
			.chat-attach-preview:not(:empty) { padding-top: 12px; }
			.chat-attach-chip {
				position: relative; display: flex; align-items: center; gap: 6px;
				background: #f5f5f5; border: 1px solid #e5e5e5; border-radius: 10px;
				padding: 6px 10px 6px 6px; font-size: 12px; color: #444;
				max-width: 200px; animation: mlpChipIn 0.15s ease;
			}
			@keyframes mlpChipIn { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
			.chat-attach-chip-thumb { width: 32px; height: 32px; border-radius: 6px; object-fit: cover; flex-shrink: 0; background: #ddd; }
			.chat-attach-chip-icon {
				width: 32px; height: 32px; border-radius: 6px; background: #10a37f; color: #fff;
				display: flex; align-items: center; justify-content: center; flex-shrink: 0;
			}
			.chat-attach-chip-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
			.chat-attach-chip-remove {
				border: none; background: #fff; color: #888; width: 18px; height: 18px;
				min-width: 18px; border-radius: 50%; cursor: pointer; display: flex;
				align-items: center; justify-content: center; font-size: 12px; line-height: 1;
				box-shadow: 0 0 0 1px #ddd inset;
			}
			.chat-attach-chip-remove:hover { background: #ff6b6b; color: #fff; box-shadow: none; }

			.chat-drop-hint {
				display: none; position: absolute; inset: 0; flex-direction: column;
				align-items: center; justify-content: center; gap: 6px;
				background: rgba(16, 163, 127, 0.06); border: 2px dashed #10a37f;
				border-radius: 10px; color: #10a37f; font-size: 13px; font-weight: 500;
				pointer-events: none; margin: 6px;
			}
			.chat-input-wrap.drag-over .chat-drop-hint { display: flex; }

			.chat-msg-attachments { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
			.chat-msg-attachments:first-child { margin-top: 0; }
			.chat-msg-img { max-width: 220px; max-height: 220px; border-radius: 8px; display: block; cursor: zoom-in; }
			.chat-msg-file {
				display: flex; align-items: center; gap: 6px;
				background: rgba(0,0,0,0.06); border-radius: 8px; padding: 6px 10px; font-size: 12px; max-width: 220px;
			}
			.chat-msg.user .chat-msg-file { background: rgba(255,255,255,0.2); }
			.chat-msg-file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

			.chat-msg.typing { display: flex; align-items: center; gap: 8px; font-style: normal; padding: 12px 16px; }
			.chat-typing-dots { display: flex; align-items: center; gap: 4px; }
			.chat-typing-dots span {
				width: 7px; height: 7px; border-radius: 50%; background: #999;
				animation: mlpBounce 1.2s infinite ease-in-out both;
			}
			.chat-typing-dots span:nth-child(1) { animation-delay: -0.28s; }
			.chat-typing-dots span:nth-child(2) { animation-delay: -0.14s; }
			.chat-typing-dots span:nth-child(3) { animation-delay: 0s; }
			@keyframes mlpBounce { 0%, 80%, 100% { transform: scale(0.6); opacity: 0.5; } 40% { transform: scale(1); opacity: 1; } }

			.chat-icon-plus { position: relative; display: inline-block; width: 14px; height: 14px; }
			.chat-icon-plus::before, .chat-icon-plus::after { content: ''; position: absolute; background: currentColor; border-radius: 1px; }
			.chat-icon-plus::before { top: 0; left: 6px; width: 2px; height: 14px; }
			.chat-icon-plus::after { top: 6px; left: 0; width: 14px; height: 2px; }

			.chat-icon-send { display: inline-block; width: 0; height: 0; border-top: 7px solid transparent; border-bottom: 7px solid transparent; border-left: 13px solid #fff; margin-left: 3px; flex-shrink: 0; }
			.chat-send-btn:disabled .chat-icon-send { border-left-color: rgba(255,255,255,0.55); }

			.chat-icon-stop { display: inline-block; width: 12px; height: 12px; background: #fff; border-radius: 2px; flex-shrink: 0; }
			.chat-send-btn.is-stop { background: #d63638; }
			.chat-send-btn.is-stop:hover { background: #b9282a; }
			.chat-send-btn.is-stop:disabled { background: #eeb3b3; }

			.chat-stopped-note { margin-top: 6px; font-size: 12px; color: #999; font-style: italic; }

			.chat-cursor { display: inline-block; width: 2px; height: 1em; background: #555; margin-left: 2px; vertical-align: text-bottom; animation: mlpBlink 0.75s step-end infinite; }
			@keyframes mlpBlink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
			/* While a reply is still streaming in it's rendered as plain text
			   into a single text node (fast) instead of re-parsing HTML on
			   every token, so newlines need to wrap via CSS instead of <br>. */
			.chat-msg-text { white-space: pre-wrap; word-wrap: break-word; }

			.chat-thinking { margin-bottom: 6px; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden; font-size: 12px; background: #fafafa; }
			.chat-thinking summary { cursor: pointer; padding: 6px 10px; color: #888; user-select: none; list-style: none; display: flex; align-items: center; gap: 6px; }
			.chat-thinking summary::-webkit-details-marker { display: none; }
			.chat-thinking summary::before { content: '▶'; font-size: 9px; transition: transform 0.2s; display: inline-block; }
			.chat-thinking[open] summary::before { transform: rotate(90deg); }
			.chat-thinking-body { padding: 8px 12px; border-top: 1px solid #e8e8e8; color: #777; line-height: 1.5; white-space: pre-wrap; word-wrap: break-word; max-height: 260px; overflow-y: auto; }

			/* ── Code status indicator (Thinking/Editing while code streams) ── */
			.chat-code-status {
				display: inline-flex;
				align-items: center;
				gap: 7px;
				padding: 6px 12px;
				margin-bottom: 8px;
				border-radius: 20px;
				background: #f2f2f2;
				width: fit-content;
			}
			.chat-code-status-icon {
				flex-shrink: 0;
				color: #888;
				animation: chatCodeStatusSpin 1s linear infinite;
			}
			@keyframes chatCodeStatusSpin {
				from { transform: rotate(0deg); }
				to { transform: rotate(360deg); }
			}
			.chat-code-status-text {
				font-size: 12.5px;
				font-weight: 500;
				background: linear-gradient(90deg, #b5b5b5 0%, #3a3a3a 45%, #b5b5b5 90%);
				background-size: 200% 100%;
				-webkit-background-clip: text;
				background-clip: text;
				color: transparent;
				animation: chatCodeStatusShimmer 1.6s linear infinite;
			}
			@keyframes chatCodeStatusShimmer {
				0% { background-position: 200% 0; }
				100% { background-position: -200% 0; }
			}

			/* ── Administration room ─────────────────────────────────────── */
			.chat-sidebar-divider { height: 1px; background: #3a3b3d; margin: 10px 0; flex-shrink: 0; }
			.chat-sidebar-disclaimer {
				margin: 14px 0 0 0 !important; padding-top: 12px; flex-shrink: 0;
				border-top: 1px solid #3a3b3d; font-size: 11px; line-height: 1.4; color: #8e8ea0;
			}
			.chat-sidebar-disclaimer a { color: #10a37f; text-decoration: none; }
			.chat-sidebar-disclaimer a:hover { text-decoration: underline; }
			.chat-room-btn {
				background: transparent; border: 1px solid #565869; color: #ececf1;
				padding: 10px 12px; border-radius: 6px; cursor: pointer; text-align: left;
				font-size: 14px; display: flex; align-items: center; gap: 8px; flex-shrink: 0;
			}
			.chat-room-btn:hover, .chat-room-btn.active { background: #2b2c2f; }
			.chat-room-btn.active { border-color: #10a37f; color: #10a37f; }
			.chat-room-btn-icon { font-size: 14px; }

			.chat-admin-view { display: none; overflow-y: auto; }
			.chat-admin-view[data-hidden="1"] { display: none; }
			.chat-admin-view[data-hidden="0"] { display: flex; }
			.chat-admin-header {
				padding: 12px 18px; border-bottom: 1px solid #eee; font-weight: 600;
				display: flex; justify-content: space-between; align-items: center; font-size: 14px; color: #333; flex-shrink: 0; gap: 10px;
			}
			.chat-admin-refresh-btn {
				background: #f0f0f0; border: 1px solid #e0e0e0; border-radius: 8px;
				padding: 5px 12px; font-size: 12px; cursor: pointer; color: #555;
			}
			.chat-admin-refresh-btn:hover { background: #e8e8e8; }
			.chat-admin-body { padding: 20px; overflow-y: auto; flex: 1; }
			.chat-admin-stats { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 22px; }
			.chat-admin-stat-card {
				background: #f7f7f8; border: 1px solid #eee; border-radius: 8px;
				padding: 14px 16px; min-width: 150px; flex: 1;
			}
			.chat-admin-stat-label { font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: .03em; margin-bottom: 6px; }
			.chat-admin-stat-value { font-size: 20px; font-weight: 700; color: #222; }
			.chat-admin-section { margin-bottom: 26px; }
			.chat-admin-section-head h3 { margin: 0 0 8px 0; font-size: 15px; color: #222; }
			.chat-admin-note { font-size: 12px; color: #888; margin: 0 0 10px 0; }
			.chat-admin-toggle-btn {
				background: #10a37f; color: #fff; border: none; border-radius: 8px;
				padding: 9px 16px; font-size: 13px; font-weight: 600; cursor: pointer;
			}
			.chat-admin-toggle-btn.is-disabled { background: #d63638; }
			.chat-admin-toggle-btn:hover { opacity: 0.9; }
			.chat-admin-models { display: flex; flex-direction: column; gap: 8px; }
			.chat-admin-model-row {
				display: flex; align-items: center; justify-content: space-between; gap: 10px;
				background: #f7f7f8; border: 1px solid #eee; border-radius: 8px; padding: 10px 14px;
			}
			.chat-admin-model-name { font-size: 13px; font-weight: 600; color: #222; }
			.chat-admin-model-meta { font-size: 11px; color: #888; margin-top: 2px; }
			.chat-admin-model-status { display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; }
			.chat-status-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
			.chat-status-online       { color: #00a32a; } .chat-status-online .chat-status-dot       { background: #00a32a; }
			.chat-status-rate_limited { color: #b8860b; } .chat-status-rate_limited .chat-status-dot { background: #dba617; }
			.chat-status-blocked      { color: #d63638; } .chat-status-blocked .chat-status-dot      { background: #d63638; }
			.chat-status-error        { color: #d63638; } .chat-status-error .chat-status-dot        { background: #d63638; }
			.chat-status-offline      { color: #787c82; } .chat-status-offline .chat-status-dot      { background: #787c82; }
			.chat-status-disabled     { color: #d63638; } .chat-status-disabled .chat-status-dot     { background: #d63638; }
			.chat-status-unknown      { color: #787c82; } .chat-status-unknown .chat-status-dot      { background: #ababab; }
			.chat-admin-model-toggle {
				background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 6px 12px;
				font-size: 12px; cursor: pointer; color: #444; flex-shrink: 0;
			}
			.chat-admin-model-toggle:hover { background: #f0f0f0; }
			.chat-admin-model-toggle.is-disabled { color: #10a37f; border-color: #10a37f; }
			.chat-admin-model-votes {
				display: flex; align-items: center; gap: 12px; font-size: 12px; font-weight: 600; flex-shrink: 0;
			}
			.chat-admin-model-vote { display: flex; align-items: center; gap: 4px; }
			.chat-admin-model-vote.likes { color: #00a32a; }
			.chat-admin-model-vote.dislikes { color: #d63638; }
			.chat-admin-model-vote svg { display: block; }

			.chat-reload-btn {
				background: #10a37f;
				color: #fff;
				border: none;
				border-radius: 8px;
				padding: 10px 20px;
				font-size: 14px;
				font-weight: 600;
				cursor: pointer;
				transition: background 0.15s, transform 0.1s;
				display: inline-flex;
				align-items: center;
				gap: 6px;
			}
			.chat-reload-btn:hover {
				background: #0d8a6a;
				transform: translateY(-1px);
			}
				</style>

		<script>
		(function() {
			// Full-page takeover.
			(function fullPageTakeover() {
				var wrap = document.getElementById('chat-ai-chat-fullpage');
				if (!wrap) return;
				wrap.id = 'chat-ai-chat-fullpage-portal';
				document.body.appendChild(wrap);
				document.documentElement.classList.add('chat-fullpage-active');
				document.body.classList.add('chat-fullpage-active');
				Array.prototype.forEach.call(document.body.children, function(el) {
					if (el !== wrap) el.setAttribute('data-mlp-hidden', '1');
				});
			})();

			<?php if ( ! $user_id ) : ?>
			// --- AI Restarting overlay (logged-out users only) ---
			// Shows a restart message and refreshes the page after 2 seconds.
			(function showRestartOverlay() {
				var wrap = document.getElementById('chat-ai-chat-fullpage-portal');
				if (!wrap) return;

				// Create a semi-transparent overlay that covers the entire app.
				var overlay = document.createElement('div');
				overlay.style.cssText = [
					'position: fixed;',
					'top: 0; left: 0; right: 0; bottom: 0;',
					'z-index: 9999;',
					'background: rgba(0,0,0,0.7);',
					'display: flex;',
					'align-items: center;',
					'justify-content: center;',
					'flex-direction: column;',
					'backdrop-filter: blur(6px);',
					'-webkit-backdrop-filter: blur(6px);'
				].join(' ');

				var content = document.createElement('div');
				content.style.cssText = [
					'background: #202123;',
					'color: #ececf1;',
					'border-radius: 16px;',
					'padding: 32px 40px;',
					'max-width: 420px;',
					'text-align: center;',
					'font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;',
					'box-shadow: 0 20px 60px rgba(0,0,0,0.5);',
					'border: 1px solid rgba(255,255,255,0.08);'
				].join(' ');

				var spinner = document.createElement('div');
				spinner.style.cssText = [
					'width: 40px;',
					'height: 40px;',
					'border: 4px solid rgba(255,255,255,0.15);',
					'border-top: 4px solid #10a37f;',
					'border-radius: 50%;',
					'animation: mlpSpin 0.8s linear infinite;',
					'margin: 0 auto 16px auto;'
				].join(' ');

				var heading = document.createElement('h2');
				heading.textContent = 'AI Restarting…';
				heading.style.cssText = [
					'margin: 0 0 8px 0;',
					'font-size: 20px;',
					'font-weight: 600;',
					'color: #ececf1;'
				].join(' ');

				var note = document.createElement('p');
				note.textContent = 'The AI chat is restarting. Please wait…';
				note.style.cssText = [
					'margin: 0;',
					'font-size: 14px;',
					'color: #9a9aab;',
					'line-height: 1.5;'
				].join(' ');

				var refreshNote = document.createElement('p');
				refreshNote.textContent = 'Refreshing in 2s…';
				refreshNote.style.cssText = [
					'margin: 10px 0 0 0;',
					'font-size: 12px;',
					'color: #6e6e80;',
					'letter-spacing: .03em;'
				].join(' ');

				content.appendChild(spinner);
				content.appendChild(heading);
				content.appendChild(note);
				content.appendChild(refreshNote);
				overlay.appendChild(content);

				// Inject the spin keyframes
				var style = document.createElement('style');
				style.textContent = '@keyframes mlpSpin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }';
				document.head.appendChild(style);

				// Insert overlay into the app container
				wrap.appendChild(overlay);

				// Refresh after 2 seconds
				setTimeout(function() {
					window.location.reload();
				}, 2000);
			})();
			<?php endif; ?>

			var restUrl    = <?php echo wp_json_encode( $rest_url ); ?>;
			var nonce      = <?php echo wp_json_encode( $nonce ); ?>;
			var jsModels   = <?php echo wp_json_encode( $js_models ); ?>;

			// ── Identity (username + guest token) ──────────────────────────
			// Logged-out visitors pick a display name once; it's stored in
			// localStorage alongside a random token, so their conversations
			// stay theirs (and separate from anyone else picking the same
			// name) and persist across visits without needing a WP account.
			var IDENTITY_KEY = 'mlp_ai_chat_identity';
			var CONVOS_KEY   = 'mlp_ai_chat_conversations_v2';
			var STALE_MS     = 10 * 24 * 60 * 60 * 1000; // 10 days

			function loadIdentity() {
				try {
					var raw = window.localStorage.getItem(IDENTITY_KEY);
					if (!raw) return null;
					var parsed = JSON.parse(raw);
					if (parsed && parsed.token && parsed.username) return parsed;
					return null;
				} catch (e) {
					return null;
				}
			}

			function saveIdentity(username) {
				var token = (window.crypto && window.crypto.randomUUID)
					? window.crypto.randomUUID().replace(/-/g, '')
					: (Date.now().toString(36) + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2));
				var identity = { username: username, token: token };
				try { window.localStorage.setItem(IDENTITY_KEY, JSON.stringify(identity)); } catch (e) {}
				return identity;
			}

			var identity   = loadIdentity();
			var guestToken = identity ? identity.token : '';

			// ── Conversation storage (100% client-side) ─────────────────────
			// Every conversation and message lives only in this browser's
			// localStorage. The server never sees or stores chat content —
			// it only ever receives one request's worth of history in
			// transit, to relay to the AI API, and forgets it immediately
			// after streaming the reply back.
			function newId() {
				return (window.crypto && window.crypto.randomUUID)
					? window.crypto.randomUUID()
					: ('c_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10));
			}
			function readConvos() {
				try {
					var raw = window.localStorage.getItem(CONVOS_KEY);
					var list = raw ? JSON.parse(raw) : [];
					return Array.isArray(list) ? list : [];
				} catch (e) { return []; }
			}
			function writeConvos(list) {
				try { window.localStorage.setItem(CONVOS_KEY, JSON.stringify(list)); } catch (e) {}
			}
			function getConvo(id) {
				var list = readConvos();
				for (var i = 0; i < list.length; i++) { if (list[i].id === id) return list[i]; }
				return null;
			}
			function upsertConvo(convo) {
				var list = readConvos();
				var idx  = -1;
				for (var i = 0; i < list.length; i++) { if (list[i].id === convo.id) { idx = i; break; } }
				if (idx === -1) list.unshift(convo); else list[idx] = convo;
				writeConvos(list);
			}
			function deleteConvoLocal(id) {
				writeConvos(readConvos().filter(function(c) { return c.id !== id; }));
			}
			function makeTitle(source) {
				source = (source || 'New Chat').trim() || 'New Chat';
				return source.length > 40 ? source.slice(0, 40) + '...' : source;
			}
			function pruneStaleConversations() {
				var now  = Date.now();
				var kept = readConvos().filter(function(c) {
					var ts = Date.parse(c.updated_at || c.created_at || '');
					return isNaN(ts) || (now - ts) <= STALE_MS;
				});
				writeConvos(kept);
				return Promise.resolve();
			}

			var currentConversationId = null;

			// Tracks the in-flight AI request so the Send button can be
			// turned into a Stop button while a reply is streaming, and so
			// the user can cancel a long/complex generation at any time.
			var activeGenerations = {}; // convoId -> { abortController, reader, userBubbleEl, assistantBubble }

			var elList        = document.getElementById('chat-conversation-list');
			var elConvSearch  = document.getElementById('chat-conv-search');
			var elConvSearchClear = document.getElementById('chat-conv-search-clear');
			var elMessages    = document.getElementById('chat-messages');
			var elInput       = document.getElementById('chat-input');
			var elSend        = document.getElementById('chat-send-btn');
			var elNewChat     = document.getElementById('chat-new-chat-btn');
			var elNewModelsBtn   = document.getElementById('chat-new-models-btn');
			var elNewModelsModal = document.getElementById('chat-new-models-modal');
			var elNewModelsClose = document.getElementById('chat-new-models-close');
			var elTitle       = document.getElementById('chat-current-title');
			var elModelSelect = document.getElementById('chat-model-select');
			var elAttachBtn   = document.getElementById('chat-attach-btn');
			var elAttachMenu  = document.getElementById('chat-attach-menu');
			var elAttachMenuImage = document.getElementById('chat-attach-menu-image');
			var elAttachMenuFile  = document.getElementById('chat-attach-menu-file');
			var elFileInput   = document.getElementById('chat-file-input');
			var elImageInput  = document.getElementById('chat-image-input');
			var elAttachPrev  = document.getElementById('chat-attach-preview');
			var elInputWrap   = document.querySelector('.chat-input-wrap');
			var elModal       = document.getElementById('chat-username-modal');
			var elModalInput  = document.getElementById('chat-username-input');
			var elModalError  = document.getElementById('chat-username-error');
			var elModalSubmit = document.getElementById('chat-username-submit');
			var elDisabledBanner = document.getElementById('chat-disabled-banner');
			var elChatView    = document.getElementById('chat-chat-view');
			var elAdminView   = document.getElementById('chat-admin-view');
			var elAdminRoomBtn = document.getElementById('chat-admin-room-btn');
			var elAdminRefreshBtn = document.getElementById('chat-admin-refresh-btn');
			var elAdminStats  = document.getElementById('chat-admin-stats');
			var elAdminModels = document.getElementById('chat-admin-models');
			var elAdminToggleGlobalBtn = document.getElementById('chat-admin-toggle-global-btn');
			var elSidebar          = document.getElementById('chat-sidebar');
			var elSidebarBackdrop  = document.getElementById('chat-sidebar-backdrop');
			var elMenuBtn          = document.getElementById('chat-menu-btn');
			var elAdminMenuBtn     = document.getElementById('chat-admin-menu-btn');

			// ── Custom "Choose AI model" dropdown ───────────────────────────
			// The real <select id="chat-model-select"> stays fully functional
			// (value/options/disabled/change event) and is only visually
			// hidden; this widget is a richer view on top of it so each model
			// can show its logo instead of plain text.
			var elModelPicker        = document.getElementById('chat-model-picker');
			var elModelPickerTrigger = document.getElementById('chat-model-picker-trigger');
			var elModelPickerIcon    = document.getElementById('chat-model-picker-trigger-icon');
			var elModelPickerLabel   = document.getElementById('chat-model-picker-trigger-label');
			var elModelPickerPanel   = document.getElementById('chat-model-picker-panel');
			var modelPickerOptionEls = Array.prototype.slice.call(elModelPickerPanel.querySelectorAll('.chat-model-picker-option'));

			function modelPickerIconMarkup(logoUrl, fallbackLetter) {
				if (logoUrl) return '<img src="' + logoUrl + '" alt="">';
				return '<span class="chat-model-picker-option-icon-fallback">' + (fallbackLetter || '?') + '</span>';
			}

			function syncModelPicker() {
				var selectedOpt = elModelSelect.options[elModelSelect.selectedIndex];
				if (selectedOpt) {
					var label = selectedOpt.dataset.label || selectedOpt.textContent;
					elModelPickerIcon.innerHTML = modelPickerIconMarkup(selectedOpt.dataset.logo, label.charAt(0).toUpperCase());
					elModelPickerLabel.textContent = label;
				}
				elModelPickerTrigger.disabled = elModelSelect.disabled;

				modelPickerOptionEls.forEach(function(el) {
					var id = el.getAttribute('data-model-id');
					var nativeOpt = null;
					Array.prototype.forEach.call(elModelSelect.options, function(o) { if (o.value === id) nativeOpt = o; });
					var isDisabled = !!(nativeOpt && nativeOpt.disabled);
					var isSelected = !!(nativeOpt && elModelSelect.value === id);
					el.setAttribute('aria-disabled', isDisabled ? 'true' : 'false');
					el.setAttribute('aria-selected', isSelected ? 'true' : 'false');
					el.classList.toggle('is-active', isSelected);
					var labelEl = el.querySelector('.chat-model-picker-option-label');
					if (labelEl) {
						var base = el.getAttribute('data-label') || labelEl.textContent;
						labelEl.textContent = base + (isDisabled ? ' (disabled)' : '');
					}
				});
			}

			function onModelPickerOutsideClick(e) {
				if (!elModelPicker.contains(e.target)) closeModelPicker();
			}
			function onModelPickerKeydown(e) {
				if (e.key === 'Escape' || e.key === 'Esc') { closeModelPicker(); elModelPickerTrigger.focus(); }
			}
			function openModelPicker() {
				if (elModelPickerTrigger.disabled) return;
				syncModelPicker();
				elModelPickerPanel.hidden = false;
				elModelPickerTrigger.setAttribute('aria-expanded', 'true');
				document.addEventListener('click', onModelPickerOutsideClick, true);
				document.addEventListener('keydown', onModelPickerKeydown, true);
			}
			function closeModelPicker() {
				elModelPickerPanel.hidden = true;
				elModelPickerTrigger.setAttribute('aria-expanded', 'false');
				document.removeEventListener('click', onModelPickerOutsideClick, true);
				document.removeEventListener('keydown', onModelPickerKeydown, true);
			}

			elModelPickerTrigger.addEventListener('click', function() {
				if (elModelPickerPanel.hidden) openModelPicker(); else closeModelPicker();
			});

			modelPickerOptionEls.forEach(function(el) {
				el.addEventListener('click', function() {
					if (el.getAttribute('aria-disabled') === 'true') return;
					var id = el.getAttribute('data-model-id');
					if (elModelSelect.value !== id) {
						elModelSelect.value = id;
						updateModelUI();
					}
					closeModelPicker();
				});
			});

			var pendingAttachments = [];
			var MAX_ATTACHMENTS    = 4;
			var MAX_FILE_BYTES     = 4 * 1024 * 1024;

			function currentModelConfig() {
				var found = null;
				jsModels.forEach(function(m) { if (m.id === elModelSelect.value) found = m; });
				return found;
			}

			var currentImagesOk = true;

			function updateModelUI() {
				elInput.placeholder = 'Message the AI…';

				var cfg = currentModelConfig();
				var imagesOk = !cfg || cfg.supports_images !== false;
				currentImagesOk = imagesOk;

				// The + button and "Add file" are always available. Only the
				// "Add image" menu option is restricted per-model.
				elAttachMenuImage.hidden = !imagesOk;
				elAttachMenuImage.disabled = !imagesOk;

				if (!imagesOk) {
					// Drop any pending image attachments so a leftover image
					// from a previous model doesn't get silently sent (and
					// rejected) once the user switches to a text-only model.
					var hadImages = pendingAttachments.some(function(a) { return a.isImage; });
					pendingAttachments = pendingAttachments.filter(function(a) { return !a.isImage; });
					if (hadImages) renderAttachPreview();
				}

				syncModelPicker();
			}

			// Refresh input placeholder when model changes.
			elModelSelect.addEventListener('change', updateModelUI);

			// ── API helper ───────────────────────────────────────────────────

			function apiFetch(path, options) {
				options = options || {};
				options.headers = Object.assign(
					{
						'Content-Type': 'application/json',
						'X-WP-Nonce': nonce,
						'X-MLP-Guest-Token': guestToken,
						'X-MLP-Guest-Username': identity ? identity.username : ''
					},
					options.headers || {}
				);
				return fetch(restUrl + path, options).then(function(res) {
					if (!res.ok) {
						return res.json().then(function(err) {
							throw new Error(err.message || 'Request failed');
						});
					}
					return res.json();
				});
			}

			// ── AI disabled (admin switch) ──────────────────────────────────

			var disabledModelIds = [];

			function applyDisabledState(isDisabled) {
				elDisabledBanner.setAttribute('data-show', isDisabled ? '1' : '0');
				elModelSelect.disabled = isDisabled;
				elInput.disabled       = isDisabled;
				elSend.disabled        = isDisabled;
				elAttachBtn.disabled   = isDisabled;
			}

			function applyModelDisabledOptions() {
				Array.prototype.forEach.call(elModelSelect.options, function(opt) {
					var isOff = disabledModelIds.indexOf(opt.value) !== -1;
					opt.disabled = isOff;
					opt.textContent = (opt.dataset.label || opt.textContent.replace(' (disabled)', '')) + (isOff ? ' (disabled)' : '');
					if (!opt.dataset.label) opt.dataset.label = opt.textContent.replace(' (disabled)', '');
				});
				if (elModelSelect.selectedOptions[0] && elModelSelect.selectedOptions[0].disabled) {
					var firstOk = Array.prototype.filter.call(elModelSelect.options, function(o) { return !o.disabled; })[0];
					if (firstOk) elModelSelect.value = firstOk.value;
				}

				syncModelPicker();
			}

			function checkAiStatus() {
				return fetch(restUrl + '/status').then(function(res) { return res.json(); })
					.then(function(data) {
						applyDisabledState(!!data.disabled);
						disabledModelIds = data.disabled_models || [];
						applyModelDisabledOptions();
					})
					.catch(function() {});
			}

			// ── Username modal ──────────────────────────────────────────────

			function showUsernameModal() {
				elModal.removeAttribute('data-hidden');
				elModalInput.focus();
			}
			function hideUsernameModal() {
				elModal.setAttribute('data-hidden', '1');
			}

			function submitUsername() {
				var name = elModalInput.value.trim();
				if (!name) {
					elModalError.textContent = 'Please enter a name.';
					return;
				}
				if (name.length > 30) {
					elModalError.textContent = 'Name is too long (30 characters max).';
					return;
				}
				identity   = saveIdentity(name);
				guestToken = identity.token;
				elModalError.textContent = '';
				hideUsernameModal();
				initChatApp();
			}

			elModalSubmit.addEventListener('click', submitUsername);
			elModalInput.addEventListener('keydown', function(e) {
				if (e.key === 'Enter') { e.preventDefault(); submitUsername(); }
			});

			function escapeHtml(str) {
				var div = document.createElement('div');
				div.innerText = str;
				return div.innerHTML;
			}

			function renderMarkdown(text) {
				try {
					if (!text) return '';

					var lines = text.split(/\r?\n/);
					var blocks = [];
					var currentPara = [];

					function flushPara() {
						if (currentPara.length === 0) return;
						var html = currentPara.map(function(line) {
							var p = escapeHtml(line);
							p = p.replace(/`([^`]+)`/g, '<code>$1</code>');
							p = p.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
							p = p.replace(/\*(.+?)\*/g, '<em>$1</em>');
							p = p.replace(/_(.+?)_/g, '<em>$1</em>');
							p = p.replace(/__(.+?)__/g, '<u>$1</u>');
							return p;
						}).join('<br>');
						blocks.push(html);
						currentPara = [];
					}

					// Claude-style "artifact" card: instead of dumping the raw
					// source straight into the chat bubble, we show a small
					// file card (icon + filename + line count). The full code
					// only appears once the user actually opens it in the
					// Monaco sidebar — same idea as Claude's artifact preview.
					function makeCodeBlock(lang, code, filenameHint) {
						var displayLang = lang || 'text';
						var blockId  = 'code_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
						var filename = (filenameHint || '').trim() || guessFilename(displayLang);
						var fileId   = storeFile(filename, monacoLangFor(displayLang), code);
						var lineCount = code.split(/\r?\n/).length;
						var meta = lineCount + (lineCount === 1 ? ' line' : ' lines') + ' · Click to open';
						return '<div class="chat-file-card chat-artifact-card chat-open-btn" id="' + blockId + '" data-file-id="' + fileId + '" role="button" tabindex="0">' +
							'<div class="chat-file-card-main">' +
								'<div class="chat-file-card-icon">' + fileIconSvg() + '</div>' +
								'<div class="chat-file-card-info">' +
									'<div class="chat-file-card-name">' + escapeHtml(filename) + '</div>' +
									'<div class="chat-file-card-meta">' + escapeHtml(meta) + '</div>' +
								'</div>' +
							'</div>' +
							'<button class="chat-file-card-btn chat-open-btn" type="button" data-file-id="' + fileId + '" title="Open in code editor">' +
								'<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:5px;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>' +
								'Open' +
							'</button>' +
							'</div>';
					}

					var inCodeBlock = false;
					var codeBlockLang = '';
					var codeBlockFilename = '';
					var codeBlockLines = [];

					for (var i = 0; i < lines.length; i++) {
						var line = lines[i];
						// Accepts a plain ```lang fence or a ```lang:filename.ext
						// fence — the model is asked to always name the file it's
						// writing, so we can show that real name on the card
						// instead of a generic "snippet.ext".
						var fenceMatch = line.match(/^```\s*([\w+-]*)(?::(\S+))?\s*$/);

						if (fenceMatch) {
							if (inCodeBlock) {
								flushPara();
								blocks.push(makeCodeBlock(codeBlockLang, codeBlockLines.join('\n'), codeBlockFilename));
								inCodeBlock = false;
								codeBlockLang = '';
								codeBlockFilename = '';
								codeBlockLines = [];
							} else {
								flushPara();
								inCodeBlock = true;
								codeBlockLang = fenceMatch[1];
								codeBlockFilename = fenceMatch[2] || '';
							}
							continue;
						}

						if (inCodeBlock) {
							codeBlockLines.push(line);
							continue;
						}

						if (line.trim() === '') {
							flushPara();
							continue;
						}

						var headingMatch = line.match(/^(#{1,6})\s+(.*)$/);
						if (headingMatch) {
							flushPara();
							var level = headingMatch[1].length;
							blocks.push('<h' + level + '>' + escapeHtml(headingMatch[2]) + '</h' + level + '>');
							continue;
						}

						currentPara.push(line);
					}

					flushPara();

					if (inCodeBlock) {
						blocks.push(makeCodeBlock(codeBlockLang, codeBlockLines.join('\n'), codeBlockFilename));
					}

					var result = [];
					for (var j = 0; j < blocks.length; j++) {
						result.push(blocks[j]);
						if (j < blocks.length - 1) {
							result.push('<div style="height:8px;"></div>');
						}
					}
					return result.join('');
				} catch (e) {
					return escapeHtml(text).replace(/\n/g, '<br>');
				}
			}

			function fileIconSvg() {
				return '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>';
			}

			function likeSvg() {
				return '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3zM7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"></path></svg>';
			}
			function dislikeSvg() {
				return '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 15v4a3 3 0 0 0 3 3l4-9V2H5.72a2 2 0 0 0-2 1.7l-1.38 9a2 2 0 0 0 2 2.3zm7-13h2.67A2.31 2.31 0 0 1 22 4v7a2.31 2.31 0 0 1-2.33 2H17"></path></svg>';
			}

			// ── File store & Monaco Sidebar ──────────────────────────────
			var fileStore = {};
			function storeFile(filename, lang, code) {
				var id = 'file_' + Date.now() + '_' + Math.random().toString(36).slice(2, 10);
				fileStore[id] = { filename: filename, lang: lang || 'plaintext', code: code };
				return id;
			}

			// Fenced code blocks only carry a loose language tag (```js,
			// ```py, ```sh, ...). Map that to a plausible file extension
			// (for the download button) and to the language id Monaco
			// actually understands (for syntax highlighting).
			var LANG_EXT_MAP = {
				javascript: 'js', js: 'js', typescript: 'ts', ts: 'ts', jsx: 'jsx', tsx: 'tsx',
				python: 'py', py: 'py', php: 'php', html: 'html', xml: 'xml', css: 'css',
				scss: 'scss', less: 'less', json: 'json', java: 'java', c: 'c', cpp: 'cpp',
				'c++': 'cpp', csharp: 'cs', 'c#': 'cs', cs: 'cs', go: 'go', golang: 'go',
				rust: 'rs', rs: 'rs', ruby: 'rb', rb: 'rb', swift: 'swift', kotlin: 'kt',
				sql: 'sql', bash: 'sh', sh: 'sh', shell: 'sh', zsh: 'sh', powershell: 'ps1',
				yaml: 'yml', yml: 'yml', markdown: 'md', md: 'md', dockerfile: 'Dockerfile',
				text: 'txt', plaintext: 'txt', '': 'txt'
			};
			var LANG_MONACO_MAP = {
				js: 'javascript', jsx: 'javascript', ts: 'typescript', tsx: 'typescript',
				py: 'python', rb: 'ruby', rs: 'rust', cs: 'csharp', 'c++': 'cpp', sh: 'shell',
				zsh: 'shell', bash: 'shell', yml: 'yaml', md: 'markdown', text: 'plaintext', '': 'plaintext'
			};
			function guessFilename(lang) {
				var key = (lang || '').toLowerCase().trim();
				var ext = LANG_EXT_MAP[key] || (/^[a-z0-9]+$/.test(key) ? key : 'txt');
				return 'snippet.' + ext;
			}
			function monacoLangFor(lang) {
				var key = (lang || '').toLowerCase().trim();
				return LANG_MONACO_MAP[key] || key || 'plaintext';
			}
			function formatBytes(bytes) {
				if (bytes === 0) return '0 B';
				var k = 1024;
				var sizes = ['B', 'KB', 'MB', 'GB'];
				var i = Math.floor(Math.log(bytes) / Math.log(k));
				return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
			}

			var monacoEditor = null;
			var monacoLoaded = false;
			var currentFileData = null;

			function loadMonaco(callback) {
				if (monacoLoaded) { callback(); return; }
				var script = document.createElement('script');
				script.src = 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs/loader.js';
				script.onload = function() {
					require.config({ paths: { 'vs': 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' }});
					require(['vs/editor/editor.main'], function() {
						monacoLoaded = true;
						callback();
					});
				};
				script.onerror = function() {
					alert('Failed to load code editor.');
				};
				document.head.appendChild(script);
			}

			function openCodeSidebar(fileId) {
				var file = fileStore[fileId];
				if (!file) return;
				currentFileData = file;
				document.getElementById('chat-code-sidebar-title').textContent = file.filename;
				document.getElementById('chat-code-sidebar').setAttribute('data-hidden', '0');
				loadMonaco(function() {
					var container = document.getElementById('chat-code-sidebar-editor');
					if (monacoEditor) monacoEditor.dispose();
					monacoEditor = monaco.editor.create(container, {
						value: file.code,
						language: file.lang || 'plaintext',
						theme: 'vs-dark',
						automaticLayout: true,
						minimap: { enabled: false },
						scrollBeyondLastLine: false,
						fontSize: 13,
						lineNumbers: 'on',
						roundedSelection: false,
						readOnly: true,
						wordWrap: 'on'
					});
				});
			}

			function closeCodeSidebar() {
				document.getElementById('chat-code-sidebar').setAttribute('data-hidden', '1');
				if (monacoEditor) { monacoEditor.dispose(); monacoEditor = null; }
				currentFileData = null;
			}

			function downloadCurrentFile() {
				if (!currentFileData) return;
				var blob = new Blob([currentFileData.code], { type: 'text/plain' });
				var url = URL.createObjectURL(blob);
				var a = document.createElement('a');
				a.href = url;
				a.download = currentFileData.filename;
				document.body.appendChild(a);
				a.click();
				document.body.removeChild(a);
				URL.revokeObjectURL(url);
			}

			var copyListenersAttached = false;
			function attachCopyListeners() {
				// This is called both at boot and again once the chat app
				// initializes; without this guard the same delegated click
				// handler got bound twice, double-firing Copy/Open actions.
				if (copyListenersAttached) return;
				copyListenersAttached = true;
				elMessages.addEventListener('keydown', function(e) {
					if (e.key !== 'Enter' && e.key !== ' ') return;
					var card = e.target.closest('.chat-artifact-card');
					if (!card) return;
					e.preventDefault();
					var fileId = card.dataset.fileId;
					if (fileId) openCodeSidebar(fileId);
				});
				elMessages.addEventListener('click', function(e) {
					var openBtn = e.target.closest('.chat-open-btn');
					if (openBtn) {
						var fileId = openBtn.dataset.fileId;
						if (fileId) openCodeSidebar(fileId);
						return;
					}
					var fbBtn = e.target.closest('.chat-feedback-btn');
					if (fbBtn) {
						var bar     = fbBtn.closest('.chat-feedback-bar');
						var modelId = bar.dataset.model;
						var msgId   = bar.dataset.msgId;
						var type    = fbBtn.dataset.type; // 'like' | 'dislike'
						var current = bar.dataset.current || '';
						var likeBtn    = bar.querySelector('.chat-feedback-btn.like');
						var dislikeBtn = bar.querySelector('.chat-feedback-btn.dislike');
						var newState;

						if (current === type) {
							// Clicking the already-active vote retracts it.
							newState = '';
							sendFeedback(modelId, type, 'remove');
						} else {
							// Switching votes (or voting for the first time):
							// clear out any opposite vote first so a model
							// never ends up double-counted for one message.
							if (current) sendFeedback(modelId, current, 'remove');
							sendFeedback(modelId, type, 'add');
							newState = type;
						}

						bar.dataset.current = newState;
						likeBtn.classList.toggle('active', newState === 'like');
						likeBtn.setAttribute('aria-pressed', newState === 'like' ? 'true' : 'false');
						dislikeBtn.classList.toggle('active', newState === 'dislike');
						dislikeBtn.setAttribute('aria-pressed', newState === 'dislike' ? 'true' : 'false');

						persistMessageFeedback(msgId, newState || null);
						return;
					}
					var btn = e.target.closest('.chat-copy-btn');
					if (!btn) return;
					var encoded = btn.dataset.clipboard;
					if (!encoded) return;
					var code = decodeURIComponent(encoded);
					navigator.clipboard.writeText(code).then(function() {
						btn.classList.add('copied');
						btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!';
						setTimeout(function() {
							btn.classList.remove('copied');
							btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy';
						}, 2000);
					}).catch(function() {
						var ta = document.createElement('textarea');
						ta.value = code;
						document.body.appendChild(ta);
						ta.select();
						document.execCommand('copy');
						document.body.removeChild(ta);
					});
				});
			}

			function readFileAsDataURL(file) {
				return new Promise(function(resolve, reject) {
					var reader = new FileReader();
					reader.onload  = function() { resolve(reader.result); };
					reader.onerror = function() { reject(new Error('Could not read file')); };
					reader.readAsDataURL(file);
				});
			}

			function addFiles(fileList) {
				var files = Array.prototype.slice.call(fileList || []);
				if (!files.length) return;
				var overLimitWarned = false;
				var imageBlockedWarned = false;
				files.forEach(function(file) {
					var isImageFile = file.type.indexOf('image/') === 0;
					if (isImageFile && !currentImagesOk) {
						if (!imageBlockedWarned) { alert("This AI Model doesn't support images."); imageBlockedWarned = true; }
						return;
					}
					if (pendingAttachments.length >= MAX_ATTACHMENTS) {
						if (!overLimitWarned) { alert('You can attach up to ' + MAX_ATTACHMENTS + ' files per message.'); overLimitWarned = true; }
						return;
					}
					if (file.size > MAX_FILE_BYTES) { alert(file.name + ' is larger than 4MB and was skipped.'); return; }
					var entry = {
						id: 'att_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8),
						name: file.name, type: file.type || 'application/octet-stream',
						size: file.size, dataUrl: null,
						isImage: file.type.indexOf('image/') === 0
					};
					pendingAttachments.push(entry);
					renderAttachPreview();
					readFileAsDataURL(file).then(function(dataUrl) {
						entry.dataUrl = dataUrl; renderAttachPreview();
					}).catch(function() {
						pendingAttachments = pendingAttachments.filter(function(a) { return a.id !== entry.id; });
						renderAttachPreview();
					});
				});
			}

			function removeAttachment(id) {
				pendingAttachments = pendingAttachments.filter(function(a) { return a.id !== id; });
				renderAttachPreview();
			}

			function renderAttachPreview() {
				elAttachPrev.innerHTML = '';
				pendingAttachments.forEach(function(att) {
					var chip = document.createElement('div');
					chip.className = 'chat-attach-chip';
					if (att.isImage && att.dataUrl) {
						var img = document.createElement('img');
						img.className = 'chat-attach-chip-thumb'; img.src = att.dataUrl;
						chip.appendChild(img);
					} else {
						var iconWrap = document.createElement('div');
						iconWrap.className = 'chat-attach-chip-icon'; iconWrap.innerHTML = fileIconSvg();
						chip.appendChild(iconWrap);
					}
					var nameSpan = document.createElement('span');
					nameSpan.className = 'chat-attach-chip-name'; nameSpan.textContent = att.name;
					chip.appendChild(nameSpan);
					var removeBtn = document.createElement('button');
					removeBtn.className = 'chat-attach-chip-remove'; removeBtn.type = 'button';
					removeBtn.innerHTML = '&times;'; removeBtn.title = 'Remove';
					removeBtn.addEventListener('click', function() { removeAttachment(att.id); });
					chip.appendChild(removeBtn);
					elAttachPrev.appendChild(chip);
				});
			}

			function renderEmptyState() {
				elMessages.innerHTML = '<div class="chat-empty-state"><h2>AI Chat</h2><p>Start a conversation below.</p></div>';
			}

			function modelLabelFor(id) {
				var found = null;
				jsModels.forEach(function(m) { if (m.id === id) found = m; });
				return found ? found.label : null;
			}

			function showAvatarTooltip(avatarEl, modelId) {
				var existing = document.querySelector('.chat-msg-avatar-tooltip');
				if (existing) existing.remove();

				var label = modelLabelFor(modelId);
				var tip = document.createElement('div');
				tip.className = 'chat-msg-avatar-tooltip';
				tip.textContent = label ? ('Powered by ' + label) : 'Model info unavailable for this message';
				document.body.appendChild(tip);

				var rect = avatarEl.getBoundingClientRect();
				tip.style.top  = (rect.bottom + window.scrollY + 6) + 'px';
				tip.style.left = (rect.left + window.scrollX) + 'px';

				function dismiss(e) {
					if (tip.contains(e.target) || e.target === avatarEl) return;
					tip.remove();
					document.removeEventListener('click', dismiss);
				}
				setTimeout(function() { document.addEventListener('click', dismiss); }, 0);
				setTimeout(function() { if (tip.parentNode) tip.remove(); }, 4000);
			}

			function makeAssistantAvatar(modelId) {
				var wrap = document.createElement('div');
				wrap.className = 'chat-msg-avatar-wrap';

				var avatar = document.createElement('img');
				avatar.className = 'chat-msg-avatar';
				avatar.src = 'https://ptero.pro/wp-content/uploads/2026/08/3234427.png';
				avatar.alt = 'AI';
				var label = modelLabelFor(modelId);
				avatar.title = label ? ('Powered by ' + label) : 'AI';
				avatar.style.cursor = 'pointer';
				avatar.addEventListener('click', function(e) {
					e.stopPropagation();
					showAvatarTooltip(avatar, modelId);
				});
				wrap.appendChild(avatar);

				var nameEl = document.createElement('span');
				nameEl.className = 'chat-msg-avatar-name';
				nameEl.textContent = label ? label.replace(/\s*\(Free\)\s*$/i, '') : 'AI';
				wrap.appendChild(nameEl);

				return wrap;
			}

			// modelId/msgId identify who to credit the vote to and which
			// local message to remember it against; feedback is the current
			// vote state for this message ('like' / 'dislike' / falsy).
			function makeFeedbackBar(modelId, msgId, feedback) {
				var bar = document.createElement('div');
				bar.className = 'chat-feedback-bar';
				bar.dataset.model = modelId;
				bar.dataset.msgId = msgId;
				bar.dataset.current = feedback || '';

				var likeBtn = document.createElement('button');
				likeBtn.type = 'button';
				likeBtn.className = 'chat-feedback-btn like' + (feedback === 'like' ? ' active' : '');
				likeBtn.dataset.type = 'like';
				likeBtn.title = 'Good response';
				likeBtn.setAttribute('aria-label', 'Good response');
				likeBtn.setAttribute('aria-pressed', feedback === 'like' ? 'true' : 'false');
				likeBtn.innerHTML = likeSvg();

				var dislikeBtn = document.createElement('button');
				dislikeBtn.type = 'button';
				dislikeBtn.className = 'chat-feedback-btn dislike' + (feedback === 'dislike' ? ' active' : '');
				dislikeBtn.dataset.type = 'dislike';
				dislikeBtn.title = 'Bad response';
				dislikeBtn.setAttribute('aria-label', 'Bad response');
				dislikeBtn.setAttribute('aria-pressed', feedback === 'dislike' ? 'true' : 'false');
				dislikeBtn.innerHTML = dislikeSvg();

				bar.appendChild(likeBtn);
				bar.appendChild(dislikeBtn);
				return bar;
			}

			function sendFeedback(modelId, type, action) {
				if (!modelId) return;
				apiFetch('/feedback', {
					method: 'POST',
					body: JSON.stringify({ model_id: modelId, type: type, action: action })
				}).catch(function() {}); // best-effort — a dropped vote isn't worth surfacing an error for
			}

			// Keeps a vote alive across page reloads / re-opening the chat by
			// writing it back onto the message object in localStorage. Scans
			// every conversation (not just the open one) so this stays correct
			// even for a message that's currently reattached mid-stream.
			function persistMessageFeedback(msgId, feedback) {
				var convos = readConvos();
				for (var i = 0; i < convos.length; i++) {
					var msgs = convos[i].messages || [];
					for (var j = 0; j < msgs.length; j++) {
						if (msgs[j].id === msgId) {
							msgs[j].feedback = feedback;
							writeConvos(convos);
							return;
						}
					}
				}
			}

			function addMessageBubble(role, content, attachments, model, msgId, feedback) {
				var emptyState = elMessages.querySelector('.chat-empty-state');
				if (emptyState) emptyState.remove();
				var bubble = document.createElement('div');
				bubble.className = 'chat-msg ' + role;

				if (role === 'assistant') {
					bubble.appendChild(makeAssistantAvatar(model));
				}

				var contentWrap = document.createElement('div');
				contentWrap.className = 'chat-msg-content';

				if (content) {
					var textDiv = document.createElement('div');
					textDiv.className = 'chat-msg-text';
					textDiv.innerHTML = renderMarkdown(content);
					contentWrap.appendChild(textDiv);
				}
				if (attachments && attachments.length) {
					var attWrap = document.createElement('div');
					attWrap.className = 'chat-msg-attachments';
					attachments.forEach(function(att) {
						var src     = att.dataUrl || att.data;
						var isImage = (att.isImage !== undefined) ? att.isImage : (att.type || '').indexOf('image/') === 0;
						if (isImage && src) {
							var img = document.createElement('img');
							img.className = 'chat-msg-img'; img.src = src; img.alt = att.name || 'attachment';
							attWrap.appendChild(img);
						} else {
							var fileChip = document.createElement('div');
							fileChip.className = 'chat-msg-file';
							fileChip.innerHTML = fileIconSvg() + '<span class="chat-msg-file-name">' + escapeHtml(att.name || 'file') + '</span>';
							attWrap.appendChild(fileChip);
						}
					});
					contentWrap.appendChild(attWrap);
				}
				// Feedback only makes sense once we know which model answered
				// and have a stable id to remember the vote against.
				if (role === 'assistant' && model && msgId) {
					contentWrap.appendChild(makeFeedbackBar(model, msgId, feedback));
				}
				bubble.appendChild(contentWrap);
				elMessages.appendChild(bubble);
				elMessages.scrollTop = elMessages.scrollHeight;
				return bubble;
			}

			function loadConversations() {
				var convos = readConvos().slice().sort(function(a, b) {
					return Date.parse(b.updated_at || 0) - Date.parse(a.updated_at || 0);
				});

				var query = (elConvSearch && elConvSearch.value || '').trim().toLowerCase();
				elConvSearchClear.hidden = !query;
				if (query) {
					convos = convos.filter(function(c) {
						return (c.title || '').toLowerCase().indexOf(query) !== -1;
					});
				}

				elList.innerHTML = '';

				if (!convos.length) {
					var empty = document.createElement('div');
					empty.className = 'chat-conv-empty-search';
					empty.textContent = query ? 'No chats found for "' + query + '"' : 'No conversations yet';
					elList.appendChild(empty);
					return;
				}

				convos.forEach(function(c) {
					var item = document.createElement('div');
					item.className = 'chat-conv-item' + (c.id === currentConversationId ? ' active' : '');
					item.dataset.id = c.id;
					var titleSpan = document.createElement('span');
					titleSpan.className = 'chat-conv-title'; titleSpan.textContent = c.title;
					item.appendChild(titleSpan);
					var delBtn = document.createElement('button');
					delBtn.className = 'chat-conv-delete'; delBtn.innerHTML = '&times;'; delBtn.title = 'Delete';
					delBtn.addEventListener('click', function(e) {
						e.stopPropagation();
						if (!confirm('Delete this conversation?')) return;
						deleteConvoLocal(c.id);
						if (currentConversationId === c.id) {
							currentConversationId = null; elTitle.textContent = 'New Chat'; renderEmptyState();
						}
						loadConversations();
					});
					item.appendChild(delBtn);
					item.addEventListener('click', function() { openConversation(c.id, c.title); closeSidebar(); });
					elList.appendChild(item);
				});
			}

			function setActiveConversationItem(id) {
				Array.prototype.forEach.call(elList.querySelectorAll('.chat-conv-item'), function(el) {
					el.classList.toggle('active', el.dataset.id === id);
				});
			}

			function updateSendButtonForCurrentConvo() {
				setSendButtonState(activeGenerations[currentConversationId] ? 'stop' : 'send');
			}

			function openConversation(id, title) {
				currentConversationId = id;
				elTitle.textContent = title || 'Chat';
				setActiveConversationItem(id);
				renderEmptyState();
				var convo = getConvo(id);
				if (convo && convo.messages && convo.messages.length) {
					elMessages.innerHTML = '';
					var idsBackfilled = false;
					convo.messages.forEach(function(m) {
						if (m.role === 'assistant' && m.model && !m.id) {
							m.id = newId();
							idsBackfilled = true;
						}
						addMessageBubble(m.role, m.text || '', m.attachments || [], m.model, m.id, m.feedback);
					});
					if (idsBackfilled) upsertConvo(convo);
				}
				// If this conversation still has a reply generating in the
				// background (e.g. it was started, then the user switched
				// away before it finished), re-attach the live bubbles so
				// the in-progress reply keeps streaming into view instead
				// of looking like it vanished.
				var gen = activeGenerations[id];
				if (gen) {
					var emptyState = elMessages.querySelector('.chat-empty-state');
					if (emptyState) emptyState.remove();
					elMessages.appendChild(gen.userBubbleEl);
					elMessages.appendChild(gen.assistantBubble);
					elMessages.scrollTop = elMessages.scrollHeight;
				}
				updateSendButtonForCurrentConvo();
			}

			function startNewChat() {
				currentConversationId = null;
				elTitle.textContent = 'New Chat';
				setActiveConversationItem(null);
				renderEmptyState();
				updateSendButtonForCurrentConvo();
			}

			// Toggles the single send/stop button between its two states.
			// 'stop' is shown the whole time a reply is streaming in, so
			// the user can cancel a long/complex generation whenever they
			// want instead of being stuck waiting.
			function setSendButtonState(state) {
				var isStop = state === 'stop';
				elSend.classList.toggle('is-stop', isStop);
				elSend.title = isStop ? 'Stop generating' : 'Send';
				elSend.querySelector('.chat-icon-send').style.display = isStop ? 'none' : '';
				elSend.querySelector('.chat-icon-stop').style.display = isStop ? '' : 'none';
				elSend.disabled = false;
			}

			function stopGeneration() {
				var g = activeGenerations[currentConversationId];
				if (!g) return;
				if (g.abortController) g.abortController.abort();
				if (g.reader) { try { g.reader.cancel(); } catch (e) {} }
			}

			elSend.addEventListener('click', function() {
				if (activeGenerations[currentConversationId]) {
					stopGeneration();
				} else {
					sendMessage();
				}
			});

			function sendMessage() {
				var text = elInput.value.trim();
				var attachmentsToSend = pendingAttachments.filter(function(a) { return !!a.dataUrl; });
				if (!text && !attachmentsToSend.length) return;

				var selectedModel = elModelSelect.value;

				// Make sure we have a local conversation to append to.
				if (!currentConversationId) {
					currentConversationId = newId();
					var now = new Date().toISOString();
					upsertConvo({
						id: currentConversationId,
						title: makeTitle(text || (attachmentsToSend[0] && attachmentsToSend[0].name) || 'New Chat'),
						created_at: now,
						updated_at: now,
						messages: []
					});
					elTitle.textContent = getConvo(currentConversationId).title;
				}
				var convo = getConvo(currentConversationId);
				if (!convo) {
					// Conversation vanished (e.g. deleted in another tab) — start fresh.
					currentConversationId = null;
					return sendMessage();
				}

				// Snapshot which conversation this send belongs to. The user
				// may switch to a different chat while the reply is still
				// streaming in — currentConversationId will change, but this
				// generation must keep targeting the conversation it was
				// actually started from (both for saving the reply, and for
				// telling the server which conversation it's replying to).
				var genConversationId = currentConversationId;
				if (activeGenerations[genConversationId]) return; // already generating here

				// Assigned now (not at persist time) so the feedback bar
				// attached to the live-streaming bubble below can reference
				// the same id that ends up saved with the message.
				var assistantMsgId = newId();

				// Everything already in this conversation becomes the history
				// sent to the API. Older attachments are dropped from the
				// resend to keep the request small — only this turn's
				// attachments are sent (matches what the model actually needs
				// to answer the latest message).
				var historyForApi = convo.messages.map(function(m) {
					return { role: m.role, text: m.text || '', attachments: [] };
				});

				var userBubbleEl = addMessageBubble('user', text, attachmentsToSend.map(function(a) {
					return { name: a.name, type: a.type, isImage: a.isImage, dataUrl: a.dataUrl };
				}));

				elInput.value = '';
				elInput.style.height = 'auto';
				updateSendButtonForCurrentConvo();

				var apiAttachments = attachmentsToSend.map(function(a) {
					return { name: a.name, type: a.type, size: a.size, data: a.dataUrl };
				});
				var localAttachments = attachmentsToSend.map(function(a) {
					return { name: a.name, type: a.type, isImage: a.isImage, dataUrl: a.dataUrl };
				});
				pendingAttachments = [];
				renderAttachPreview();

				var emptyState = elMessages.querySelector('.chat-empty-state');
				if (emptyState) emptyState.remove();

				var assistantBubble = document.createElement('div');
				assistantBubble.className = 'chat-msg assistant';

				var avatar = makeAssistantAvatar(selectedModel);
				assistantBubble.appendChild(avatar);

				var contentWrap = document.createElement('div');
				contentWrap.className = 'chat-msg-content';

				var textDiv = document.createElement('div');
				textDiv.className = 'chat-msg-text';
				contentWrap.appendChild(textDiv);

				var thinkingEl   = null;
				var thinkingBody = null;
				var thinkingText = '';

				// Claude-style "Thinking… / Editing…" pill shown above the
				// reply while the model is actively streaming a fenced code
				// block, so the user gets the same visual cue Claude gives
				// while it writes out full code — a spinning icon plus
				// shimmering text that alternates between the two labels
				// until the code block closes.
				var codeStatusEl       = null;
				var codeStatusTextEl   = null;
				var codeStatusInterval = null;
				var codeStatusPhrases  = ['Writing code', 'Editing', 'Reviewing'];
				var codeStatusPhraseIx = 0;

				assistantBubble.appendChild(contentWrap);
				elMessages.appendChild(assistantBubble);

				// Track this generation against the conversation it actually
				// belongs to (genConversationId), not whichever conversation
				// happens to be open later. This is what lets openConversation()
				// re-attach a still-streaming reply if the user switches away
				// and back, and lets the send/stop button + persistTurn() below
				// target the right chat even after the user has navigated off it.
				activeGenerations[genConversationId] = {
					abortController: null,
					reader: null,
					userBubbleEl: userBubbleEl,
					assistantBubble: assistantBubble
				};
				updateSendButtonForCurrentConvo();

				var cursor = document.createElement('span');
				cursor.className = 'chat-cursor';
				// The streamed reply is written into this single text node
				// instead of being re-parsed as HTML on every token — see
				// the batched render pipeline below.
				var streamTextNode = document.createTextNode('');
				textDiv.appendChild(streamTextNode);
				textDiv.appendChild(cursor);
				elMessages.scrollTop = elMessages.scrollHeight;

				var fullText = '';

				// ── Batched rendering ────────────────────────────────────
				// A fast model can emit far more than 60 tokens/sec. The
				// old code re-escaped the *entire* accumulated reply and
				// rebuilt textDiv's innerHTML on every single token, plus
				// forced a synchronous scroll reflow each time — cost grows
				// with the reply length, so a long code block made every
				// subsequent token more expensive than the last and the
				// tab would freeze. Instead we just append to plain JS
				// strings as tokens arrive (cheap) and flush the DOM at
				// most once per animation frame, however many tokens
				// landed in between.
				var streamEnded      = false;
				var renderScheduled  = false;
				var scrollNeeded     = false;
				var thinkingDirty    = false;

				function flushFrame() {
					renderScheduled = false;
					if (streamEnded) return; // final markdown render already replaced the DOM
					if (streamTextNode.nodeValue !== fullText) {
						streamTextNode.nodeValue = fullText;
					}
					if (thinkingDirty && thinkingBody) {
						thinkingBody.textContent = thinkingText;
						thinkingDirty = false;
					}
					if (scrollNeeded) {
						if (genConversationId === currentConversationId) {
							elMessages.scrollTop = elMessages.scrollHeight;
						}
						scrollNeeded = false;
					}
				}
				function scheduleFrame() {
					if (renderScheduled) return;
					renderScheduled = true;
					requestAnimationFrame(flushFrame);
				}

				function ensureThinkingBlock() {
					if (thinkingEl) return;
					thinkingEl = document.createElement('details');
					thinkingEl.className = 'chat-thinking';
					var summary = document.createElement('summary');
					summary.textContent = 'Thinking…';
					thinkingBody = document.createElement('div');
					thinkingBody.className = 'chat-thinking-body';
					thinkingEl.appendChild(summary);
					thinkingEl.appendChild(thinkingBody);
					contentWrap.insertBefore(thinkingEl, textDiv);
				}

				function ensureCodeStatus() {
					if (codeStatusEl) return;
					codeStatusEl = document.createElement('div');
					codeStatusEl.className = 'chat-code-status';
					codeStatusEl.innerHTML =
						'<svg class="chat-code-status-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">' +
							'<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-dasharray="34 100"></circle>' +
						'</svg>' +
						'<span class="chat-code-status-text">Writing code</span>';
					contentWrap.insertBefore(codeStatusEl, textDiv);
					codeStatusTextEl = codeStatusEl.querySelector('.chat-code-status-text');
					codeStatusPhraseIx = 0;
					codeStatusInterval = setInterval(function() {
						codeStatusPhraseIx = (codeStatusPhraseIx + 1) % codeStatusPhrases.length;
						if (codeStatusTextEl) codeStatusTextEl.textContent = codeStatusPhrases[codeStatusPhraseIx];
					}, 1100);
					scrollNeeded = true;
					scheduleFrame();
				}

				function removeCodeStatus() {
					if (codeStatusInterval) { clearInterval(codeStatusInterval); codeStatusInterval = null; }
					if (codeStatusEl) { codeStatusEl.remove(); codeStatusEl = null; codeStatusTextEl = null; }
				}

				function persistTurn(replyText) {
					var c = getConvo(genConversationId);
					if (!c) return;
					c.messages.push({ role: 'user', text: text, attachments: localAttachments });
					c.messages.push({ role: 'assistant', text: replyText, attachments: [], model: selectedModel, id: assistantMsgId, feedback: null });
					c.updated_at = new Date().toISOString();
					upsertConvo(c);
					loadConversations();
				}

				// No client-side time limit is imposed on the request itself
				// — fetch() has no timeout by default and none is added
				// here, so a long/complex reply (large code files, deep
				// reasoning, etc.) is free to keep streaming for as long as
				// it takes. The only way this ends early is the user
				// clicking Stop (or leaving the page), via the abort
				// controller below.
				var abortController = new AbortController();
				activeGenerations[genConversationId].abortController = abortController;
				var wasStopped = false;

				function finishGenerating() {
					delete activeGenerations[genConversationId];
					// Only touch the send button / steal keyboard focus if the
					// user is still looking at this conversation. If they've
					// switched away, this generation finishing in the background
					// shouldn't hijack whatever chat is now on screen.
					if (genConversationId === currentConversationId) {
						setSendButtonState('send');
						elInput.focus();
					}
				}

				fetch(restUrl + '/chat-stream', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'X-WP-Nonce': nonce,
						'X-MLP-Guest-Token': guestToken,
						'X-MLP-Guest-Username': identity ? identity.username : ''
					},
					body: JSON.stringify({
						message: text, model: selectedModel,
						conversation_id: currentConversationId,
						attachments: apiAttachments,
						history: historyForApi
					}),
					signal: abortController.signal
				}).then(function(response) {
					if (!response.ok) {
						return response.json().then(function(err) { throw new Error(err.message || 'Request failed'); });
					}
					var reader    = response.body.getReader();
					var decoder   = new TextDecoder();
					var sseBuffer = '';
					activeGenerations[genConversationId].reader = reader;

					function readChunk() {
						return reader.read().then(function(result) {
							if (result.done) return;
							sseBuffer += decoder.decode(result.value, { stream: true });
							var lines = sseBuffer.split('\n');
							sseBuffer = lines.pop();
							lines.forEach(function(line) {
								line = line.trim();
								if (line.indexOf('data: ') !== 0) return;
								try {
									var data = JSON.parse(line.slice(6));
									if (data.error) {
										streamEnded = true;
										cursor.remove();
										removeCodeStatus();
										if (!fullText) {
											var errMsg = data.error.indexOf('quota') !== -1
												? '⚠️ ' + data.error
												: 'Error: ' + data.error;
											var isCookieErr = data.error.indexOf('Cookie check failed') !== -1 || data.error.indexOf('cookie') !== -1;
											if (isCookieErr) {
												textDiv.innerHTML = '<div style="color:#d63638;font-weight:600;margin-bottom:10px;">' + escapeHtml(errMsg) + '</div>' +
													'<button class="chat-reload-btn" type="button" onclick="window.location.reload();">&#x21bb; Reload the site</button>';
											} else {
												textDiv.innerHTML = escapeHtml(errMsg);
											}
										}
										finishGenerating();
										return;
									}
									if (data.thinking) {
										ensureThinkingBlock();
										thinkingText += data.thinking;
										thinkingDirty = true;
										scrollNeeded = true;
										scheduleFrame();
									}
									if (data.token) {
										fullText += data.token;
										// An odd number of ``` fences means we're
										// currently inside an unclosed code block —
										// show the animated status pill for as long
										// as that's true, hide it again once the
										// fence closes (or never show it for plain
										// prose replies).
										var fenceCount = (fullText.match(/```/g) || []).length;
										if (fenceCount % 2 === 1) {
											ensureCodeStatus();
										} else if (codeStatusEl) {
											removeCodeStatus();
										}
										scrollNeeded = true;
										scheduleFrame();
									}
									if (data.done) {
										streamEnded = true; // stop any in-flight rAF from touching the (about to be replaced) DOM
										cursor.remove();
										removeCodeStatus();
										if (thinkingEl) {
											var smry = thinkingEl.querySelector('summary');
											if (smry) smry.textContent = 'Thinking';
										}
										textDiv.innerHTML = renderMarkdown(fullText);
										contentWrap.appendChild(makeFeedbackBar(selectedModel, assistantMsgId, null));
										persistTurn(fullText);
										finishGenerating();
									}
								} catch(e) {}
							});
							return readChunk();
						});
					}
					return readChunk();
				}).catch(function(err) {
					streamEnded = true;
					cursor.remove();
					removeCodeStatus();
					wasStopped = err && (err.name === 'AbortError');
					if (wasStopped) {
						// User hit Stop mid-stream — keep whatever text has
						// already arrived rather than discarding it, and
						// save the partial reply just like a finished one.
						if (fullText) {
							textDiv.innerHTML = renderMarkdown(fullText) + '<div class="chat-stopped-note">Stopped by user</div>';
							contentWrap.appendChild(makeFeedbackBar(selectedModel, assistantMsgId, null));
							persistTurn(fullText);
						} else {
							textDiv.innerHTML = '<div class="chat-stopped-note">Stopped by user</div>';
						}
					} else if (!fullText) {
						textDiv.innerHTML = escapeHtml('Error: ' + err.message);
					}
					finishGenerating();
				});
			}

			function closeAttachMenu() {
				elAttachMenu.hidden = true;
				elAttachBtn.setAttribute('aria-expanded', 'false');
			}
			function openAttachMenu() {
				elAttachMenu.hidden = false;
				elAttachBtn.setAttribute('aria-expanded', 'true');
			}
			elAttachBtn.addEventListener('click', function(e) {
				e.stopPropagation();
				if (elAttachMenu.hidden) openAttachMenu(); else closeAttachMenu();
			});
			elAttachMenuImage.addEventListener('click', function() {
				closeAttachMenu();
				if (!currentImagesOk) { alert("This AI Model doesn't support images."); return; }
				elImageInput.click();
			});
			elAttachMenuFile.addEventListener('click', function() {
				closeAttachMenu();
				elFileInput.click();
			});
			document.addEventListener('click', function(e) {
				if (!elAttachMenu.hidden && !elAttachMenu.contains(e.target) && e.target !== elAttachBtn) closeAttachMenu();
			});
			document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeAttachMenu(); });
			elImageInput.addEventListener('change', function() { addFiles(this.files); this.value = ''; });
			elFileInput.addEventListener('change', function() { addFiles(this.files); this.value = ''; });

			var dragCounter = 0;
			elInputWrap.addEventListener('dragover',  function(e) { e.preventDefault(); });
			elInputWrap.addEventListener('dragenter', function(e) { e.preventDefault(); dragCounter++; elInputWrap.classList.add('drag-over'); });
			elInputWrap.addEventListener('dragleave', function(e) { e.preventDefault(); dragCounter = Math.max(0, dragCounter - 1); if (!dragCounter) elInputWrap.classList.remove('drag-over'); });
			elInputWrap.addEventListener('drop',      function(e) { e.preventDefault(); dragCounter = 0; elInputWrap.classList.remove('drag-over'); if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files); });

			elInput.addEventListener('paste', function(e) {
				var items = (e.clipboardData || {}).items || [];
				var pastedFiles = [];
				for (var i = 0; i < items.length; i++) {
					if (items[i].kind === 'file') { var f = items[i].getAsFile(); if (f) pastedFiles.push(f); }
				}
				if (pastedFiles.length) addFiles(pastedFiles);
			});

			elInput.addEventListener('keydown', function(e) {
				if (e.key === 'Enter' && !e.shiftKey) {
					e.preventDefault();
					if (!elSend.classList.contains('is-stop')) sendMessage();
				}
			});
			elInput.addEventListener('input', function() {
				elInput.style.height = 'auto';
				elInput.style.height = Math.min(elInput.scrollHeight, 140) + 'px';
			});
			elNewChat.addEventListener('click', function() { showChatView(); startNewChat(); closeSidebar(); });

		// ── New Models popup ─────────────────────────────────────────────
		function openNewModelsModal() { elNewModelsModal.removeAttribute('data-hidden'); }
		function closeNewModelsModal() { elNewModelsModal.setAttribute('data-hidden', '1'); }

		if (elNewModelsBtn) {
			elNewModelsBtn.addEventListener('click', function() { openNewModelsModal(); });
		}
		if (elNewModelsClose) {
			elNewModelsClose.addEventListener('click', closeNewModelsModal);
		}
		elNewModelsModal.addEventListener('click', function(e) {
			if (e.target === elNewModelsModal) closeNewModelsModal();
		});
		Array.prototype.forEach.call(elNewModelsModal.querySelectorAll('.chat-new-models-start-btn'), function(btn) {
			btn.addEventListener('click', function() {
				var modelId = btn.getAttribute('data-model-id');
				if (modelId) {
					elModelSelect.value = modelId;
					updateModelUI();
				}
				closeNewModelsModal();
				showChatView();
				startNewChat();
				closeSidebar();
			});
		});

			// Sidebar controls
			document.getElementById('chat-code-sidebar-close').addEventListener('click', closeCodeSidebar);
			document.getElementById('chat-code-sidebar-download').addEventListener('click', downloadCurrentFile);

			// Copy buttons
			attachCopyListeners();

			// Sidebar chat search
			elConvSearch.addEventListener('input', function() { loadConversations(); });
			elConvSearchClear.addEventListener('click', function() {
				elConvSearch.value = '';
				loadConversations();
				elConvSearch.focus();
			});

			// Sidebar logo click -> New Chat
			var elSidebarLogo = document.querySelector('.chat-sidebar-logo');
			if (elSidebarLogo) {
				elSidebarLogo.title = 'Start new chat';
				elSidebarLogo.style.cursor = 'pointer';
				elSidebarLogo.addEventListener('click', function() {
					showChatView();
					startNewChat();
					closeSidebar();
				});
			}

			// ── Mobile off-canvas sidebar ────────────────────────────────────
			// Below 768px the sidebar becomes a slide-in drawer opened via the
			// hamburger button in the header; above that width these are
			// harmless no-ops since the CSS keeps the sidebar always visible.
			function openSidebar() {
				elSidebar.classList.add('open');
				elSidebarBackdrop.classList.add('open');
				if (elMenuBtn) elMenuBtn.setAttribute('aria-expanded', 'true');
				if (elAdminMenuBtn) elAdminMenuBtn.setAttribute('aria-expanded', 'true');
			}
			function closeSidebar() {
				elSidebar.classList.remove('open');
				elSidebarBackdrop.classList.remove('open');
				if (elMenuBtn) elMenuBtn.setAttribute('aria-expanded', 'false');
				if (elAdminMenuBtn) elAdminMenuBtn.setAttribute('aria-expanded', 'false');
			}
			function toggleSidebar() {
				if (elSidebar.classList.contains('open')) closeSidebar(); else openSidebar();
			}
			if (elMenuBtn) elMenuBtn.addEventListener('click', toggleSidebar);
			if (elAdminMenuBtn) elAdminMenuBtn.addEventListener('click', toggleSidebar);
			elSidebarBackdrop.addEventListener('click', closeSidebar);

			// ── Administration room (manage_options users only) ─────────────
			var STATE_LABELS = {
				online: 'Online', rate_limited: 'Rate Limited', blocked: 'Blocked',
				error: 'Error', offline: 'Offline', disabled: 'Disabled', unknown: 'Unknown'
			};

			function showChatView() {
				if (elAdminView) elAdminView.setAttribute('data-hidden', '1');
				elChatView.style.display = '';
				if (elAdminRoomBtn) elAdminRoomBtn.classList.remove('active');
			}
			function showAdminView() {
				elChatView.style.display = 'none';
				elAdminView.setAttribute('data-hidden', '0');
				elAdminRoomBtn.classList.add('active');
				refreshAdminData();
			}

			function renderAdminStats(data) {
				elAdminStats.innerHTML = '';
				var cards = [
					{ label: 'AI Status', value: data.disabled ? 'Disabled' : 'Enabled' },
					{ label: 'Total Requests', value: data.total_requests },
					{ label: 'New Users Today', value: data.new_today },
					{ label: 'All Users', value: data.all_users }
				];
				cards.forEach(function(c) {
					var card = document.createElement('div');
					card.className = 'chat-admin-stat-card';
					card.innerHTML = '<div class="chat-admin-stat-label"></div><div class="chat-admin-stat-value"></div>';
					card.querySelector('.chat-admin-stat-label').textContent = c.label;
					card.querySelector('.chat-admin-stat-value').textContent = c.value;
					elAdminStats.appendChild(card);
				});
			}

			function renderAdminModels(data) {
				elAdminModels.innerHTML = '';
				(data.models || []).forEach(function(m) {
					var row = document.createElement('div');
					row.className = 'chat-admin-model-row';

					var left = document.createElement('div');
					left.innerHTML = '<div class="chat-admin-model-name"></div><div class="chat-admin-model-meta"></div>';
					left.querySelector('.chat-admin-model-name').textContent = m.label;
					left.querySelector('.chat-admin-model-meta').textContent = m.message || (m.configured ? '' : 'API key not configured');
					row.appendChild(left);

					var status = document.createElement('div');
					status.className = 'chat-admin-model-status chat-status-' + m.state;
					status.innerHTML = '<span class="chat-status-dot"></span><span></span>';
					status.querySelector('span:last-child').textContent = STATE_LABELS[m.state] || m.state;
					row.appendChild(status);

					var votes = document.createElement('div');
					votes.className = 'chat-admin-model-votes';
					votes.innerHTML =
						'<span class="chat-admin-model-vote likes">' + likeSvg() + '<span></span></span>' +
						'<span class="chat-admin-model-vote dislikes">' + dislikeSvg() + '<span></span></span>';
					votes.querySelector('.likes span').textContent = m.likes || 0;
					votes.querySelector('.dislikes span').textContent = m.dislikes || 0;
					row.appendChild(votes);

					var toggleBtn = document.createElement('button');
					toggleBtn.type = 'button';
					toggleBtn.className = 'chat-admin-model-toggle' + (m.disabled ? ' is-disabled' : '');
					toggleBtn.textContent = m.disabled ? 'Enable' : 'Disable';
					toggleBtn.addEventListener('click', function() { toggleModel(m.id); });
					row.appendChild(toggleBtn);

					elAdminModels.appendChild(row);
				});
			}

			function renderAdminData(data) {
				renderAdminStats(data);
				renderAdminModels(data);
				elAdminToggleGlobalBtn.textContent = data.disabled ? 'Re-enable AI Chat' : 'Disable AI Chat';
				elAdminToggleGlobalBtn.classList.toggle('is-disabled', !data.disabled);
				// Keep the visitor-facing UI's disabled state and model list in sync too.
				applyDisabledState(!!data.disabled);
				disabledModelIds = (data.models || []).filter(function(m) { return m.disabled; }).map(function(m) { return m.id; });
				applyModelDisabledOptions();
			}

			function refreshAdminData() {
				apiFetch('/admin/status').then(renderAdminData).catch(function() {});
			}

			function toggleGlobal() {
				elAdminToggleGlobalBtn.disabled = true;
				apiFetch('/admin/toggle-global', { method: 'POST' })
					.then(renderAdminData)
					.finally(function() { elAdminToggleGlobalBtn.disabled = false; });
			}

			function toggleModel(modelId) {
				apiFetch('/admin/toggle-model', {
					method: 'POST',
					body: JSON.stringify({ model_id: modelId })
				}).then(renderAdminData);
			}

			if (elAdminRoomBtn) {
				elAdminRoomBtn.addEventListener('click', function() { showAdminView(); closeSidebar(); });
				elAdminRefreshBtn.addEventListener('click', refreshAdminData);
				elAdminToggleGlobalBtn.addEventListener('click', toggleGlobal);
			}

			// ── Bootstrapping ────────────────────────────────────────────────
			// Everything that talks to the server waits until we know who's
			// asking: for logged-in users that's immediate; for guests, the
			// username modal has to be completed first.
			var chatStarted = false;
			function initChatApp() {
				if (chatStarted) return;
				chatStarted = true;
				checkAiStatus();
				updateModelUI();
				attachCopyListeners();
				pruneStaleConversations().then(loadConversations, loadConversations);
			}

			<?php if ( $user_id ) : ?>
			// Logged-in WP user — no name prompt needed.
			initChatApp();
			<?php else : ?>
			if (identity && identity.username) {
				initChatApp();
			} else {
				showUsernameModal();
			}
			<?php endif; ?>
		})();
		</script>
		<?php
		return ob_get_clean();
	}
}

MLP_AI_Chat::instance();
