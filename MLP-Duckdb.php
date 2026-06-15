<?php
/**
 * Plugin Name: MLP DuckDB Editor
 * Plugin URI:  https://pterocos.eu.org
 * Description: DB SQL
 * Version:     1.0.0
 * Author:      Pterocos
 * License:     GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 5.0
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

/* ── Load AI chat handler ─────────────────────────────────────────────────── */
$_mlp_duckdb_ai_file = plugin_dir_path( __FILE__ ) . 'mlp-ai-chat-duckdb.php';
if ( file_exists( $_mlp_duckdb_ai_file ) ) {
    require_once $_mlp_duckdb_ai_file;
}
unset( $_mlp_duckdb_ai_file );

class MLP_DuckDB {

    /* ── Storage key prefix for shared DuckDB projects ─────────────────── */
    const SHARE_PREFIX = 'mlp_duckdb_share_';

    /* ── Rate-limit: 5 publishes per 10 minutes per IP ─────────────────── */
    const PUB_MAX    = 5;
    const PUB_WINDOW = 600; // 10 minutes

    public static function init() {
        add_action( 'wp_head',   [ __CLASS__, 'output_styles'  ], 98 );
        add_action( 'wp_footer', [ __CLASS__, 'output_scripts' ], 5  );

        if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
            add_action( 'wp_ajax_mlp_duckdb_publish_project',        [ __CLASS__, 'ajax_publish' ] );
            add_action( 'wp_ajax_nopriv_mlp_duckdb_publish_project', [ __CLASS__, 'ajax_publish' ] );

            add_action( 'wp_ajax_mlp_duckdb_get_projects',        [ __CLASS__, 'ajax_get_projects' ] );
            add_action( 'wp_ajax_nopriv_mlp_duckdb_get_projects', [ __CLASS__, 'ajax_get_projects' ] );

            add_action( 'wp_ajax_mlp_duckdb_get_project',        [ __CLASS__, 'ajax_get_project' ] );
            add_action( 'wp_ajax_nopriv_mlp_duckdb_get_project', [ __CLASS__, 'ajax_get_project' ] );

            add_action( 'wp_ajax_mlp_duckdb_react',        [ __CLASS__, 'ajax_react' ] );
            add_action( 'wp_ajax_nopriv_mlp_duckdb_react', [ __CLASS__, 'ajax_react' ] );
        }
    }

    /* ── Client IP helper ───────────────────────────────────────────────── */
    private static function get_client_ip() {
        foreach ( [ 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' ] as $h ) {
            if ( ! empty( $_SERVER[ $h ] ) ) {
                $v = trim( explode( ',', $_SERVER[ $h ] )[0] );
                if ( filter_var( $v, FILTER_VALIDATE_IP ) ) { return $v; }
            }
        }
        return '0.0.0.0';
    }

    /* ─────────────────────────────────────────────────────────────────────
     *  AJAX: Publish a DuckDB project
     * ───────────────────────────────────────────────────────────────────── */
    public static function ajax_publish() {
        if ( ! check_ajax_referer( 'mlp_duckdb_nonce', 'nonce', false ) ) {
            wp_send_json_error( [ 'message' => 'Invalid request.' ], 403 );
        }

        $ip       = self::get_client_ip();
        $rl_key   = 'mlp_duckdb_pub_rl_' . md5( $ip );
        $rl_data  = get_transient( $rl_key );
        if ( ! is_array( $rl_data ) ) {
            $rl_data = [ 'count' => 0, 'reset_at' => time() + self::PUB_WINDOW ];
        }
        if ( $rl_data['reset_at'] <= time() ) {
            $rl_data = [ 'count' => 0, 'reset_at' => time() + self::PUB_WINDOW ];
        }
        if ( $rl_data['count'] >= self::PUB_MAX ) {
            wp_send_json_error( [
                'message' => 'Too many publishes. Please wait 10 minutes before publishing again.',
                'rate_limited' => true,
            ], 429 );
            return;
        }
        $rl_data['count']++;
        set_transient( $rl_key, $rl_data, max( 60, $rl_data['reset_at'] - time() ) );

        $name        = isset( $_POST['name'] )        ? sanitize_text_field( wp_unslash( $_POST['name'] ) )        : 'Untitled DuckDB Project';
        $description = isset( $_POST['description'] ) ? sanitize_textarea_field( wp_unslash( $_POST['description'] ) ) : '';
        $author      = isset( $_POST['author'] )      ? sanitize_text_field( wp_unslash( $_POST['author'] ) )      : 'Anonymous';
        $sql         = isset( $_POST['sql'] )         ? wp_unslash( $_POST['sql'] )                               : '';

        if ( mb_strlen( $name )        > 200  ) { $name        = mb_substr( $name, 0, 200 ); }
        if ( mb_strlen( $description ) > 2000 ) { $description = mb_substr( $description, 0, 2000 ); }
        if ( mb_strlen( $author )      > 100  ) { $author      = mb_substr( $author, 0, 100 ); }
        if ( mb_strlen( $sql )         > 200000 ) {
            wp_send_json_error( [ 'message' => 'SQL is too long (max 200 KB).' ], 400 );
            return;
        }
        if ( trim( $sql ) === '' ) {
            wp_send_json_error( [ 'message' => 'Cannot publish an empty query.' ], 400 );
            return;
        }

        $existing_token = isset( $_POST['existing_token'] ) ? sanitize_key( wp_unslash( $_POST['existing_token'] ) ) : '';
        $token = $existing_token ?: strtolower( wp_generate_password( 22, false, false ) );

        $record = [
            'created'     => ( $existing_token ? ( get_option( self::SHARE_PREFIX . $existing_token, [] )['created'] ?? time() ) : time() ),
            'updated'     => time(),
            'name'        => $name,
            'description' => $description,
            'author'      => $author,
            'sql'         => $sql,
            'ip_hash'     => md5( $ip ),
            'views'       => ( $existing_token ? ( get_option( self::SHARE_PREFIX . $existing_token, [] )['views'] ?? 0 ) : 0 ),
            'likes'       => ( $existing_token ? ( get_option( self::SHARE_PREFIX . $existing_token, [] )['likes'] ?? 0 ) : 0 ),
        ];

        update_option( self::SHARE_PREFIX . $token, $record, false );

        wp_send_json_success( [
            'token'     => $token,
            'share_url' => home_url( '/?mlp_duckdb_share=' . $token ),
        ] );
    }

    /* ─────────────────────────────────────────────────────────────────────
     *  AJAX: Get paginated shared projects
     * ───────────────────────────────────────────────────────────────────── */
    public static function ajax_get_projects() {
        $page     = max( 1, intval( $_REQUEST['page'] ?? 1 ) );
        $per_page = 12;
        $search   = isset( $_REQUEST['search'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['search'] ) ) : '';

        $cache_key = 'mlp_duckdb_gallery_p' . $page . '_s' . md5( $search );
        $cached    = get_transient( $cache_key );
        if ( $cached !== false ) {
            wp_send_json_success( $cached );
            return;
        }

        global $wpdb;
        $rows = $wpdb->get_results(
            "SELECT option_name, option_value FROM {$wpdb->options}
             WHERE option_name LIKE 'mlp_duckdb_share_%'
             ORDER BY option_id DESC",
            ARRAY_A
        );

        $projects = [];
        foreach ( $rows as $row ) {
            $token  = substr( $row['option_name'], strlen( self::SHARE_PREFIX ) );
            $record = maybe_unserialize( $row['option_value'] );
            if ( ! is_array( $record ) || ! empty( $record['admin_deleted'] ) ) { continue; }
            if ( $search !== '' ) {
                $haystack = strtolower( ( $record['name'] ?? '' ) . ' ' . ( $record['author'] ?? '' ) . ' ' . ( $record['description'] ?? '' ) );
                if ( strpos( $haystack, strtolower( $search ) ) === false ) { continue; }
            }
            $projects[] = [
                'token'       => $token,
                'name'        => $record['name']        ?? 'Untitled',
                'author'      => $record['author']      ?? 'Anonymous',
                'description' => $record['description'] ?? '',
                'sql'         => mb_substr( $record['sql'] ?? '', 0, 1000 ),
                'views'       => intval( $record['views'] ?? 0 ),
                'likes'       => intval( $record['likes'] ?? 0 ),
                'created'     => $record['created']     ?? 0,
                'share_url'   => home_url( '/?mlp_duckdb_share=' . $token ),
            ];
        }

        $total       = count( $projects );
        $total_pages = max( 1, (int) ceil( $total / $per_page ) );
        $page        = min( $page, $total_pages );
        $items       = array_slice( $projects, ( $page - 1 ) * $per_page, $per_page );

        $result = [ 'projects' => $items, 'total' => $total, 'total_pages' => $total_pages, 'page' => $page ];
        set_transient( $cache_key, $result, 60 );
        wp_send_json_success( $result );
    }

    /* ─────────────────────────────────────────────────────────────────────
     *  AJAX: Get a single shared project by token
     * ───────────────────────────────────────────────────────────────────── */
    public static function ajax_get_project() {
        $token = isset( $_REQUEST['token'] ) ? sanitize_key( wp_unslash( $_REQUEST['token'] ) ) : '';
        if ( ! $token ) {
            wp_send_json_error( [ 'message' => 'Missing token.' ], 400 );
        }
        $record = get_option( self::SHARE_PREFIX . $token, null );
        if ( ! is_array( $record ) ) {
            wp_send_json_error( [ 'message' => 'Project not found.' ], 404 );
        }
        if ( ! empty( $record['admin_deleted'] ) ) {
            wp_send_json_error( [ 'message' => 'This project has been removed.' ], 410 );
        }

        /* Deduplicated view count */
        $ip       = self::get_client_ip();
        $dkey     = 'mlp_duckdb_vw_' . $token . '_' . substr( md5( $ip ), 0, 12 );
        if ( ! get_transient( $dkey ) ) {
            $record['views'] = intval( $record['views'] ?? 0 ) + 1;
            $record['last_viewed'] = time();
            update_option( self::SHARE_PREFIX . $token, $record, false );
            set_transient( $dkey, 1, 300 );
        }

        wp_send_json_success( [
            'token'       => $token,
            'name'        => $record['name']        ?? 'Untitled',
            'author'      => $record['author']      ?? 'Anonymous',
            'description' => $record['description'] ?? '',
            'sql'         => $record['sql']         ?? '',
            'views'       => intval( $record['views'] ?? 0 ),
            'likes'       => intval( $record['likes'] ?? 0 ),
            'created'     => $record['created']     ?? 0,
        ] );
    }

    /* ─────────────────────────────────────────────────────────────────────
     *  AJAX: React (like) to a shared project
     * ───────────────────────────────────────────────────────────────────── */
    public static function ajax_react() {
        $token = isset( $_POST['token'] ) ? sanitize_key( wp_unslash( $_POST['token'] ) ) : '';
        $state = intval( $_POST['state'] ?? 1 );
        if ( ! $token ) { wp_send_json_error( [ 'message' => 'Invalid.' ], 400 ); }

        $record = get_option( self::SHARE_PREFIX . $token, null );
        if ( ! is_array( $record ) ) { wp_send_json_error( [ 'message' => 'Not found.' ], 404 ); }

        $ip      = self::get_client_ip();
        $ip_hash = substr( md5( $ip ), 0, 12 );
        $dkey    = 'mlp_duckdb_lk_' . $token . '_' . $ip_hash;
        $current = intval( $record['likes'] ?? 0 );

        if ( $state && ! get_transient( $dkey ) ) {
            $current++;
            set_transient( $dkey, 1, DAY_IN_SECONDS );
        } elseif ( ! $state && get_transient( $dkey ) ) {
            $current = max( 0, $current - 1 );
            delete_transient( $dkey );
        }

        $record['likes'] = $current;
        update_option( self::SHARE_PREFIX . $token, $record, false );

        wp_send_json_success( [
            'likes'        => $current,
            'viewer_liked' => (bool) get_transient( $dkey ),
        ] );
    }

    /* ─────────────────────────────────────────────────────────────────────
     *  Render the full DuckDB editor page (called from shortcode or template)
     * ───────────────────────────────────────────────────────────────────── */
    public static function render_editor() {
        $nonce    = wp_create_nonce( 'mlp_duckdb_nonce' );
        $ajax_url = admin_url( 'admin-ajax.php' );
        $home_url = esc_url( home_url( '/' ) );
        ?>
        <div id="mlp-duckdb-root" data-nonce="<?php echo esc_attr( $nonce ); ?>" data-ajax="<?php echo esc_attr( $ajax_url ); ?>" data-home="<?php echo esc_attr( $home_url ); ?>">

            <!-- ── Toolbar ──────────────────────────────────────────────── -->
            <div class="mlp-ddb-toolbar">
                <div class="mlp-ddb-toolbar-left">
                    <div class="mlp-ddb-brand">
                        <svg class="mlp-ddb-brand-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2z" fill="#FFBC00"/>
                            <path d="M8 8h8v2H8V8zM8 11h8v2H8v-2zM8 14h5v2H8v-2z" fill="#1e293b"/>
                        </svg>
                        <span class="mlp-ddb-brand-label">DuckDB Editor</span>
                    </div>
                    <button class="mlp-ddb-btn mlp-ddb-btn-run" id="mlp-ddb-run-btn" title="Run query (Ctrl+Enter)">
                        <svg viewBox="0 0 24 24" fill="currentColor" width="14" height="14"><path d="M8 5v14l11-7z"/></svg>
                        Run
                    </button>
                    <button class="mlp-ddb-btn mlp-ddb-btn-clear" id="mlp-ddb-clear-btn" title="Clear editor">Clear</button>
                    <button class="mlp-ddb-btn mlp-ddb-btn-format" id="mlp-ddb-format-btn" title="Format SQL">Format</button>
                    <div class="mlp-ddb-separator"></div>
                    <button class="mlp-ddb-btn mlp-ddb-btn-example" id="mlp-ddb-example-btn" title="Load an example query">Examples ▾</button>
                </div>
                <div class="mlp-ddb-toolbar-right">
                    <button class="mlp-ddb-btn mlp-ddb-btn-publish" id="mlp-ddb-publish-btn">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8M16 6l-4-4-4 4M12 2v13"/></svg>
                        Publish
                    </button>
                    <button class="mlp-ddb-btn mlp-ddb-btn-ai" id="mlp-ddb-ai-toggle-btn">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.22 4.22l2.12 2.12M17.66 17.66l2.12 2.12M4.22 19.78l2.12-2.12M17.66 6.34l2.12-2.12"/></svg>
                        AI Chat
                    </button>
                    <div class="mlp-ddb-status" id="mlp-ddb-status">
                        <span class="mlp-ddb-status-dot" id="mlp-ddb-status-dot"></span>
                        <span id="mlp-ddb-status-text">Initialising…</span>
                    </div>
                </div>
            </div>

            <!-- ── Examples dropdown ────────────────────────────────────── -->
            <div class="mlp-ddb-examples-menu" id="mlp-ddb-examples-menu" style="display:none;">
                <div class="mlp-ddb-ex-item" data-sql="-- Aggregate functions
SELECT
    range(1, 11) AS numbers,
    SUM(n) AS total,
    AVG(n) AS average,
    MIN(n) AS min_val,
    MAX(n) AS max_val
FROM unnest(range(1, 11)) t(n);
">Aggregates</div>
                <div class="mlp-ddb-ex-item" data-sql="-- Window functions
SELECT
    name,
    department,
    salary,
    RANK() OVER (PARTITION BY department ORDER BY salary DESC) AS dept_rank,
    AVG(salary) OVER (PARTITION BY department) AS dept_avg_salary
FROM (VALUES
    ('Alice',   'Engineering', 95000),
    ('Bob',     'Engineering', 85000),
    ('Carol',   'Marketing',   72000),
    ('Dave',    'Marketing',   68000),
    ('Eve',     'Engineering', 90000)
) t(name, department, salary);
">Window Functions</div>
                <div class="mlp-ddb-ex-item" data-sql="-- JSON data handling
SELECT
    json_extract('{\&quot;user\&quot;:{\&quot;name\&quot;:\&quot;Alice\&quot;,\&quot;age\&quot;:30,\&quot;tags\&quot;:[\&quot;admin\&quot;,\&quot;developer\&quot;]}}', '$.user.name') AS name,
    json_extract('{\&quot;user\&quot;:{\&quot;name\&quot;:\&quot;Alice\&quot;,\&quot;age\&quot;:30,\&quot;tags\&quot;:[\&quot;admin\&quot;,\&quot;developer\&quot;]}}', '$.user.age')  AS age,
    json_extract('{\&quot;user\&quot;:{\&quot;name\&quot;:\&quot;Alice\&quot;,\&quot;age\&quot;:30,\&quot;tags\&quot;:[\&quot;admin\&quot;,\&quot;developer\&quot;]}}', '$.user.tags[0]') AS first_tag;
">JSON Handling</div>
                <div class="mlp-ddb-ex-item" data-sql="-- Date & time operations
SELECT
    CURRENT_DATE AS today,
    CURRENT_TIMESTAMP AS now,
    DATE_TRUNC('month', CURRENT_DATE) AS month_start,
    DATE_ADD(CURRENT_DATE, INTERVAL 7 DAY) AS next_week,
    DATEDIFF('day', DATE '2024-01-01', CURRENT_DATE) AS days_since_2024,
    STRFTIME(CURRENT_DATE, '%Y-%m-%d') AS formatted;
">Date & Time</div>
                <div class="mlp-ddb-ex-item" data-sql="-- CTE with recursive data
WITH RECURSIVE fib(n, a, b) AS (
    SELECT 0, 0, 1
    UNION ALL
    SELECT n+1, b, a+b FROM fib WHERE n < 15
)
SELECT n AS position, a AS fibonacci_number
FROM fib
ORDER BY n;
">Recursive CTE</div>
                <div class="mlp-ddb-ex-item" data-sql="-- Create table and insert data
CREATE TABLE employees (
    id      INTEGER PRIMARY KEY,
    name    VARCHAR,
    dept    VARCHAR,
    salary  DECIMAL(10,2),
    hired   DATE
);

INSERT INTO employees VALUES
    (1, 'Alice',  'Engineering', 95000.00, '2021-03-15'),
    (2, 'Bob',    'Engineering', 85000.00, '2022-07-01'),
    (3, 'Carol',  'Marketing',   72000.00, '2020-11-20'),
    (4, 'Dave',   'Marketing',   68000.00, '2023-01-10'),
    (5, 'Eve',    'Engineering', 90000.00, '2021-08-30');

SELECT dept,
       COUNT(*) AS headcount,
       ROUND(AVG(salary), 2) AS avg_salary,
       SUM(salary) AS total_payroll
FROM employees
GROUP BY dept
ORDER BY total_payroll DESC;
">Table CRUD</div>
                <div class="mlp-ddb-ex-item" data-sql="-- DuckDB-specific: range generation & ASOF join
SELECT * FROM range(1, 8) t(day_num),
    LATERAL (SELECT day_num * day_num AS squared, sqrt(day_num) AS root_approx) sub;
">LATERAL & Range</div>
            </div>

            <!-- ── Main workspace ────────────────────────────────────────── -->
            <div class="mlp-ddb-workspace" id="mlp-ddb-workspace">

                <!-- Editor column -->
                <div class="mlp-ddb-editor-col" id="mlp-ddb-editor-col">
                    <div class="mlp-ddb-editor-wrap">
                        <div id="mlp-ddb-monaco" style="width:100%;height:100%;min-height:260px;"></div>
                    </div>
                </div>

                <!-- Results column -->
                <div class="mlp-ddb-results-col" id="mlp-ddb-results-col">
                    <div class="mlp-ddb-results-tabs">
                        <button class="mlp-ddb-rtab active" data-pane="results">Results</button>
                        <button class="mlp-ddb-rtab" data-pane="schema">Schema</button>
                        <button class="mlp-ddb-rtab" data-pane="messages">Messages</button>
                        <span class="mlp-ddb-exec-time" id="mlp-ddb-exec-time"></span>
                    </div>

                    <!-- Results pane -->
                    <div class="mlp-ddb-rpane" id="mlp-ddb-pane-results">
                        <div class="mlp-ddb-results-empty" id="mlp-ddb-results-empty">
                            <svg viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="1.5" width="40" height="40"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v6c0 1.657 4.03 3 9 3s9-1.343 9-3V5"/><path d="M3 11v6c0 1.657 4.03 3 9 3s9-1.343 9-3v-6"/></svg>
                            <p>Run a query to see results here</p>
                        </div>
                        <div class="mlp-ddb-results-table-wrap" id="mlp-ddb-results-table-wrap" style="display:none;">
                            <div class="mlp-ddb-row-count" id="mlp-ddb-row-count"></div>
                            <div class="mlp-ddb-table-scroll">
                                <table class="mlp-ddb-table" id="mlp-ddb-table">
                                    <thead id="mlp-ddb-thead"></thead>
                                    <tbody id="mlp-ddb-tbody"></tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <!-- Schema pane -->
                    <div class="mlp-ddb-rpane" id="mlp-ddb-pane-schema" style="display:none;">
                        <div class="mlp-ddb-schema-empty" id="mlp-ddb-schema-empty">
                            <p>Create a table to see schema here.<br><small>Use CREATE TABLE then run a query.</small></p>
                        </div>
                        <div id="mlp-ddb-schema-list"></div>
                    </div>

                    <!-- Messages pane -->
                    <div class="mlp-ddb-rpane" id="mlp-ddb-pane-messages" style="display:none;">
                        <div id="mlp-ddb-messages-log" class="mlp-ddb-messages-log">
                            <p class="mlp-ddb-msg-info">DuckDB WASM is loading…</p>
                        </div>
                    </div>
                </div>

                <!-- AI Chat sidebar -->
                <div class="mlp-ddb-ai-sidebar" id="mlp-ddb-ai-sidebar" style="display:none;">
                    <div class="mlp-ddb-ai-header">
                        <span>AI Chat</span>
                        <button class="mlp-ddb-ai-close" id="mlp-ddb-ai-close">✕</button>
                    </div>
                    <div class="mlp-ddb-ai-messages" id="mlp-ddb-ai-messages">
                        <div class="mlp-ddb-ai-bubble mlp-ddb-ai-bubble-bot">
                            Hi! I'm your DuckDB AI assistant. Ask me to write queries, explain syntax, debug errors, or optimize your SQL.
                        </div>
                    </div>
                    <div class="mlp-ddb-ai-input-row">
                        <textarea class="mlp-ddb-ai-input" id="mlp-ddb-ai-input" rows="2" placeholder="Ask about DuckDB SQL…"></textarea>
                        <button class="mlp-ddb-ai-send" id="mlp-ddb-ai-send">Send</button>
                    </div>
                </div>
            </div><!-- /.mlp-ddb-workspace -->

            <!-- ── Publish modal ─────────────────────────────────────────── -->
            <div class="mlp-ddb-modal-bg" id="mlp-ddb-publish-modal" style="display:none;">
                <div class="mlp-ddb-modal">
                    <div class="mlp-ddb-modal-header">
                        <h3>Publish DuckDB Project</h3>
                        <button class="mlp-ddb-modal-close" id="mlp-ddb-modal-close">✕</button>
                    </div>
                    <div class="mlp-ddb-modal-body">
                        <label>Project Name <span class="mlp-ddb-req">*</span></label>
                        <input type="text" id="mlp-ddb-pub-name" maxlength="200" placeholder="My DuckDB Analysis" />

                        <label>Description <small>(optional)</small></label>
                        <textarea id="mlp-ddb-pub-desc" maxlength="2000" rows="3" placeholder="What does this query do?"></textarea>

                        <label>Your Name <small>(optional)</small></label>
                        <input type="text" id="mlp-ddb-pub-author" maxlength="100" placeholder="Anonymous" />

                        <div class="mlp-ddb-modal-note">
                            Only your SQL code will be published — no results or data are stored.
                        </div>
                    </div>
                    <div class="mlp-ddb-modal-footer">
                        <button class="mlp-ddb-btn mlp-ddb-btn-cancel" id="mlp-ddb-pub-cancel">Cancel</button>
                        <button class="mlp-ddb-btn mlp-ddb-btn-publish" id="mlp-ddb-pub-confirm">Publish</button>
                    </div>
                    <div class="mlp-ddb-pub-result" id="mlp-ddb-pub-result" style="display:none;"></div>
                </div>
            </div>

        </div><!-- /#mlp-duckdb-root -->

        <!-- ── Shared Projects Gallery ───────────────────────────────────── -->
        <div id="mlp-duckdb-gallery">
            <div class="mlp-ddb-gallery-header">
                <h2 class="mlp-ddb-gallery-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v6c0 1.657 4.03 3 9 3s9-1.343 9-3V5"/><path d="M3 11v6c0 1.657 4.03 3 9 3s9-1.343 9-3v-6"/></svg>
                    Shared DuckDB Projects
                </h2>
                <div class="mlp-ddb-gallery-search-wrap">
                    <input type="text" id="mlp-ddb-gallery-search" placeholder="Search projects…" />
                    <button id="mlp-ddb-gallery-search-btn">Search</button>
                </div>
            </div>
            <div class="mlp-ddb-gallery-grid" id="mlp-ddb-gallery-grid">
                <div class="mlp-ddb-gallery-loading">Loading projects…</div>
            </div>
            <div class="mlp-ddb-gallery-pagination" id="mlp-ddb-gallery-pagination"></div>
        </div>
        <?php
    }

    /* ─────────────────────────────────────────────────────────────────────
     *  Output CSS
     * ───────────────────────────────────────────────────────────────────── */
    public static function output_styles() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) ) { return; }
        $relevant = has_shortcode( $post->post_content, 'mlp_duckdb' )
                 || isset( $_GET['mlp_duckdb_share'] )
                 || class_exists( 'MLP_Projects' );
        if ( ! $relevant ) { return; }
        ?>
        <style id="mlp-duckdb-styles">
        /* ─── Root variables ─── */
        #mlp-duckdb-root, #mlp-duckdb-gallery {
            --ddb-bg: #0f172a;
            --ddb-surface: #1e293b;
            --ddb-surface2: #263347;
            --ddb-border: #334155;
            --ddb-accent: #FFBC00;
            --ddb-accent2: #f59e0b;
            --ddb-text: #e2e8f0;
            --ddb-muted: #94a3b8;
            --ddb-green: #22c55e;
            --ddb-red: #ef4444;
            --ddb-blue: #3b82f6;
            --ddb-radius: 8px;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }

        /* ─── Root layout ─── */
        #mlp-duckdb-root {
            background: var(--ddb-bg);
            border-radius: 12px;
            overflow: hidden;
            margin: 16px 0;
            border: 1px solid var(--ddb-border);
            position: relative;
        }

        /* ─── Toolbar ─── */
        .mlp-ddb-toolbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            padding: 10px 14px;
            background: var(--ddb-surface);
            border-bottom: 1px solid var(--ddb-border);
            flex-wrap: wrap;
        }
        .mlp-ddb-toolbar-left, .mlp-ddb-toolbar-right {
            display: flex;
            align-items: center;
            gap: 6px;
            flex-wrap: wrap;
        }
        .mlp-ddb-brand {
            display: flex;
            align-items: center;
            gap: 7px;
            margin-right: 6px;
        }
        .mlp-ddb-brand-icon { width: 22px; height: 22px; }
        .mlp-ddb-brand-label {
            font-size: 13px;
            font-weight: 700;
            color: var(--ddb-accent);
            letter-spacing: -0.3px;
        }
        .mlp-ddb-separator {
            width: 1px;
            height: 20px;
            background: var(--ddb-border);
            margin: 0 2px;
        }
        .mlp-ddb-btn {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 5px 12px;
            border: 1px solid var(--ddb-border);
            border-radius: 6px;
            background: var(--ddb-surface2);
            color: var(--ddb-text);
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: background .12s, border-color .12s, color .12s;
            white-space: nowrap;
        }
        .mlp-ddb-btn:hover { background: #2d3f55; border-color: #4b6080; }
        .mlp-ddb-btn-run {
            background: var(--ddb-accent);
            border-color: var(--ddb-accent2);
            color: #1e293b;
        }
        .mlp-ddb-btn-run:hover { background: var(--ddb-accent2); }
        .mlp-ddb-btn-publish {
            background: var(--ddb-blue);
            border-color: #2563eb;
            color: #fff;
        }
        .mlp-ddb-btn-publish:hover { background: #2563eb; }
        .mlp-ddb-btn-ai {
            background: #4f46e5;
            border-color: #4338ca;
            color: #fff;
        }
        .mlp-ddb-btn-ai:hover { background: #4338ca; }
        .mlp-ddb-btn-cancel { background: transparent; }

        /* ─── Status indicator ─── */
        .mlp-ddb-status {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 11px;
            color: var(--ddb-muted);
        }
        .mlp-ddb-status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #f59e0b;
            transition: background .3s;
        }
        .mlp-ddb-status-dot.ready { background: var(--ddb-green); }
        .mlp-ddb-status-dot.error { background: var(--ddb-red); }

        /* ─── Examples menu ─── */
        .mlp-ddb-examples-menu {
            position: absolute;
            top: 48px;
            left: 220px;
            z-index: 200;
            background: var(--ddb-surface);
            border: 1px solid var(--ddb-border);
            border-radius: var(--ddb-radius);
            box-shadow: 0 8px 24px rgba(0,0,0,.45);
            min-width: 200px;
            overflow: hidden;
        }
        .mlp-ddb-ex-item {
            padding: 9px 14px;
            font-size: 12px;
            color: var(--ddb-text);
            cursor: pointer;
            border-bottom: 1px solid var(--ddb-border);
            transition: background .1s;
        }
        .mlp-ddb-ex-item:last-child { border-bottom: none; }
        .mlp-ddb-ex-item:hover { background: var(--ddb-surface2); color: var(--ddb-accent); }

        /* ─── Workspace ─── */
        .mlp-ddb-workspace {
            display: grid;
            grid-template-columns: 1fr 1fr;
            height: 420px;
            position: relative;
        }
        .mlp-ddb-workspace.has-ai {
            grid-template-columns: 1fr 1fr 320px;
        }
        @media (max-width: 768px) {
            .mlp-ddb-workspace,
            .mlp-ddb-workspace.has-ai {
                grid-template-columns: 1fr;
                height: auto;
            }
        }

        /* ─── Editor column ─── */
        .mlp-ddb-editor-col {
            border-right: 1px solid var(--ddb-border);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        .mlp-ddb-editor-wrap {
            flex: 1;
            overflow: hidden;
        }

        /* ─── Results column ─── */
        .mlp-ddb-results-col {
            display: flex;
            flex-direction: column;
            overflow: hidden;
            background: var(--ddb-bg);
        }
        .mlp-ddb-results-tabs {
            display: flex;
            align-items: center;
            gap: 2px;
            padding: 6px 10px 0;
            border-bottom: 1px solid var(--ddb-border);
            background: var(--ddb-surface);
        }
        .mlp-ddb-rtab {
            padding: 5px 12px;
            background: transparent;
            border: none;
            border-bottom: 2px solid transparent;
            color: var(--ddb-muted);
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: color .12s, border-color .12s;
        }
        .mlp-ddb-rtab.active {
            color: var(--ddb-accent);
            border-bottom-color: var(--ddb-accent);
        }
        .mlp-ddb-exec-time {
            margin-left: auto;
            font-size: 11px;
            color: var(--ddb-muted);
            padding-right: 4px;
        }
        .mlp-ddb-rpane {
            flex: 1;
            overflow: auto;
            padding: 0;
        }

        /* Results empty state */
        .mlp-ddb-results-empty, .mlp-ddb-schema-empty {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 10px;
            height: 100%;
            padding: 30px 20px;
            text-align: center;
            color: var(--ddb-muted);
            font-size: 13px;
        }

        /* Results table */
        .mlp-ddb-results-table-wrap {
            display: flex;
            flex-direction: column;
            height: 100%;
        }
        .mlp-ddb-row-count {
            font-size: 11px;
            color: var(--ddb-muted);
            padding: 5px 12px;
            border-bottom: 1px solid var(--ddb-border);
            background: var(--ddb-surface);
        }
        .mlp-ddb-table-scroll {
            overflow: auto;
            flex: 1;
        }
        .mlp-ddb-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            color: var(--ddb-text);
            white-space: nowrap;
        }
        .mlp-ddb-table thead th {
            position: sticky;
            top: 0;
            background: var(--ddb-surface2);
            padding: 7px 12px;
            text-align: left;
            font-weight: 700;
            color: var(--ddb-muted);
            border-bottom: 1px solid var(--ddb-border);
            font-size: 11px;
            letter-spacing: .5px;
            text-transform: uppercase;
        }
        .mlp-ddb-table tbody td {
            padding: 5px 12px;
            border-bottom: 1px solid rgba(51,65,85,.5);
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 11.5px;
        }
        .mlp-ddb-table tbody tr:hover td { background: var(--ddb-surface2); }
        .mlp-ddb-table tbody tr:last-child td { border-bottom: none; }
        .mlp-ddb-null-val { color: var(--ddb-muted); font-style: italic; }

        /* Schema pane */
        .mlp-ddb-schema-table-block {
            margin: 10px 12px;
            border: 1px solid var(--ddb-border);
            border-radius: 6px;
            overflow: hidden;
        }
        .mlp-ddb-schema-table-name {
            padding: 7px 12px;
            background: var(--ddb-surface2);
            font-size: 12px;
            font-weight: 700;
            color: var(--ddb-accent);
            border-bottom: 1px solid var(--ddb-border);
        }
        .mlp-ddb-schema-col-row {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 5px 12px;
            font-size: 11px;
            border-bottom: 1px solid rgba(51,65,85,.4);
        }
        .mlp-ddb-schema-col-row:last-child { border-bottom: none; }
        .mlp-ddb-schema-col-name { color: var(--ddb-text); font-weight: 600; font-family: monospace; }
        .mlp-ddb-schema-col-type { color: var(--ddb-blue); font-family: monospace; }
        .mlp-ddb-schema-col-pk { color: var(--ddb-accent); font-size: 10px; }

        /* Messages pane */
        .mlp-ddb-messages-log {
            padding: 10px 14px;
            font-size: 12px;
            font-family: 'JetBrains Mono', monospace;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .mlp-ddb-msg-info  { color: var(--ddb-muted); }
        .mlp-ddb-msg-ok    { color: var(--ddb-green); }
        .mlp-ddb-msg-error { color: var(--ddb-red); }

        /* ─── AI Sidebar ─── */
        .mlp-ddb-ai-sidebar {
            border-left: 1px solid var(--ddb-border);
            display: flex;
            flex-direction: column;
            background: var(--ddb-bg);
            overflow: hidden;
        }
        .mlp-ddb-ai-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 14px;
            border-bottom: 1px solid var(--ddb-border);
            background: var(--ddb-surface);
            font-size: 13px;
            font-weight: 700;
            color: var(--ddb-text);
        }
        .mlp-ddb-ai-close {
            background: none;
            border: none;
            color: var(--ddb-muted);
            cursor: pointer;
            font-size: 14px;
            line-height: 1;
            padding: 2px 5px;
            border-radius: 4px;
        }
        .mlp-ddb-ai-close:hover { background: var(--ddb-surface2); color: var(--ddb-text); }
        .mlp-ddb-ai-messages {
            flex: 1;
            overflow-y: auto;
            padding: 12px 10px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .mlp-ddb-ai-bubble {
            padding: 9px 12px;
            border-radius: 8px;
            font-size: 12px;
            line-height: 1.6;
            max-width: 95%;
            word-break: break-word;
        }
        .mlp-ddb-ai-bubble-user {
            background: var(--ddb-blue);
            color: #fff;
            align-self: flex-end;
        }
        .mlp-ddb-ai-bubble-bot {
            background: var(--ddb-surface2);
            color: var(--ddb-text);
            align-self: flex-start;
        }
        .mlp-ddb-ai-bubble pre {
            background: rgba(0,0,0,.3);
            border-radius: 5px;
            padding: 8px;
            overflow-x: auto;
            font-size: 11px;
            margin: 6px 0 0;
            white-space: pre-wrap;
        }
        .mlp-ddb-ai-apply-btn {
            display: inline-block;
            margin-top: 6px;
            padding: 4px 10px;
            background: var(--ddb-accent);
            color: #1e293b;
            border: none;
            border-radius: 5px;
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
        }
        .mlp-ddb-ai-apply-btn:hover { background: var(--ddb-accent2); }
        .mlp-ddb-ai-undo-btn {
            display: inline-block;
            margin-top: 6px;
            margin-left: 4px;
            padding: 4px 10px;
            background: rgba(255,255,255,0.08);
            color: #94a3b8;
            border: 1px solid #334155;
            border-radius: 5px;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
        }
        .mlp-ddb-ai-undo-btn:hover { background: rgba(255,255,255,0.14); color: #e2e8f0; }
        /* ── AI thinking animation ── */
        @keyframes mlp-brain-pulse {
            0%,100% { opacity: .45; transform: scale(1); }
            50%      { opacity: 1;   transform: scale(1.18); }
        }
        @keyframes mlp-dot-bounce {
            0%,80%,100% { transform: translateY(0);   opacity: .35; }
            40%          { transform: translateY(-5px); opacity: 1;   }
        }
        .mlp-ddb-brain-icon {
            flex-shrink: 0;
            animation: mlp-brain-pulse 1.5s ease-in-out infinite;
            color: #60a5fa;
        }
        .mlp-ddb-thinking-dot {
            width: 5px; height: 5px; border-radius: 50%;
            background: #60a5fa; display: inline-block;
            animation: mlp-dot-bounce 1.3s ease-in-out infinite;
        }
        .mlp-ddb-ai-input-row {
            display: flex;
            gap: 6px;
            padding: 8px 10px;
            border-top: 1px solid var(--ddb-border);
            background: var(--ddb-surface);
        }
        .mlp-ddb-ai-input {
            flex: 1;
            background: var(--ddb-bg);
            border: 1px solid var(--ddb-border);
            border-radius: 6px;
            color: var(--ddb-text);
            font-size: 12px;
            padding: 6px 9px;
            resize: none;
            font-family: inherit;
        }
        .mlp-ddb-ai-input:focus { outline: none; border-color: var(--ddb-blue); }
        .mlp-ddb-ai-send {
            padding: 6px 12px;
            background: var(--ddb-blue);
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
            align-self: flex-end;
        }
        .mlp-ddb-ai-send:hover { background: #2563eb; }
        .mlp-ddb-ai-providers {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 6px 10px 8px;
            background: var(--ddb-surface);
            border-top: 1px solid var(--ddb-border);
        }
        .mlp-ddb-ai-providers .cf-turnstile { margin: 0 auto; }

        /* ─── Publish modal ─── */
        .mlp-ddb-modal-bg {
            position: fixed;
            inset: 0;
            z-index: 1000;
            background: rgba(0,0,0,.7);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .mlp-ddb-modal {
            background: var(--ddb-surface);
            border: 1px solid var(--ddb-border);
            border-radius: 12px;
            width: 100%;
            max-width: 460px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0,0,0,.6);
        }
        .mlp-ddb-modal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 20px;
            border-bottom: 1px solid var(--ddb-border);
        }
        .mlp-ddb-modal-header h3 { margin: 0; font-size: 15px; color: var(--ddb-text); }
        .mlp-ddb-modal-close {
            background: none;
            border: none;
            color: var(--ddb-muted);
            cursor: pointer;
            font-size: 16px;
            padding: 2px 6px;
            border-radius: 4px;
        }
        .mlp-ddb-modal-close:hover { background: var(--ddb-surface2); color: var(--ddb-text); }
        .mlp-ddb-modal-body { padding: 16px 20px; display: flex; flex-direction: column; gap: 10px; }
        .mlp-ddb-modal-body label { font-size: 12px; font-weight: 600; color: var(--ddb-muted); }
        .mlp-ddb-modal-body input,
        .mlp-ddb-modal-body textarea {
            width: 100%;
            background: var(--ddb-bg);
            border: 1px solid var(--ddb-border);
            border-radius: 6px;
            color: var(--ddb-text);
            font-size: 13px;
            padding: 8px 10px;
            font-family: inherit;
            box-sizing: border-box;
        }
        .mlp-ddb-modal-body input:focus,
        .mlp-ddb-modal-body textarea:focus { outline: none; border-color: var(--ddb-blue); }
        .mlp-ddb-modal-note {
            font-size: 11px;
            color: var(--ddb-muted);
            background: var(--ddb-surface2);
            border-radius: 6px;
            padding: 8px 10px;
        }
        .mlp-ddb-req { color: var(--ddb-red); }
        .mlp-ddb-modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 8px;
            padding: 12px 20px;
            border-top: 1px solid var(--ddb-border);
        }
        .mlp-ddb-pub-result {
            padding: 12px 20px;
            font-size: 12px;
            border-top: 1px solid var(--ddb-border);
        }
        .mlp-ddb-pub-result.ok  { color: var(--ddb-green); }
        .mlp-ddb-pub-result.err { color: var(--ddb-red); }

        /* ─── Gallery ─── */
        #mlp-duckdb-gallery {
            margin: 24px 0;
        }
        .mlp-ddb-gallery-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }
        .mlp-ddb-gallery-title {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 18px;
            font-weight: 700;
            color: var(--ddb-text);
            margin: 0;
        }
        .mlp-ddb-gallery-search-wrap {
            display: flex;
            gap: 6px;
        }
        .mlp-ddb-gallery-search-wrap input {
            padding: 7px 12px;
            border-radius: 7px;
            border: 1px solid var(--ddb-border);
            background: var(--ddb-surface);
            color: var(--ddb-text);
            font-size: 13px;
            min-width: 200px;
        }
        .mlp-ddb-gallery-search-wrap input:focus { outline: none; border-color: var(--ddb-blue); }
        .mlp-ddb-gallery-search-wrap button {
            padding: 7px 14px;
            background: var(--ddb-blue);
            color: #fff;
            border: none;
            border-radius: 7px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
        }
        .mlp-ddb-gallery-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 16px;
        }
        .mlp-ddb-gallery-loading {
            grid-column: 1 / -1;
            text-align: center;
            color: var(--ddb-muted);
            padding: 40px;
        }
        .mlp-ddb-gallery-empty {
            grid-column: 1 / -1;
            text-align: center;
            color: var(--ddb-muted);
            padding: 40px;
        }

        /* Gallery card */
        .mlp-ddb-card {
            background: var(--ddb-surface);
            border: 1px solid var(--ddb-border);
            border-radius: 10px;
            overflow: hidden;
            transition: border-color .15s, box-shadow .15s;
            cursor: pointer;
            display: flex;
            flex-direction: column;
        }
        .mlp-ddb-card:hover {
            border-color: var(--ddb-accent);
            box-shadow: 0 4px 20px rgba(0,0,0,.3);
        }
        .mlp-ddb-card-code {
            background: var(--ddb-bg);
            padding: 12px 14px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 11px;
            color: var(--ddb-text);
            height: 130px;
            overflow: hidden;
            position: relative;
            line-height: 1.6;
            white-space: pre;
        }
        .mlp-ddb-card-code::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 40px;
            background: linear-gradient(transparent, var(--ddb-bg));
        }
        .mlp-ddb-card-footer {
            padding: 10px 14px;
            border-top: 1px solid var(--ddb-border);
            background: var(--ddb-surface2);
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .mlp-ddb-card-title {
            font-size: 13px;
            font-weight: 700;
            color: var(--ddb-text);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .mlp-ddb-card-meta {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 11px;
            color: var(--ddb-muted);
        }
        .mlp-ddb-card-author { font-style: italic; }
        .mlp-ddb-card-desc {
            font-size: 11px;
            color: var(--ddb-muted);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .mlp-ddb-card-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-top: 4px;
        }
        .mlp-ddb-card-like-btn {
            background: none;
            border: 1px solid var(--ddb-border);
            border-radius: 5px;
            color: var(--ddb-muted);
            font-size: 11px;
            padding: 3px 8px;
            cursor: pointer;
            transition: all .12s;
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .mlp-ddb-card-like-btn:hover,
        .mlp-ddb-card-like-btn.liked { color: var(--ddb-accent); border-color: var(--ddb-accent); }
        .mlp-ddb-card-load-btn {
            margin-left: auto;
            background: var(--ddb-accent);
            border: none;
            border-radius: 5px;
            color: #1e293b;
            font-size: 11px;
            font-weight: 700;
            padding: 4px 10px;
            cursor: pointer;
        }
        .mlp-ddb-card-load-btn:hover { background: var(--ddb-accent2); }

        /* Gallery pagination */
        .mlp-ddb-gallery-pagination {
            display: flex;
            justify-content: center;
            gap: 6px;
            margin-top: 20px;
        }
        .mlp-ddb-page-btn {
            padding: 6px 12px;
            border: 1px solid var(--ddb-border);
            border-radius: 6px;
            background: var(--ddb-surface);
            color: var(--ddb-text);
            font-size: 12px;
            cursor: pointer;
        }
        .mlp-ddb-page-btn:hover { border-color: var(--ddb-accent); }
        .mlp-ddb-page-btn.current { background: var(--ddb-accent); color: #1e293b; border-color: var(--ddb-accent); font-weight: 700; }

        /* SQL syntax highlight in preview (simple CSS-based) */
        .mlp-ddb-card-code .kw { color: #7dd3fc; }
        .mlp-ddb-card-code .fn { color: #a78bfa; }
        .mlp-ddb-card-code .num { color: #86efac; }
        .mlp-ddb-card-code .str { color: #fcd34d; }
        .mlp-ddb-card-code .cm { color: #64748b; }

        @media (max-width: 600px) {
            .mlp-ddb-gallery-header { flex-direction: column; align-items: flex-start; }
            .mlp-ddb-gallery-search-wrap { width: 100%; }
            .mlp-ddb-gallery-search-wrap input { flex: 1; min-width: 0; }
        }

        /* Hide HTML/CSS/JS chat when DuckDB overlay is active */
        html.mlp-ddb-active #mlpChatToggle,
        html.mlp-ddb-active #mlpChatSidebar { display: none !important; }
        </style>
        <?php
    }

    /* ─────────────────────────────────────────────────────────────────────
     *  Output JavaScript (Monaco + DuckDB WASM + gallery + AI chat)
     * ───────────────────────────────────────────────────────────────────── */
    public static function output_scripts() { // phpcs:ignore
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) ) { return; }
        $relevant = has_shortcode( $post->post_content, 'mlp_duckdb' )
                 || isset( $_GET['mlp_duckdb_share'] )
                 || class_exists( 'MLP_Projects' );
        if ( ! $relevant ) { return; }

        $nonce       = wp_create_nonce( 'mlp_duckdb_nonce' );
        $ajax_url    = admin_url( 'admin-ajax.php' );
        $ts_site_key = defined( 'MLP_TURNSTILE_SITE_KEY' ) ? MLP_TURNSTILE_SITE_KEY : '';
        ?>
        <!-- Monaco Editor loader -->
        <script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.46.0/min/vs/loader.js" defer></script>
        <?php if ( $ts_site_key ) : ?>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        <?php endif; ?>

        <script>
        (function() {
        'use strict';

        var MLP_DUCKDB_NONCE      = <?php echo wp_json_encode( $nonce ); ?>;
        var MLP_DUCKDB_AJAX       = <?php echo wp_json_encode( $ajax_url ); ?>;
        var MLP_DUCKDB_TS_SITEKEY = <?php echo wp_json_encode( $ts_site_key ); ?>;
        var DUCKDB_VERSION        = '1.29.0';

        /* Cloudflare Turnstile — lazy, first-message gate */
        var mlpDdbTsToken    = '';
        var mlpDdbTsVerified = sessionStorage.getItem('mlp_ddb_ts_v') === '1';
        var mlpDdbTsPending  = '';    /* message queued while user completes captcha */
        var mlpDdbTsAutoSend = false; /* suppress duplicate user bubble on auto-send */
        var ddbEditorUndo    = '';    /* undo stack for main editor Apply */
        var ovEditorUndo     = '';    /* undo stack for overlay editor Apply */

        window.mlpDdbTsCallback = function(token) {
            mlpDdbTsToken    = token;
            mlpDdbTsVerified = true;
            sessionStorage.setItem('mlp_ddb_ts_v', '1');
            /* Remove any inline gate bubbles */
            ['mlp-ddb-ts-gate', 'mlp-ddb-ov-ts-gate'].forEach(function(id) {
                var el = document.getElementById(id);
                if (el && el.parentNode) el.parentNode.removeChild(el);
            });
            /* Auto-send the queued message — flag prevents a duplicate user bubble */
            if (mlpDdbTsPending) {
                var pending = mlpDdbTsPending;
                mlpDdbTsPending  = '';
                mlpDdbTsAutoSend = true;
                var ovAiSidebar = document.getElementById('mlp-ddb-ov-ai-sidebar');
                if (ovAiSidebar && ovAiSidebar.style.display !== 'none') {
                    var ovIn = document.getElementById('mlp-ddb-ov-ai-input');
                    if (ovIn) { ovIn.value = pending; ovSendAI(); }
                } else {
                    var mainIn = document.getElementById('mlp-ddb-ai-input');
                    if (mainIn) { mainIn.value = pending; sendAIMessage(); }
                }
            }
        };

        /* Render a Turnstile gate bubble inside a messages container */
        function showTurnstileGate(msgContainerId, gateId) {
            var msgs = document.getElementById(msgContainerId);
            if (!msgs || document.getElementById(gateId)) return;
            var gate = document.createElement('div');
            gate.id = gateId;
            gate.className = 'mlp-ddb-ai-bubble mlp-ddb-ai-bubble-bot';
            gate.style.cssText = 'display:flex;flex-direction:column;gap:8px;';
            gate.innerHTML =
                '<span style="font-size:12px;line-height:1.5;">To continue, please complete the quick verification:</span>' +
                '<div id="' + gateId + '-widget"></div>';
            msgs.appendChild(gate);
            msgs.scrollTop = msgs.scrollHeight;
            (function tryRender(n) {
                if (typeof turnstile !== 'undefined') {
                    turnstile.render(document.getElementById(gateId + '-widget'), {
                        sitekey: MLP_DUCKDB_TS_SITEKEY,
                        callback: window.mlpDdbTsCallback,
                        size: 'compact',
                    });
                } else if (n < 20) {
                    setTimeout(function() { tryRender(n + 1); }, 300);
                }
            }(0));
        }
        var DUCKDB_ESM_URL     = 'https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@' + DUCKDB_VERSION + '/+esm';
        var CDN_BASE           = 'https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@' + DUCKDB_VERSION + '/dist';

        /* Brain SVG + bouncing dots used for the "thinking" bubble */
        var THINKING_HTML =
            '<svg class="mlp-ddb-brain-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' +
              '<path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-1.07-4.8A3 3 0 0 1 4.5 10.5a3 3 0 0 1 1.7-2.7A2.5 2.5 0 0 1 9.5 2Z"/>' +
              '<path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 1.07-4.8A3 3 0 0 0 19.5 10.5a3 3 0 0 0-1.7-2.7A2.5 2.5 0 0 0 14.5 2Z"/>' +
            '</svg>' +
            '<span class="mlp-ddb-thinking-dot"></span>' +
            '<span class="mlp-ddb-thinking-dot" style="animation-delay:.22s"></span>' +
            '<span class="mlp-ddb-thinking-dot" style="animation-delay:.44s"></span>';

        /* ── Tiny SQL syntax highlighter for gallery cards ──────────────── */
        function sqlHighlight(code) {
            var esc = code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
            var kws = ['SELECT','FROM','WHERE','JOIN','LEFT','RIGHT','INNER','OUTER','ON',
                       'GROUP BY','ORDER BY','HAVING','LIMIT','OFFSET','INSERT','UPDATE',
                       'DELETE','CREATE','TABLE','DROP','ALTER','WITH','AS','AND','OR','NOT',
                       'IN','IS','NULL','DISTINCT','UNION','ALL','VALUES','SET','INTO',
                       'PRIMARY KEY','PARTITION BY','OVER','RECURSIVE','LATERAL','INTERVAL'];
            var kwRe = new RegExp('\\b(' + kws.join('|') + ')\\b', 'gi');
            esc = esc.replace(/(--.*)$/gm, '<span class="cm">$1</span>');
            esc = esc.replace(/(\/\*[\s\S]*?\*\/)/g, '<span class="cm">$1</span>');
            esc = esc.replace(/'([^']*)'/g, "<span class=\"str\">'$1'</span>");
            esc = esc.replace(/\b(\d+\.?\d*)\b/g, '<span class="num">$1</span>');
            esc = esc.replace(kwRe, '<span class="kw">$1</span>');
            return esc;
        }

        /* ── State ──────────────────────────────────────────────────────── */
        var db           = null;
        var conn         = null;
        var monacoEditor = null;
        var dbReady      = false;
        var aiHistory    = [];

        /* ── DOM helpers ─────────────────────────────────────────────────── */
        function $(id) { return document.getElementById(id); }
        function log(msg, cls) {
            var el = $('mlp-ddb-messages-log');
            if (!el) return;
            var p = document.createElement('p');
            p.className = 'mlp-ddb-msg-' + (cls || 'info');
            p.textContent = msg;
            el.appendChild(p);
            el.scrollTop = el.scrollHeight;
        }
        function setStatus(text, state) {
            var dot  = $('mlp-ddb-status-dot');
            var txt  = $('mlp-ddb-status-text');
            if (dot) { dot.className = 'mlp-ddb-status-dot' + (state ? ' ' + state : ''); }
            if (txt) txt.textContent = text;
        }

        /* ── Initialise Monaco then DuckDB WASM ────────────────────────── */
        function init() {
            var root = $('mlp-duckdb-root');
            if (!root) return;

            // Monaco
            var loaderScript = document.querySelector('script[src*="vs/loader.js"]');
            function whenLoaderReady(tries) {
                tries = tries || 0;
                if (typeof require !== 'undefined') {
                    setupMonaco();
                } else if (tries < 40) {
                    setTimeout(function() { whenLoaderReady(tries + 1); }, 250);
                }
            }
            if (loaderScript && loaderScript.getAttribute('defer') !== null) {
                whenLoaderReady();
            } else {
                setupMonaco();
            }
        }

        function setupMonaco() {
            require.config({ paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.46.0/min/vs' } });
            require(['vs/editor/editor.main'], function() {
                var container = $('mlp-ddb-monaco');
                if (!container) return;

                monacoEditor = monaco.editor.create(container, {
                    value: '-- Welcome to DuckDB Editor!\n-- Write your SQL here and press Run (Ctrl+Enter)\n\nSELECT\n    range AS n,\n    n * n AS squared,\n    SQRT(n) AS square_root\nFROM range(1, 11) t(n)\nORDER BY n;',
                    language: 'sql',
                    theme: 'vs-dark',
                    fontSize: 13,
                    fontFamily: "'JetBrains Mono', 'Fira Code', Menlo, monospace",
                    fontLigatures: true,
                    minimap: { enabled: false },
                    scrollBeyondLastLine: false,
                    wordWrap: 'on',
                    lineNumbers: 'on',
                    renderLineHighlight: 'line',
                    padding: { top: 12, bottom: 12 },
                    automaticLayout: true,
                    tabSize: 2,
                    insertSpaces: true,
                    suggestOnTriggerCharacters: true,
                });

                // Ctrl+Enter to run
                monacoEditor.addCommand(
                    monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter,
                    runQuery
                );

                // Now load DuckDB WASM
                loadDuckDB();
            });
        }

        function loadDuckDB() {
            setStatus('Loading DuckDB WASM…', '');
            log('Loading DuckDB WASM from CDN…', 'info');

            import(DUCKDB_ESM_URL)
                .then(function(duckdb) {
                    window._mlpDuckdb = duckdb;
                    /* Force EH bundle — avoids COI/pthreads which hangs without
                       Cross-Origin-Opener-Policy headers (most WordPress hosts). */
                    var bundle = duckdb.getJsDelivrBundles().eh;
                    var workerUrl = URL.createObjectURL(
                        new Blob(['importScripts("' + bundle.mainWorker + '");'],
                                 { type: 'application/javascript' })
                    );
                    var logger = new duckdb.ConsoleLogger();
                    var worker = new Worker(workerUrl);
                    db = new duckdb.AsyncDuckDB(logger, worker);
                    return db.instantiate(bundle.mainModule)
                        .then(function() { return db.connect(); })
                        .then(function(c) {
                            conn    = c;
                            dbReady = true;
                            URL.revokeObjectURL(workerUrl);
                            setStatus('Ready', 'ready');
                            log('DuckDB WASM ready. Run a query to get started!', 'ok');
                        });
                })
                .catch(function(err) {
                    setStatus('CDN load failed', 'error');
                    log('Failed to load DuckDB: ' + (err && err.message ? err.message : err), 'error');
                });
        }

        /* ── Run query ───────────────────────────────────────────────────── */
        function runQuery() {
            if (!dbReady || !conn) {
                showToastDdb('DuckDB is not ready yet. Please wait.', 'warn');
                return;
            }
            var sql = monacoEditor ? monacoEditor.getValue() : '';
            if (!sql.trim()) { showToastDdb('Nothing to run.', 'warn'); return; }

            var runBtn = $('mlp-ddb-run-btn');
            if (runBtn) { runBtn.disabled = true; runBtn.textContent = '⏳ Running…'; }

            var t0 = performance.now();
            switchResultPane('results');

            conn.query(sql)
                .then(function(result) {
                    var elapsed = ((performance.now() - t0) / 1000).toFixed(3);
                    $('mlp-ddb-exec-time').textContent = elapsed + 's';

                    var schema  = result.schema;
                    var batches = result.batches;

                    /* Build flat rows from Arrow batches */
                    var rows = [];
                    if (batches) {
                        batches.forEach(function(batch) {
                            var numRows = batch.numRows;
                            for (var r = 0; r < numRows; r++) {
                                var row = {};
                                schema.fields.forEach(function(field, ci) {
                                    var col = batch.getChildAt(ci);
                                    row[field.name] = col ? col.get(r) : null;
                                });
                                rows.push(row);
                            }
                        });
                    }

                    renderResults(schema.fields.map(function(f){ return f.name; }), rows);
                    log('Query OK — ' + rows.length + ' row(s) in ' + elapsed + 's', 'ok');
                    refreshSchema();
                })
                .catch(function(err) {
                    renderError(err.message);
                    log('Error: ' + err.message, 'error');
                    switchResultPane('messages');
                })
                .finally(function() {
                    if (runBtn) {
                        runBtn.disabled = false;
                        runBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" width="14" height="14"><path d="M8 5v14l11-7z"/></svg> Run';
                    }
                });
        }

        function renderResults(cols, rows) {
            var empty = $('mlp-ddb-results-empty');
            var wrap  = $('mlp-ddb-results-table-wrap');
            var thead = $('mlp-ddb-thead');
            var tbody = $('mlp-ddb-tbody');
            var rcount= $('mlp-ddb-row-count');

            if (empty) empty.style.display = 'none';
            if (wrap)  wrap.style.display = '';

            // Header
            thead.innerHTML = '<tr>' + cols.map(function(c) {
                return '<th>' + escHtml(c) + '</th>';
            }).join('') + '</tr>';

            // Body (limit 5000 rows for display)
            var displayRows = rows.slice(0, 5000);
            tbody.innerHTML = displayRows.map(function(row) {
                return '<tr>' + cols.map(function(c) {
                    var v = row[c];
                    if (v === null || v === undefined) {
                        return '<td><span class="mlp-ddb-null-val">NULL</span></td>';
                    }
                    if (typeof v === 'bigint') v = v.toString();
                    if (typeof v === 'object') v = JSON.stringify(v);
                    return '<td>' + escHtml(String(v)) + '</td>';
                }).join('') + '</tr>';
            }).join('');

            var msg = rows.length + ' row' + (rows.length !== 1 ? 's' : '');
            if (rows.length > 5000) msg += ' (showing first 5,000)';
            if (rcount) rcount.textContent = msg;
        }

        function renderError(msg) {
            var empty = $('mlp-ddb-results-empty');
            var wrap  = $('mlp-ddb-results-table-wrap');
            if (wrap)  wrap.style.display = 'none';
            if (empty) {
                empty.style.display = '';
                empty.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="1.5" width="32" height="32"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>' +
                    '<p style="color:#ef4444;font-family:monospace;font-size:12px;max-width:400px;word-break:break-word;">' + escHtml(msg) + '</p>';
            }
        }

        function refreshSchema() {
            if (!dbReady || !conn) return;
            conn.query("SELECT table_name, column_name, data_type, is_nullable FROM information_schema.columns ORDER BY table_name, ordinal_position")
                .then(function(result) {
                    var tables = {};
                    if (result.batches) {
                        result.batches.forEach(function(batch) {
                            for (var r = 0; r < batch.numRows; r++) {
                                var tname = batch.getChildAt(0).get(r);
                                var cname = batch.getChildAt(1).get(r);
                                var dtype = batch.getChildAt(2).get(r);
                                if (!tables[tname]) tables[tname] = [];
                                tables[tname].push({ name: cname, type: dtype });
                            }
                        });
                    }
                    renderSchema(tables);
                })
                .catch(function() {});
        }

        function renderSchema(tables) {
            var list  = $('mlp-ddb-schema-list');
            var empty = $('mlp-ddb-schema-empty');
            if (!list) return;
            var keys = Object.keys(tables);
            if (!keys.length) {
                if (empty) empty.style.display = '';
                list.innerHTML = '';
                return;
            }
            if (empty) empty.style.display = 'none';
            list.innerHTML = keys.map(function(tname) {
                var cols = tables[tname].map(function(c) {
                    return '<div class="mlp-ddb-schema-col-row">' +
                        '<span class="mlp-ddb-schema-col-name">' + escHtml(c.name) + '</span>' +
                        '<span class="mlp-ddb-schema-col-type">' + escHtml(c.type || '') + '</span>' +
                    '</div>';
                }).join('');
                return '<div class="mlp-ddb-schema-table-block">' +
                    '<div class="mlp-ddb-schema-table-name">📋 ' + escHtml(tname) + '</div>' +
                    cols +
                '</div>';
            }).join('');
        }

        /* ── Result pane switcher ────────────────────────────────────────── */
        function switchResultPane(which) {
            ['results','schema','messages'].forEach(function(name) {
                var pane = $('mlp-ddb-pane-' + name);
                var tab  = document.querySelector('[data-pane="' + name + '"]');
                if (pane) pane.style.display = (name === which) ? '' : 'none';
                if (tab)  tab.classList.toggle('active', name === which);
            });
        }

        /* ── Format SQL (basic prettifier) ──────────────────────────────── */
        function formatSQL(sql) {
            var keywords = ['SELECT','FROM','WHERE','JOIN','LEFT JOIN','RIGHT JOIN',
                'INNER JOIN','ON','GROUP BY','ORDER BY','HAVING','LIMIT','OFFSET',
                'UNION','UNION ALL','WITH','INSERT INTO','VALUES','UPDATE','SET',
                'DELETE FROM','CREATE TABLE','DROP TABLE','ALTER TABLE'];
            var result = sql;
            keywords.forEach(function(kw) {
                result = result.replace(new RegExp('\\b' + kw + '\\b', 'gi'), '\n' + kw);
            });
            return result.replace(/^\n/, '').replace(/\n{2,}/g, '\n');
        }

        /* ── Gallery ─────────────────────────────────────────────────────── */
        var galleryPage = 1;

        function loadGallery(page, search) {
            var grid = $('mlp-ddb-gallery-grid');
            var pgn  = $('mlp-ddb-gallery-pagination');
            if (!grid) return;
            grid.innerHTML = '<div class="mlp-ddb-gallery-loading">Loading…</div>';
            if (pgn) pgn.innerHTML = '';

            var body = new URLSearchParams();
            body.set('action', 'mlp_duckdb_get_projects');
            body.set('page', page || 1);
            if (search) body.set('search', search);

            fetch(MLP_DUCKDB_AJAX, { method: 'POST', body: body })
                .then(function(r) { return r.json(); })
                .then(function(resp) {
                    if (!resp || !resp.success) {
                        grid.innerHTML = '<div class="mlp-ddb-gallery-empty">Could not load projects.</div>';
                        return;
                    }
                    var data = resp.data;
                    if (!data.projects || !data.projects.length) {
                        grid.innerHTML = '<div class="mlp-ddb-gallery-empty">No published projects yet. Be the first!</div>';
                        return;
                    }
                    grid.innerHTML = '';
                    data.projects.forEach(function(proj) {
                        grid.appendChild(buildCard(proj));
                    });
                    renderPagination(data.page, data.total_pages, search);
                })
                .catch(function() {
                    grid.innerHTML = '<div class="mlp-ddb-gallery-empty">Network error loading gallery.</div>';
                });
        }

        function buildCard(proj) {
            var card = document.createElement('div');
            card.className = 'mlp-ddb-card';

            var codePreview = document.createElement('div');
            codePreview.className = 'mlp-ddb-card-code';
            codePreview.innerHTML = sqlHighlight(proj.sql || '');
            card.appendChild(codePreview);

            var footer = document.createElement('div');
            footer.className = 'mlp-ddb-card-footer';
            footer.innerHTML =
                '<div class="mlp-ddb-card-title">' + escHtml(proj.name || 'Untitled') + '</div>' +
                (proj.description ? '<div class="mlp-ddb-card-desc">' + escHtml(proj.description) + '</div>' : '') +
                '<div class="mlp-ddb-card-meta">' +
                    '<span class="mlp-ddb-card-author">by ' + escHtml(proj.author || 'Anonymous') + '</span>' +
                    '<span>👁 ' + (proj.views || 0) + '</span>' +
                '</div>' +
                '<div class="mlp-ddb-card-actions">' +
                    '<button class="mlp-ddb-card-like-btn" data-token="' + escHtml(proj.token) + '" data-likes="' + (proj.likes || 0) + '">♥ ' + (proj.likes || 0) + '</button>' +
                    '<button class="mlp-ddb-card-load-btn" data-sql="' + escAttr(proj.sql || '') + '">Load →</button>' +
                '</div>';
            card.appendChild(footer);
            return card;
        }

        function renderPagination(page, totalPages, search) {
            var pgn = $('mlp-ddb-gallery-pagination');
            if (!pgn || totalPages <= 1) { if (pgn) pgn.innerHTML = ''; return; }
            var html = '';
            for (var i = 1; i <= totalPages; i++) {
                html += '<button class="mlp-ddb-page-btn' + (i === page ? ' current' : '') + '" data-page="' + i + '" data-search="' + escAttr(search || '') + '">' + i + '</button>';
            }
            pgn.innerHTML = html;
        }

        /* ── AI Chat ─────────────────────────────────────────────────────── */
        function sendAIMessage() {
            var input    = $('mlp-ddb-ai-input');
            var sendBtn  = $('mlp-ddb-ai-send');
            var messages = $('mlp-ddb-ai-messages');
            if (!input || !messages) return;

            var userMsg = input.value.trim();
            if (!userMsg) return;

            input.value = '';
            var _auto = mlpDdbTsAutoSend; mlpDdbTsAutoSend = false;
            if (!_auto) appendAIBubble(userMsg, 'user');
            if (sendBtn) sendBtn.disabled = true;

            /* Turnstile gate — show once before first message if configured */
            if (MLP_DUCKDB_TS_SITEKEY && !mlpDdbTsVerified) {
                mlpDdbTsPending = userMsg;
                if (sendBtn) sendBtn.disabled = false;
                showTurnstileGate('mlp-ddb-ai-messages', 'mlp-ddb-ts-gate');
                return;
            }

            var currentSQL = monacoEditor ? monacoEditor.getValue() : '';

            aiHistory.push({ role: 'user', content: userMsg });

            var body = new URLSearchParams();
            body.set('action',   'mlp_ai_chat_duckdb');
            body.set('nonce',    MLP_DUCKDB_NONCE);
            body.set('message',  userMsg);
            body.set('sql_code', currentSQL);
            body.set('provider', 'cerebras');
            body.set('history',  JSON.stringify(aiHistory.slice(-10)));
            if (mlpDdbTsToken) { body.set('turnstile_token', mlpDdbTsToken); mlpDdbTsToken = ''; }

            var thinkingBubble = appendAIBubble('Thinking…', 'bot', true);

            fetch(MLP_DUCKDB_AJAX, { method: 'POST', body: body })
                .then(function(r) { return r.json(); })
                .then(function(resp) {
                    if (thinkingBubble && thinkingBubble.parentNode) {
                        thinkingBubble.parentNode.removeChild(thinkingBubble);
                    }
                    if (resp && resp.success && resp.data && resp.data.reply) {
                        var reply = resp.data.reply;
                        aiHistory.push({ role: 'assistant', content: reply });
                        appendAIBubble(reply, 'bot');
                    } else {
                        appendAIBubble('Sorry, I could not get a response. Please try again.', 'bot');
                    }
                })
                .catch(function() {
                    if (thinkingBubble && thinkingBubble.parentNode) {
                        thinkingBubble.parentNode.removeChild(thinkingBubble);
                    }
                    appendAIBubble('Network error. Please check your connection.', 'bot');
                })
                .finally(function() {
                    if (sendBtn) sendBtn.disabled = false;
                });
        }

        function appendAIBubble(text, role, isTemp) {
            var messages = $('mlp-ddb-ai-messages');
            if (!messages) return null;

            var bubble = document.createElement('div');
            bubble.className = 'mlp-ddb-ai-bubble mlp-ddb-ai-bubble-' + (role === 'user' ? 'user' : 'bot');

            /* Thinking indicator — brain SVG + bouncing dots */
            if (isTemp) {
                bubble.style.cssText = 'display:flex;align-items:center;gap:6px;';
                bubble.innerHTML = THINKING_HTML;
                messages.appendChild(bubble);
                messages.scrollTop = messages.scrollHeight;
                return bubble;
            }

            if (role !== 'user') {
                /* Two-pass render: extract code blocks first so \n→<br> never contaminates data-sql */
                var _blocks = [];
                var html = text.replace(/```(?:sql|SQL)?\n?([\s\S]*?)```/g, function(_, code) {
                    var raw = code.trim();
                    var idx = _blocks.length;
                    _blocks.push(raw);
                    return '\x01BLK' + idx + '\x01';
                });

                html = escHtml(html);
                html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
                html = html.replace(/`([^`]+)`/g, '<code style="background:rgba(0,0,0,.3);padding:1px 4px;border-radius:3px;font-size:11px;">$1</code>');
                html = html.replace(/\n/g, '<br>');

                /* Restore code blocks — raw SQL goes into data-sql, no <br> contamination */
                html = html.replace(/\x01BLK(\d+)\x01/g, function(_, i) {
                    var raw = _blocks[parseInt(i)];
                    return '<pre>' + escHtml(raw) + '</pre>' +
                        '<button class="mlp-ddb-ai-apply-btn" data-sql="' + escAttr(raw) + '">Apply to Editor</button>' +
                        '<button class="mlp-ddb-ai-undo-btn">Undo</button>';
                });

                bubble.innerHTML = html;
            } else {
                bubble.textContent = text;
            }

            messages.appendChild(bubble);
            messages.scrollTop = messages.scrollHeight;
            return bubble;
        }

        /* ── Publish ─────────────────────────────────────────────────────── */
        function publishProject() {
            var name   = ($('mlp-ddb-pub-name')   || {}).value || '';
            var desc   = ($('mlp-ddb-pub-desc')   || {}).value || '';
            var author = ($('mlp-ddb-pub-author') || {}).value || 'Anonymous';
            var sql    = monacoEditor ? monacoEditor.getValue() : '';

            if (!name.trim()) { showToastDdb('Please enter a project name.', 'warn'); return; }
            if (!sql.trim())  { showToastDdb('Cannot publish an empty query.', 'warn'); return; }

            var confirmBtn = $('mlp-ddb-pub-confirm');
            if (confirmBtn) { confirmBtn.disabled = true; confirmBtn.textContent = 'Publishing…'; }

            var body = new URLSearchParams();
            body.set('action', 'mlp_duckdb_publish_project');
            body.set('nonce', MLP_DUCKDB_NONCE);
            body.set('name', name);
            body.set('description', desc);
            body.set('author', author);
            body.set('sql', sql);

            fetch(MLP_DUCKDB_AJAX, { method: 'POST', body: body })
                .then(function(r) { return r.json(); })
                .then(function(resp) {
                    var result = $('mlp-ddb-pub-result');
                    if (result) result.style.display = '';
                    if (resp && resp.success) {
                        var url = resp.data && resp.data.share_url ? resp.data.share_url : '';
                        if (result) {
                            result.className = 'mlp-ddb-pub-result ok';
                            result.innerHTML = '✓ Published! <a href="' + escHtml(url) + '" target="_blank" style="color:inherit;text-decoration:underline;">' + escHtml(url) + '</a>';
                        }
                        loadGallery(1, '');
                    } else {
                        var msg = (resp && resp.data && resp.data.message) ? resp.data.message : 'Publish failed.';
                        if (result) { result.className = 'mlp-ddb-pub-result err'; result.textContent = '✗ ' + msg; }
                    }
                })
                .catch(function() {
                    var result = $('mlp-ddb-pub-result');
                    if (result) { result.style.display = ''; result.className = 'mlp-ddb-pub-result err'; result.textContent = '✗ Network error. Please try again.'; }
                })
                .finally(function() {
                    if (confirmBtn) { confirmBtn.disabled = false; confirmBtn.textContent = 'Publish'; }
                });
        }

        /* ── Tiny toast ──────────────────────────────────────────────────── */
        function showToastDdb(msg, type) {
            var toast = document.createElement('div');
            toast.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;' +
                'padding:10px 18px;border-radius:8px;font-size:13px;font-weight:600;' +
                'background:' + (type === 'warn' ? '#92400e' : '#1e3a5f') + ';' +
                'color:#fff;box-shadow:0 4px 16px rgba(0,0,0,.4);' +
                'animation:mlpFadeIn .2s ease;pointer-events:none;max-width:320px;';
            toast.textContent = msg;
            document.body.appendChild(toast);
            setTimeout(function() {
                toast.style.opacity = '0';
                toast.style.transition = 'opacity .3s';
                setTimeout(function() { toast.remove(); }, 300);
            }, 3000);
        }

        /* ── Helpers ─────────────────────────────────────────────────────── */
        function escHtml(str) {
            return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
        }
        function escAttr(str) {
            return String(str).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
        }

        /* ── Event wiring (delegated) ────────────────────────────────────── */
        function wireEvents() {
            /* Run */
            var runBtn = $('mlp-ddb-run-btn');
            if (runBtn) runBtn.addEventListener('click', runQuery);

            /* Clear */
            var clearBtn = $('mlp-ddb-clear-btn');
            if (clearBtn) clearBtn.addEventListener('click', function() {
                if (monacoEditor) monacoEditor.setValue('');
            });

            /* Format */
            var fmtBtn = $('mlp-ddb-format-btn');
            if (fmtBtn) fmtBtn.addEventListener('click', function() {
                if (monacoEditor) monacoEditor.setValue(formatSQL(monacoEditor.getValue()));
            });

            /* Examples menu */
            var exBtn  = $('mlp-ddb-example-btn');
            var exMenu = $('mlp-ddb-examples-menu');
            if (exBtn && exMenu) {
                exBtn.addEventListener('click', function(e) {
                    e.stopPropagation();
                    exMenu.style.display = exMenu.style.display === 'none' ? '' : 'none';
                });
                document.addEventListener('click', function() { if (exMenu) exMenu.style.display = 'none'; });
                exMenu.addEventListener('click', function(e) {
                    var item = e.target.closest('.mlp-ddb-ex-item');
                    if (!item) return;
                    var sql = item.getAttribute('data-sql') || '';
                    if (monacoEditor) monacoEditor.setValue(sql.replace(/&quot;/g, '"').replace(/&#39;/g,"'").replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>'));
                    exMenu.style.display = 'none';
                });
            }

            /* Result pane tabs */
            document.querySelectorAll('.mlp-ddb-rtab').forEach(function(tab) {
                tab.addEventListener('click', function() {
                    switchResultPane(tab.getAttribute('data-pane'));
                });
            });

            /* AI toggle */
            var aiToggle = $('mlp-ddb-ai-toggle-btn');
            var aiSidebar = $('mlp-ddb-ai-sidebar');
            var workspace = $('mlp-ddb-workspace');
            if (aiToggle && aiSidebar) {
                aiToggle.addEventListener('click', function() {
                    var open = aiSidebar.style.display !== 'none';
                    aiSidebar.style.display = open ? 'none' : '';
                    if (workspace) workspace.classList.toggle('has-ai', !open);
                });
            }
            var aiClose = $('mlp-ddb-ai-close');
            if (aiClose && aiSidebar) {
                aiClose.addEventListener('click', function() {
                    aiSidebar.style.display = 'none';
                    if (workspace) workspace.classList.remove('has-ai');
                });
            }

            /* AI send */
            var aiSend = $('mlp-ddb-ai-send');
            if (aiSend) aiSend.addEventListener('click', sendAIMessage);
            var aiInput = $('mlp-ddb-ai-input');
            if (aiInput) {
                aiInput.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendAIMessage(); }
                });
            }

            /* Publish button */
            var pubBtn   = $('mlp-ddb-publish-btn');
            var pubModal = $('mlp-ddb-publish-modal');
            if (pubBtn && pubModal) {
                pubBtn.addEventListener('click', function() { pubModal.style.display = ''; });
            }
            var pubClose = $('mlp-ddb-modal-close');
            var pubCancel= $('mlp-ddb-pub-cancel');
            if (pubClose && pubModal) pubClose.addEventListener('click', function() { pubModal.style.display = 'none'; });
            if (pubCancel && pubModal) pubCancel.addEventListener('click', function() { pubModal.style.display = 'none'; });
            if (pubModal) pubModal.addEventListener('click', function(e) { if (e.target === pubModal) pubModal.style.display = 'none'; });
            var pubConfirm = $('mlp-ddb-pub-confirm');
            if (pubConfirm) pubConfirm.addEventListener('click', publishProject);

            /* Gallery: delegated clicks */
            var galleryGrid = $('mlp-ddb-gallery-grid');
            if (galleryGrid) {
                galleryGrid.addEventListener('click', function(e) {
                    /* Load SQL into editor */
                    var loadBtn = e.target.closest('.mlp-ddb-card-load-btn');
                    if (loadBtn && monacoEditor) {
                        var sql = loadBtn.getAttribute('data-sql') || '';
                        monacoEditor.setValue(sql);
                        window.scrollTo({ top: 0, behavior: 'smooth' });
                        return;
                    }
                    /* Like */
                    var likeBtn = e.target.closest('.mlp-ddb-card-like-btn');
                    if (likeBtn) {
                        var token  = likeBtn.getAttribute('data-token');
                        var liked  = likeBtn.classList.contains('liked');
                        var body   = new URLSearchParams();
                        body.set('action', 'mlp_duckdb_react');
                        body.set('token', token);
                        body.set('state', liked ? '0' : '1');
                        fetch(MLP_DUCKDB_AJAX, { method: 'POST', body: body })
                            .then(function(r) { return r.json(); })
                            .then(function(resp) {
                                if (resp && resp.success) {
                                    likeBtn.classList.toggle('liked', !liked);
                                    likeBtn.textContent = '♥ ' + (resp.data.likes || 0);
                                }
                            });
                    }
                    /* Click anywhere on card (but not on buttons) to load */
                    var card = e.target.closest('.mlp-ddb-card');
                    if (card && !e.target.closest('button')) {
                        var loadB = card.querySelector('.mlp-ddb-card-load-btn');
                        if (loadB && monacoEditor) {
                            monacoEditor.setValue(loadB.getAttribute('data-sql') || '');
                            window.scrollTo({ top: 0, behavior: 'smooth' });
                        }
                    }
                });
            }

            /* Gallery: AI reply "Apply" buttons */
            var aiMessages = $('mlp-ddb-ai-messages');
            if (aiMessages) {
                aiMessages.addEventListener('click', function(e) {
                    var applyBtn = e.target.closest('.mlp-ddb-ai-apply-btn');
                    if (applyBtn && monacoEditor) {
                        ddbEditorUndo = monacoEditor.getValue();
                        monacoEditor.setValue(applyBtn.getAttribute('data-sql') || '');
                        showToastDdb('SQL applied to editor!', 'ok');
                    }
                    var undoBtn = e.target.closest('.mlp-ddb-ai-undo-btn');
                    if (undoBtn && monacoEditor) {
                        if (ddbEditorUndo !== '') {
                            monacoEditor.setValue(ddbEditorUndo);
                            ddbEditorUndo = '';
                            showToastDdb('Undo!', 'ok');
                        }
                    }
                });
            }

            /* Gallery search */
            var searchBtn = $('mlp-ddb-gallery-search-btn');
            var searchInput = $('mlp-ddb-gallery-search');
            if (searchBtn && searchInput) {
                searchBtn.addEventListener('click', function() {
                    galleryPage = 1;
                    loadGallery(1, searchInput.value.trim());
                });
                searchInput.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter') { galleryPage = 1; loadGallery(1, searchInput.value.trim()); }
                });
            }

            /* Gallery pagination */
            var pgn = $('mlp-ddb-gallery-pagination');
            if (pgn) {
                pgn.addEventListener('click', function(e) {
                    var btn = e.target.closest('.mlp-ddb-page-btn');
                    if (!btn) return;
                    var page   = parseInt(btn.getAttribute('data-page'), 10);
                    var search = btn.getAttribute('data-search') || '';
                    loadGallery(page, search);
                    document.getElementById('mlp-duckdb-gallery').scrollIntoView({ behavior: 'smooth' });
                });
            }
        }

        /* ── Boot ────────────────────────────────────────────────────────── */
        document.addEventListener('DOMContentLoaded', function() {
            if (!$('mlp-duckdb-root')) return;
            wireEvents();
            init();
            loadGallery(1, '');
        });

        /* ═══════════════════════════════════════════════════════════════════
         *  mlpOpenDuckDBEditor — full-screen overlay editor
         *  Called by mlp-projects.php when the user opens a DuckDB project.
         * ═══════════════════════════════════════════════════════════════════ */
        (function() {

        var LS_PROJECTS_KEY = 'mlp_projects';
        var overlayEditor   = null;   /* Monaco editor inside overlay */
        var overlayProjId   = null;
        var overlayDB       = null;   /* DuckDB connection for overlay */
        var overlayConn     = null;
        var overlayDBReady  = false;
        var overlayAiHistory = [];    /* AI chat history for overlay */

        /* ── Read/write localStorage projects (same format as mlp-projects.php) ─ */
        function getProjects() {
            try { return JSON.parse(localStorage.getItem(LS_PROJECTS_KEY) || '[]'); } catch(e) { return []; }
        }
        function saveProjects(arr) {
            try { localStorage.setItem(LS_PROJECTS_KEY, JSON.stringify(arr)); } catch(e) {}
        }
        function getProject(id) {
            var all = getProjects();
            for (var i = 0; i < all.length; i++) { if (all[i].id === id) return all[i]; }
            return null;
        }
        function saveProjectSQL(id, sql) {
            var all = getProjects();
            for (var i = 0; i < all.length; i++) {
                if (all[i].id === id) {
                    all[i].duckdb    = sql;
                    all[i].updatedAt = new Date().toISOString();
                    break;
                }
            }
            saveProjects(all);
        }

        /* ── Build the overlay DOM ──────────────────────────────────────── */
        function buildOverlay() {
            if (document.getElementById('mlp-ddb-overlay')) return;
            var ov = document.createElement('div');
            ov.id = 'mlp-ddb-overlay';
            ov.style.cssText = [
                'position:fixed;inset:0;z-index:99999;',
                'background:#0f172a;display:none;',
                'flex-direction:column;font-family:Inter,system-ui,sans-serif;'
            ].join('');
            ov.innerHTML = [
                /* Header bar */
                '<div id="mlp-ddb-ov-bar" style="',
                    'display:flex;align-items:center;gap:8px;',
                    'padding:8px 14px;',
                    'background:#1e293b;border-bottom:1px solid #334155;',
                    'flex-shrink:0;flex-wrap:wrap;">',
                  '<button id="mlp-ddb-ov-back" style="',
                      'display:inline-flex;align-items:center;gap:5px;',
                      'padding:5px 10px;background:transparent;border:1px solid #334155;',
                      'border-radius:6px;color:#94a3b8;font-size:12px;font-weight:600;cursor:pointer;',
                      'margin-right:4px;flex-shrink:0;">',
                    '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>',
                    'Projects',
                  '</button>',
                  '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" xmlns="http://www.w3.org/2000/svg">',
                    '<path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2z" fill="#FFBC00"/>',
                    '<path d="M8 8h8v2H8V8zM8 11h8v2H8v-2zM8 14h5v2H8v-2z" fill="#1e293b"/>',
                  '</svg>',
                  '<span id="mlp-ddb-ov-title" style="font-size:13px;font-weight:700;color:#fef3c7;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">DuckDB Editor</span>',
                  '<button id="mlp-ddb-ov-run" style="',
                      'display:inline-flex;align-items:center;gap:4px;',
                      'padding:5px 12px;background:#FFBC00;border:none;',
                      'border-radius:6px;color:#1e293b;font-size:12px;font-weight:700;cursor:pointer;">',
                    '&#9654; Run',
                  '</button>',
                  '<button id="mlp-ddb-ov-save" style="',
                      'padding:5px 12px;background:#3b82f6;border:none;',
                      'border-radius:6px;color:#fff;font-size:12px;font-weight:700;cursor:pointer;">',
                    '💾 Save',
                  '</button>',
                  '<button id="mlp-ddb-ov-ai" style="',
                      'padding:5px 12px;background:#4f46e5;border:none;',
                      'border-radius:6px;color:#fff;font-size:12px;font-weight:700;cursor:pointer;">',
                    '✨ AI',
                  '</button>',
                  '<div id="mlp-ddb-ov-status" style="font-size:11px;color:#94a3b8;display:flex;align-items:center;gap:4px;">',
                    '<span id="mlp-ddb-ov-dot" style="width:8px;height:8px;border-radius:50%;background:#f59e0b;display:inline-block;"></span>',
                    '<span id="mlp-ddb-ov-stxt">Loading…</span>',
                  '</div>',
                '</div>',

                /* Main area: editor | results | AI sidebar */
                '<div id="mlp-ddb-ov-body" style="display:flex;flex:1;overflow:hidden;">',

                  /* Editor panel */
                  '<div id="mlp-ddb-ov-editor-wrap" style="',
                      'flex:1;min-width:0;border-right:1px solid #334155;position:relative;">',
                    '<div id="mlp-ddb-ov-monaco" style="width:100%;height:100%;"></div>',
                  '</div>',

                  /* Results panel */
                  '<div id="mlp-ddb-ov-results-wrap" style="',
                      'width:380px;min-width:220px;display:flex;flex-direction:column;',
                      'background:#0f172a;">',
                    '<div style="display:flex;align-items:center;gap:2px;padding:6px 10px 0;',
                        'border-bottom:1px solid #334155;background:#1e293b;">',
                      '<button class="mlp-ddb-ov-rtab active" data-ov-pane="results" style="',
                          'padding:5px 12px;background:transparent;border:none;',
                          'border-bottom:2px solid #FFBC00;color:#FFBC00;',
                          'font-size:12px;font-weight:600;cursor:pointer;">Results</button>',
                      '<button class="mlp-ddb-ov-rtab" data-ov-pane="schema" style="',
                          'padding:5px 12px;background:transparent;border:none;',
                          'border-bottom:2px solid transparent;color:#94a3b8;',
                          'font-size:12px;font-weight:600;cursor:pointer;">Schema</button>',
                      '<button class="mlp-ddb-ov-rtab" data-ov-pane="msgs" style="',
                          'padding:5px 12px;background:transparent;border:none;',
                          'border-bottom:2px solid transparent;color:#94a3b8;',
                          'font-size:12px;font-weight:600;cursor:pointer;">Messages</button>',
                      '<span id="mlp-ddb-ov-etime" style="margin-left:auto;font-size:11px;color:#64748b;padding-right:4px;"></span>',
                    '</div>',
                    '<div id="mlp-ddb-ov-pane-results" style="flex:1;overflow:auto;padding:0;">',
                      '<div id="mlp-ddb-ov-empty" style="display:flex;flex-direction:column;',
                          'align-items:center;justify-content:center;height:100%;',
                          'color:#64748b;font-size:13px;gap:8px;padding:20px;text-align:center;">',
                        '<svg viewBox="0 0 24 24" fill="none" stroke="#475569" stroke-width="1.5" width="36" height="36">',
                          '<ellipse cx="12" cy="5" rx="9" ry="3"/>',
                          '<path d="M3 5v6c0 1.657 4.03 3 9 3s9-1.343 9-3V5"/>',
                          '<path d="M3 11v6c0 1.657 4.03 3 9 3s9-1.343 9-3v-6"/>',
                        '</svg>',
                        '<p>Run a query to see results</p>',
                      '</div>',
                      '<div id="mlp-ddb-ov-table-wrap" style="display:none;flex-direction:column;height:100%;">',
                        '<div id="mlp-ddb-ov-rcount" style="font-size:11px;color:#64748b;padding:5px 12px;',
                            'border-bottom:1px solid #334155;background:#1e293b;"></div>',
                        '<div style="overflow:auto;flex:1;">',
                          '<table id="mlp-ddb-ov-table" style="width:100%;border-collapse:collapse;font-size:12px;',
                              'color:#e2e8f0;white-space:nowrap;font-family:\'JetBrains Mono\',monospace;">',
                            '<thead id="mlp-ddb-ov-thead" style="position:sticky;top:0;"></thead>',
                            '<tbody id="mlp-ddb-ov-tbody"></tbody>',
                          '</table>',
                        '</div>',
                      '</div>',
                    '</div>',
                    '<div id="mlp-ddb-ov-pane-schema" style="flex:1;overflow:auto;padding:0;display:none;">',
                      '<div id="mlp-ddb-ov-schema-empty" style="padding:20px;color:#64748b;font-size:12px;text-align:center;">',
                        'Create tables to see schema here.',
                      '</div>',
                      '<div id="mlp-ddb-ov-schema-list"></div>',
                    '</div>',
                    '<div id="mlp-ddb-ov-pane-msgs" style="flex:1;overflow:auto;display:none;">',
                      '<div id="mlp-ddb-ov-msgs-log" style="padding:10px 14px;font-size:12px;',
                          'font-family:\'JetBrains Mono\',monospace;display:flex;flex-direction:column;gap:4px;">',
                        '<p style="color:#64748b;">DuckDB loading…</p>',
                      '</div>',
                    '</div>',
                  '</div>',

                  /* AI sidebar (hidden by default) */
                  '<div id="mlp-ddb-ov-ai-sidebar" style="',
                      'width:300px;border-left:1px solid #334155;',
                      'display:none;flex-direction:column;background:#0f172a;">',
                    '<div style="display:flex;align-items:center;justify-content:space-between;',
                        'padding:10px 14px;border-bottom:1px solid #334155;background:#1e293b;">',
                      '<span style="font-size:13px;font-weight:700;color:#e2e8f0;">AI Chat</span>',
                      '<button id="mlp-ddb-ov-ai-close" style="background:none;border:none;color:#94a3b8;cursor:pointer;font-size:14px;">✕</button>',
                    '</div>',
                    '<div id="mlp-ddb-ov-ai-msgs" style="flex:1;overflow-y:auto;padding:12px 10px;',
                        'display:flex;flex-direction:column;gap:10px;">',
                      '<div style="padding:9px 12px;border-radius:8px;background:#263347;color:#e2e8f0;font-size:12px;line-height:1.6;">',
                        'Hi! Ask me to write, fix, or explain DuckDB SQL queries.',
                      '</div>',
                    '</div>',
                    '<div style="display:flex;gap:6px;padding:8px 10px;border-top:1px solid #334155;background:#1e293b;">',
                      '<textarea id="mlp-ddb-ov-ai-input" rows="2" placeholder="Ask about DuckDB SQL…" style="',
                          'flex:1;background:#0f172a;border:1px solid #334155;border-radius:6px;',
                          'color:#e2e8f0;font-size:12px;padding:6px 9px;resize:none;font-family:inherit;">',
                      '</textarea>',
                      '<button id="mlp-ddb-ov-ai-send" style="',
                          'padding:6px 12px;background:#3b82f6;color:#fff;border:none;',
                          'border-radius:6px;font-size:12px;font-weight:700;cursor:pointer;align-self:flex-end;">',
                        'Send',
                      '</button>',
                    '</div>',
                  '</div>',

                '</div>'  /* /#mlp-ddb-ov-body */
            ].join('');
            document.body.appendChild(ov);
            wireOverlayEvents(ov);
        }

        function ovLog(msg, cls) {
            var el = document.getElementById('mlp-ddb-ov-msgs-log');
            if (!el) return;
            var p = document.createElement('p');
            p.style.color = cls === 'ok' ? '#22c55e' : cls === 'error' ? '#ef4444' : '#94a3b8';
            p.textContent = msg;
            el.appendChild(p);
            el.scrollTop = el.scrollHeight;
        }
        function ovSetStatus(txt, state) {
            var dot = document.getElementById('mlp-ddb-ov-dot');
            var stxt = document.getElementById('mlp-ddb-ov-stxt');
            if (dot) dot.style.background = state === 'ready' ? '#22c55e' : state === 'error' ? '#ef4444' : '#f59e0b';
            if (stxt) stxt.textContent = txt || '';
        }
        function ovSwitchPane(which) {
            ['results','schema','msgs'].forEach(function(name) {
                var pane = document.getElementById('mlp-ddb-ov-pane-' + name);
                var tabs = document.querySelectorAll('[data-ov-pane="' + name + '"]');
                var isActive = (name === which);
                if (pane) pane.style.display = isActive ? (name === 'results' ? 'block' : 'block') : 'none';
                tabs.forEach(function(t) {
                    t.style.borderBottomColor = isActive ? '#FFBC00' : 'transparent';
                    t.style.color = isActive ? '#FFBC00' : '#94a3b8';
                });
            });
        }

        function ovRenderResults(cols, rows) {
            var empty = document.getElementById('mlp-ddb-ov-empty');
            var wrap  = document.getElementById('mlp-ddb-ov-table-wrap');
            var thead = document.getElementById('mlp-ddb-ov-thead');
            var tbody = document.getElementById('mlp-ddb-ov-tbody');
            var rcount= document.getElementById('mlp-ddb-ov-rcount');
            if (empty) empty.style.display = 'none';
            if (wrap)  { wrap.style.display = 'flex'; }
            var escH = function(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); };
            thead.innerHTML = '<tr>' + cols.map(function(c){
                return '<th style="padding:7px 12px;text-align:left;font-weight:700;color:#94a3b8;background:#1e293b;border-bottom:1px solid #334155;font-size:11px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;">' + escH(c) + '</th>';
            }).join('') + '</tr>';
            tbody.innerHTML = rows.slice(0, 5000).map(function(row){
                return '<tr>' + cols.map(function(c){
                    var v = row[c];
                    if (v === null || v === undefined) return '<td style="padding:5px 12px;border-bottom:1px solid rgba(51,65,85,.5);"><span style="color:#64748b;font-style:italic;">NULL</span></td>';
                    if (typeof v === 'bigint') v = v.toString();
                    if (typeof v === 'object') v = JSON.stringify(v);
                    return '<td style="padding:5px 12px;border-bottom:1px solid rgba(51,65,85,.5);">' + escH(String(v)) + '</td>';
                }).join('') + '</tr>';
            }).join('');
            if (rcount) rcount.textContent = rows.length + ' row' + (rows.length !== 1 ? 's' : '') + (rows.length > 5000 ? ' (showing first 5,000)' : '');
        }

        function ovRunQuery() {
            if (!overlayConn) { ovLog('DuckDB not ready yet.', 'error'); return; }
            var sql = overlayEditor ? overlayEditor.getValue() : '';
            if (!sql.trim()) return;
            var runBtn = document.getElementById('mlp-ddb-ov-run');
            if (runBtn) { runBtn.disabled = true; runBtn.textContent = '⏳ Running…'; }
            var t0 = performance.now();
            ovSwitchPane('results');
            overlayConn.query(sql)
                .then(function(result) {
                    var elapsed = ((performance.now() - t0) / 1000).toFixed(3);
                    var etEl = document.getElementById('mlp-ddb-ov-etime');
                    if (etEl) etEl.textContent = elapsed + 's';
                    var schema  = result.schema;
                    var batches = result.batches;
                    var rows = [];
                    if (batches) {
                        batches.forEach(function(batch) {
                            for (var r = 0; r < batch.numRows; r++) {
                                var row = {};
                                schema.fields.forEach(function(field, ci) {
                                    var col = batch.getChildAt(ci);
                                    row[field.name] = col ? col.get(r) : null;
                                });
                                rows.push(row);
                            }
                        });
                    }
                    ovRenderResults(schema.fields.map(function(f){ return f.name; }), rows);
                    ovLog('OK — ' + rows.length + ' row(s) in ' + elapsed + 's', 'ok');
                    ovRefreshSchema();
                })
                .catch(function(err) {
                    var emptyEl = document.getElementById('mlp-ddb-ov-empty');
                    var wrapEl  = document.getElementById('mlp-ddb-ov-table-wrap');
                    if (wrapEl)  wrapEl.style.display = 'none';
                    if (emptyEl) {
                        emptyEl.style.display = '';
                        emptyEl.innerHTML = '<p style="color:#ef4444;font-family:monospace;font-size:12px;max-width:320px;word-break:break-word;">' + err.message.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</p>';
                    }
                    ovLog('Error: ' + err.message, 'error');
                    ovSwitchPane('msgs');
                })
                .finally(function() {
                    if (runBtn) { runBtn.disabled = false; runBtn.innerHTML = '&#9654; Run'; }
                });
        }

        function ovRefreshSchema() {
            if (!overlayConn) return;
            overlayConn.query("SELECT table_name, column_name, data_type FROM information_schema.columns ORDER BY table_name, ordinal_position")
                .then(function(result) {
                    var tables = {};
                    if (result.batches) {
                        result.batches.forEach(function(batch) {
                            for (var r = 0; r < batch.numRows; r++) {
                                var tn = batch.getChildAt(0).get(r);
                                var cn = batch.getChildAt(1).get(r);
                                var dt = batch.getChildAt(2).get(r);
                                if (!tables[tn]) tables[tn] = [];
                                tables[tn].push({ name: cn, type: dt });
                            }
                        });
                    }
                    var list  = document.getElementById('mlp-ddb-ov-schema-list');
                    var empty = document.getElementById('mlp-ddb-ov-schema-empty');
                    var escH  = function(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); };
                    var keys  = Object.keys(tables);
                    if (!keys.length) { if (empty) empty.style.display = ''; if (list) list.innerHTML = ''; return; }
                    if (empty) empty.style.display = 'none';
                    if (list) {
                        list.innerHTML = keys.map(function(tn){
                            return '<div style="margin:10px 12px;border:1px solid #334155;border-radius:6px;overflow:hidden;">' +
                                '<div style="padding:7px 12px;background:#263347;font-size:12px;font-weight:700;color:#FFBC00;">📋 ' + escH(tn) + '</div>' +
                                tables[tn].map(function(c){
                                    return '<div style="display:flex;gap:10px;padding:5px 12px;font-size:11px;border-bottom:1px solid rgba(51,65,85,.4);">' +
                                        '<span style="color:#e2e8f0;font-weight:600;font-family:monospace;">' + escH(c.name) + '</span>' +
                                        '<span style="color:#3b82f6;font-family:monospace;">' + escH(c.type||'') + '</span>' +
                                    '</div>';
                                }).join('') +
                            '</div>';
                        }).join('');
                    }
                }).catch(function(){});
        }

        function ovSendAI() {
            var input    = document.getElementById('mlp-ddb-ov-ai-input');
            var sendBtn  = document.getElementById('mlp-ddb-ov-ai-send');
            var messages = document.getElementById('mlp-ddb-ov-ai-msgs');
            if (!input || !messages) return;
            var userMsg = input.value.trim();
            if (!userMsg) return;
            input.value = '';

            var escH = function(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); };
            var escA = function(s){ return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); };

            /* User bubble — suppressed on captcha auto-send (already shown before gate) */
            var _autoOv = mlpDdbTsAutoSend; mlpDdbTsAutoSend = false;
            if (!_autoOv) {
                var ub = document.createElement('div');
                ub.style.cssText = 'padding:9px 12px;border-radius:8px;background:#3b82f6;color:#fff;font-size:12px;line-height:1.6;align-self:flex-end;max-width:95%;word-break:break-word;';
                ub.textContent = userMsg;
                messages.appendChild(ub);
                messages.scrollTop = messages.scrollHeight;
            }

            if (sendBtn) sendBtn.disabled = true;

            /* Turnstile gate — show once before first message if configured */
            if (MLP_DUCKDB_TS_SITEKEY && !mlpDdbTsVerified) {
                mlpDdbTsPending = userMsg;
                if (sendBtn) sendBtn.disabled = false;
                showTurnstileGate('mlp-ddb-ov-ai-msgs', 'mlp-ddb-ov-ts-gate');
                return;
            }

            /* Track history */
            overlayAiHistory.push({ role: 'user', content: userMsg });

            var currentSQL = overlayEditor ? overlayEditor.getValue() : '';

            var body = new URLSearchParams();
            body.set('action',   'mlp_ai_chat_duckdb');
            body.set('nonce',    MLP_DUCKDB_NONCE);
            body.set('message',  userMsg);
            body.set('sql_code', currentSQL);
            body.set('provider', 'cerebras');
            body.set('history',  JSON.stringify(overlayAiHistory.slice(-10)));
            if (mlpDdbTsToken) { body.set('turnstile_token', mlpDdbTsToken); mlpDdbTsToken = ''; }

            /* Thinking bubble */
            var thinkBub = document.createElement('div');
            thinkBub.style.cssText = 'padding:9px 12px;border-radius:8px;background:#263347;display:flex;align-items:center;gap:6px;';
            thinkBub.innerHTML = THINKING_HTML;
            messages.appendChild(thinkBub);
            messages.scrollTop = messages.scrollHeight;

            fetch(MLP_DUCKDB_AJAX, { method: 'POST', body: body })
                .then(function(r){ return r.json(); })
                .then(function(resp) {
                    if (thinkBub.parentNode) thinkBub.parentNode.removeChild(thinkBub);
                    if (resp && resp.success && resp.data && resp.data.reply) {
                        var reply = resp.data.reply;
                        overlayAiHistory.push({ role: 'assistant', content: reply });
                        var bb = document.createElement('div');
                        bb.style.cssText = 'padding:9px 12px;border-radius:8px;background:#263347;color:#e2e8f0;font-size:12px;line-height:1.6;align-self:flex-start;max-width:95%;word-break:break-word;';
                        /* Two-pass render: extract code blocks before \n→<br> so data-sql stays clean */
                        var _ovBlocks = [];
                        var html = reply.replace(/```(?:sql|SQL)?\n?([\s\S]*?)```/g, function(_, code) {
                            var raw = code.trim();
                            _ovBlocks.push(raw);
                            return '\x01OVBLK' + (_ovBlocks.length - 1) + '\x01';
                        });
                        html = escH(html);
                        html = html.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>');
                        html = html.replace(/`([^`]+)`/g,'<code style="background:rgba(0,0,0,.3);padding:1px 4px;border-radius:3px;font-size:11px;">$1</code>');
                        html = html.replace(/\n/g,'<br>');
                        html = html.replace(/\x01OVBLK(\d+)\x01/g, function(_, i) {
                            var raw = _ovBlocks[parseInt(i)];
                            return '<pre style="background:rgba(0,0,0,.3);border-radius:5px;padding:8px;overflow-x:auto;font-size:11px;margin:6px 0 0;white-space:pre-wrap;">' + escH(raw) + '</pre>' +
                                '<button class="mlp-ddb-ov-apply" data-sql="' + escA(raw) + '" style="display:inline-block;margin-top:6px;padding:4px 10px;background:#FFBC00;color:#1e293b;border:none;border-radius:5px;font-size:11px;font-weight:700;cursor:pointer;">Apply to Editor</button>' +
                                '<button class="mlp-ddb-ov-undo" style="display:inline-block;margin-top:6px;margin-left:4px;padding:4px 10px;background:rgba(255,255,255,0.08);color:#94a3b8;border:1px solid #334155;border-radius:5px;font-size:11px;font-weight:600;cursor:pointer;">Undo</button>';
                        });
                        bb.innerHTML = html;
                        messages.appendChild(bb);
                        messages.scrollTop = messages.scrollHeight;
                    } else {
                        var msg = (resp && resp.data && resp.data.message) ? resp.data.message : 'Sorry, could not get a response.';
                        var eb = document.createElement('div');
                        eb.style.cssText = 'padding:9px 12px;border-radius:8px;background:#263347;color:#fbbf24;font-size:12px;';
                        eb.textContent = msg;
                        messages.appendChild(eb);
                        messages.scrollTop = messages.scrollHeight;
                    }
                })
                .catch(function(){
                    if (thinkBub.parentNode) thinkBub.parentNode.removeChild(thinkBub);
                    var eb = document.createElement('div');
                    eb.style.cssText = 'padding:9px 12px;border-radius:8px;background:#263347;color:#ef4444;font-size:12px;';
                    eb.textContent = 'Network error. Please try again.';
                    messages.appendChild(eb);
                })
                .finally(function(){ if (sendBtn) sendBtn.disabled = false; });
        }

        function goBackToProjects(ov) {
            if (overlayProjId && overlayEditor) {
                saveProjectSQL(overlayProjId, overlayEditor.getValue());
            }
            document.documentElement.classList.remove('mlp-ddb-active');
            ov.style.display = 'none';
            overlayProjId = null;
            if (typeof window.mlpProjectsOpen === 'function') {
                window.mlpProjectsOpen();
            }
        }

        function wireOverlayEvents(ov) {
            /* ← Projects button */
            var backBtn = document.getElementById('mlp-ddb-ov-back');
            if (backBtn) backBtn.addEventListener('click', function() {
                goBackToProjects(ov);
            });
            /* ESC → back to projects */
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && ov.style.display !== 'none') {
                    goBackToProjects(ov);
                }
            });
            /* Run */
            var runBtn = document.getElementById('mlp-ddb-ov-run');
            if (runBtn) runBtn.addEventListener('click', ovRunQuery);
            /* Save */
            var saveBtn = document.getElementById('mlp-ddb-ov-save');
            if (saveBtn) saveBtn.addEventListener('click', function() {
                if (overlayProjId && overlayEditor) {
                    saveProjectSQL(overlayProjId, overlayEditor.getValue());
                    /* Brief feedback */
                    saveBtn.textContent = '✓ Saved!';
                    saveBtn.style.background = '#22c55e';
                    setTimeout(function() { saveBtn.textContent = '💾 Save'; saveBtn.style.background = '#3b82f6'; }, 1500);
                }
            });
            /* Result pane tabs */
            ov.addEventListener('click', function(e) {
                var tab = e.target.closest('[data-ov-pane]');
                if (tab) ovSwitchPane(tab.getAttribute('data-ov-pane'));
                /* Apply AI SQL */
                var applyBtn = e.target.closest('.mlp-ddb-ov-apply');
                if (applyBtn && overlayEditor) {
                    ovEditorUndo = overlayEditor.getValue();
                    overlayEditor.setValue(applyBtn.getAttribute('data-sql') || '');
                }
                var undoBtn = e.target.closest('.mlp-ddb-ov-undo');
                if (undoBtn && overlayEditor) {
                    if (ovEditorUndo !== '') {
                        overlayEditor.setValue(ovEditorUndo);
                        ovEditorUndo = '';
                    }
                }
            });
            /* AI toggle */
            var aiBtn = document.getElementById('mlp-ddb-ov-ai');
            var aiSidebar = document.getElementById('mlp-ddb-ov-ai-sidebar');
            if (aiBtn && aiSidebar) {
                aiBtn.addEventListener('click', function() {
                    aiSidebar.style.display = aiSidebar.style.display === 'none' ? 'flex' : 'none';
                    aiSidebar.style.flexDirection = 'column';
                });
            }
            var aiClose = document.getElementById('mlp-ddb-ov-ai-close');
            if (aiClose && aiSidebar) aiClose.addEventListener('click', function() { aiSidebar.style.display = 'none'; });
            /* AI send */
            var aiSend = document.getElementById('mlp-ddb-ov-ai-send');
            if (aiSend) aiSend.addEventListener('click', ovSendAI);
            var aiInput = document.getElementById('mlp-ddb-ov-ai-input');
            if (aiInput) aiInput.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ovSendAI(); }
            });
        }

        function initOverlayMonaco(sql) {
            var container = document.getElementById('mlp-ddb-ov-monaco');
            if (!container) return;
            if (overlayEditor) {
                overlayEditor.setValue(sql || '');
                return;
            }
            function tryCreate(tries) {
                tries = tries || 0;
                if (typeof require !== 'undefined' && typeof monaco !== 'undefined') {
                    overlayEditor = monaco.editor.create(container, {
                        value: sql || '',
                        language: 'sql',
                        theme: 'vs-dark',
                        fontSize: 13,
                        fontFamily: "'JetBrains Mono','Fira Code',Menlo,monospace",
                        fontLigatures: true,
                        minimap: { enabled: false },
                        scrollBeyondLastLine: false,
                        wordWrap: 'on',
                        automaticLayout: true,
                        padding: { top: 12, bottom: 12 },
                    });
                    overlayEditor.addCommand(
                        monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter,
                        ovRunQuery
                    );
                    overlayEditor.addCommand(
                        monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS,
                        function() {
                            if (overlayProjId) saveProjectSQL(overlayProjId, overlayEditor.getValue());
                        }
                    );
                    /* Auto-save on change (debounced) */
                    var _saveTimer = null;
                    overlayEditor.onDidChangeModelContent(function() {
                        if (_saveTimer) clearTimeout(_saveTimer);
                        _saveTimer = setTimeout(function() {
                            if (overlayProjId && overlayEditor) {
                                saveProjectSQL(overlayProjId, overlayEditor.getValue());
                            }
                        }, 1500);
                    });
                } else if (tries < 60) {
                    setTimeout(function(){ tryCreate(tries + 1); }, 200);
                }
            }
            tryCreate();
        }

        function initOverlayDuckDB() {
            if (overlayDBReady && overlayConn) { ovSetStatus('Ready', 'ready'); return; }
            ovSetStatus('Loading DuckDB…', '');

            /* Reuse already-loaded module if available */
            var ddbPromise = window._mlpDuckdb
                ? Promise.resolve(window._mlpDuckdb)
                : import(DUCKDB_ESM_URL).then(function(m) { window._mlpDuckdb = m; return m; });

            ddbPromise
                .then(function(duckdb) {
                    /* Force EH bundle — avoids COI/pthreads which hangs without
                       Cross-Origin-Opener-Policy headers (most WordPress hosts). */
                    var bundle    = duckdb.getJsDelivrBundles().eh;
                    var workerUrl = URL.createObjectURL(
                        new Blob(['importScripts("' + bundle.mainWorker + '");'],
                                 { type: 'application/javascript' })
                    );
                    var logger = new duckdb.ConsoleLogger();
                    var worker = new Worker(workerUrl);
                    overlayDB  = new duckdb.AsyncDuckDB(logger, worker);
                    return overlayDB.instantiate(bundle.mainModule)
                        .then(function() { return overlayDB.connect(); })
                        .then(function(c) {
                            overlayConn    = c;
                            overlayDBReady = true;
                            URL.revokeObjectURL(workerUrl);
                            ovSetStatus('Ready', 'ready');
                            ovLog('DuckDB ready.', 'ok');
                        });
                })
                .catch(function(err) {
                    ovSetStatus('CDN error', 'error');
                    ovLog('DuckDB load error: ' + (err && err.message ? err.message : err), 'error');
                });
        }

        /* ── The global entry point called by mlp-projects.php ─────────── */
        window.mlpOpenDuckDBEditor = function(projectId) {
            buildOverlay();
            var ov = document.getElementById('mlp-ddb-overlay');
            if (!ov) return;

            overlayProjId = projectId;
            var proj = getProject(projectId);
            var sql  = proj ? (proj.duckdb || proj.duckdbSql || '') : '';
            var name = proj ? (proj.name || 'DuckDB Project') : 'DuckDB Editor';

            /* Update title */
            var titleEl = document.getElementById('mlp-ddb-ov-title');
            if (titleEl) titleEl.textContent = '🦆 ' + name;

            /* Clear previous results */
            var emptyEl = document.getElementById('mlp-ddb-ov-empty');
            var wrapEl  = document.getElementById('mlp-ddb-ov-table-wrap');
            var msgsLog = document.getElementById('mlp-ddb-ov-msgs-log');
            if (emptyEl) { emptyEl.style.display = ''; emptyEl.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="#475569" stroke-width="1.5" width="36" height="36"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v6c0 1.657 4.03 3 9 3s9-1.343 9-3V5"/><path d="M3 11v6c0 1.657 4.03 3 9 3s9-1.343 9-3v-6"/></svg><p>Run a query to see results</p>'; }
            if (wrapEl)  wrapEl.style.display = 'none';
            if (msgsLog) msgsLog.innerHTML = '<p style="color:#64748b;">DuckDB loading…</p>';

            /* Show overlay */
            document.documentElement.classList.add('mlp-ddb-active');
            ov.style.display = 'flex';
            ov.style.flexDirection = 'column';

            /* Init Monaco then DuckDB */
            initOverlayMonaco(sql);
            initOverlayDuckDB();
        };

        })(); /* end overlay IIFE */

        /* ── Boot ────────────────────────────────────────────────────────── */
        document.addEventListener('DOMContentLoaded', function() {
            if (!$('mlp-duckdb-root')) return;
            wireEvents();
            init();
            loadGallery(1, '');
        });

        })();
        </script>
        <?php
    }
}

/* ── Bootstrap ────────────────────────────────────────────────────────────── */
add_action( 'plugins_loaded', [ 'MLP_DuckDB', 'init' ] );
