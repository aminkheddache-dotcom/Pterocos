<?php
/**
 * MLP AI Chat SQL Edition
 * Adds AI chat assistant for SQL editor. SQLite/database-specific system prompt.
 * Uses same providers as HTML/Python chat.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

add_action( 'wp_ajax_mlp_ai_chat_sql',        'mlp_ai_chat_sql_handler' );
add_action( 'wp_ajax_nopriv_mlp_ai_chat_sql', 'mlp_ai_chat_sql_handler' );

function mlp_ai_chat_sql_handler() {
    $_mlp_guard_key   = 'mlp_in_flight_sql';
    $_mlp_guard_group = 'mlp';
    $_mlp_max         = 4;
    $_mlp_in_flight   = (int) wp_cache_get( $_mlp_guard_key, $_mlp_guard_group );
    if ( $_mlp_in_flight >= $_mlp_max ) {
        wp_send_json_error( [ 'message' => 'Please try again later.' ], 503 );
        return;
    }
    wp_cache_set( $_mlp_guard_key, $_mlp_in_flight + 1, $_mlp_guard_group, 120 );
    register_shutdown_function( function() use ( $_mlp_guard_key, $_mlp_guard_group ) {
        $current = (int) wp_cache_get( $_mlp_guard_key, $_mlp_guard_group );
        wp_cache_set( $_mlp_guard_key, max( 0, $current - 1 ), $_mlp_guard_group, 120 );
    } );

    @set_time_limit( 45 );

    $ip = sanitize_text_field(
        $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'
    );
    if ( str_contains( $ip, ',' ) ) { $ip = trim( explode( ',', $ip )[0] ); }
    $ip_key = md5( $ip );

    /* Turnstile verification */
    $_ts_verified_key = 'mlp_ts_v_sql_' . $ip_key;
    if ( ! get_transient( $_ts_verified_key ) ) {
        $ts_token  = sanitize_text_field( wp_unslash( $_POST['turnstile_token'] ?? '' ) );
        $ts_secret = defined( 'MLP_TURNSTILE_SECRET_KEY' ) ? MLP_TURNSTILE_SECRET_KEY : '';
        if ( empty( $ts_token ) ) {
            wp_send_json_error( [ 'message' => 'Please complete the human verification first.' ], 403 );
            return;
        }
        $ts_res  = wp_remote_post( 'https://challenges.cloudflare.com/turnstile/v0/siteverify', [
            'timeout' => 8,
            'headers' => [ 'Content-Type' => 'application/json' ],
            'body'    => wp_json_encode( [ 'secret' => $ts_secret, 'response' => $ts_token ] ),
        ] );
        $ts_body = json_decode( wp_remote_retrieve_body( $ts_res ), true );
        if ( empty( $ts_body['success'] ) ) {
            wp_send_json_error( [ 'message' => 'Human verification failed. Please try again.' ], 403 );
            return;
        }
        set_transient( $_ts_verified_key, 1, DAY_IN_SECONDS );
    }
    unset( $_ts_verified_key );

    /* Banned IPs */
    $_banned_fast = wp_cache_get( 'mlp_banned_ips_sql', 'mlp' );
    if ( false === $_banned_fast ) {
        $_banned_fast = (array) get_option( 'mlp_banned_ips_sql', [] );
        wp_cache_set( 'mlp_banned_ips_sql', $_banned_fast, 'mlp', 300 );
    }
    if ( in_array( $ip, $_banned_fast, true ) ) {
        wp_send_json_error( [ 'message' => 'Access denied.' ], 403 );
        return;
    }
    unset( $_banned_fast );

    /* Burst limit: 5 requests per 10 seconds */
    $burst_key  = 'mlp_burst_sql_' . $ip_key;
    $burst_data = get_transient( $burst_key );
    if ( ! is_array( $burst_data ) ) { $burst_data = []; }
    $now        = time();
    $burst_data = array_filter( $burst_data, fn( $t ) => $now - $t < 10 );
    if ( count( $burst_data ) >= 5 ) {
        wp_send_json_error( [ 'message' => 'Too many requests. Please slow down.' ], 429 );
        return;
    }
    $burst_data[] = $now;
    set_transient( $burst_key, array_values( $burst_data ), 10 );

    /* Hourly limit: 40 requests */
    $hour_key   = 'mlp_hr_sql_' . $ip_key;
    $hour_count = (int) get_transient( $hour_key );
    if ( $hour_count >= 40 ) {
        wp_send_json_error( [ 'message' => 'Hourly limit reached. Please try again later.' ], 429 );
        return;
    }
    set_transient( $hour_key, $hour_count + 1, HOUR_IN_SECONDS );

    /* Strike system */
    $banned       = (array) get_option( 'mlp_banned_ips_sql', [] );
    $strike_key   = 'mlp_strikes_sql_' . $ip_key;
    $strike_count = (int) get_transient( $strike_key );
    if ( $hour_count + 1 >= 40 ) {
        $strike_count++;
        set_transient( $strike_key, $strike_count, DAY_IN_SECONDS );
        if ( $strike_count >= 3 ) {
            $banned[] = $ip;
            update_option( 'mlp_banned_ips_sql', array_unique( $banned ) );
            wp_cache_delete( 'mlp_banned_ips_sql', 'mlp' );
        }
    }

    /* Origin check */
    $referer   = wp_get_referer();
    $origin_ok = ! empty( $referer ) && (
        str_contains( $referer, home_url() ) ||
        str_contains( $referer, wp_parse_url( home_url(), PHP_URL_HOST ) )
    );
    if ( ! $origin_ok ) {
        $burst_data[] = $now;
        set_transient( $burst_key, $burst_data, 10 );
    }

    /* Inputs */
    $user_msg = sanitize_textarea_field( wp_unslash( $_POST['message'] ?? '' ) );
    $sql_code = wp_unslash( $_POST['sql_code'] ?? '' );
    $history  = json_decode( wp_unslash( $_POST['history'] ?? '[]' ), true );
    if ( ! is_array( $history ) ) { $history = []; }

    if ( empty( $user_msg ) ) {
        wp_send_json_error( [ 'message' => 'Message cannot be empty.' ], 400 );
        return;
    }
    if ( strlen( $user_msg ) > 8000 ) {
        wp_send_json_error( [ 'message' => 'Message too long (max 8000 chars).' ], 400 );
        return;
    }

    /* SQL code context */
    $sql_t        = trim( $sql_code );
    $code_context = '';
    if ( $sql_t ) {
        $code_context = "\n\n--- CURRENT SQL CODE ---\n" . substr( $sql_t, 0, 6000 ) . "\n--- END OF SQL ---\n";
    }
    unset( $sql_t );

    /* System prompt */
    $system = <<<'SYS'
You are an elite SQLite/SQL developer embedded inside a live Monaco SQL editor. The environment runs SQLite 3 entirely in the browser via sql.js (WebAssembly). You have deep expertise in SQL, database design, query optimization, and SQLite-specific features.

━━━ YOUR ROLE ━━━
You help users write, debug, optimize, and understand SQL queries and database schemas. You always read the provided editor SQL before answering — never assume what code looks like.

━━━ ENVIRONMENT FACTS ━━━
• Runtime: SQLite 3 (in-browser via sql.js — no server)
• Supported: All standard SQLite syntax, CTEs, window functions, JSON functions, FTS5
• Not supported: stored procedures, user-defined functions (unless via sql.js API), network calls, file I/O
• Database is in-memory: data resets on page refresh; only SQL code is saved

━━━ CODE OUTPUT FORMAT (MANDATORY) ━━━
1. When producing or modifying SQL, wrap it in a labeled SQL fence:
   ```sql
   -- full SQL here
   ```
2. Always output the COMPLETE file content inside the fence — never partial snippets.
3. If you only explain without changing SQL, use zero code fences.
4. CRITICAL: If the user asks you to build, create, fix, change, or modify ANYTHING in their SQL — output the full modified SQL inside fences. A response without code fences when SQL was requested is a failure.

━━━ RESPONSE QUALITY RULES ━━━
• For schema design: think about normalization, indexes, and constraints.
• For queries: consider performance — suggest indexes where appropriate.
• For bugs: identify root cause first, then fix with explanation.
• For optimization: explain why the optimized version is faster.
• Always include CREATE TABLE before INSERT statements so queries are runnable standalone.
• Prefer explicit column lists in INSERT and SELECT over wildcards when clarity helps.
• Use meaningful table and column names.
• Add comments for complex queries.
• Mention SQLite-specific limitations when relevant (e.g., no RIGHT JOIN in old versions, limited ALTER TABLE).

━━━ TONE & STYLE ━━━
• Be direct, confident, and concise. No filler phrases.
• Use markdown: **bold** for key terms, `inline code` for identifiers, numbered lists for steps.
• If a request is ambiguous, make a reasonable assumption and state it, then proceed.
• If you notice other issues beyond what was asked, mention them briefly as "💡 Tip:" at the end.
SYS;

    $new_user_text = $user_msg . $code_context;
    $oai_messages  = null;

    $history_norm = [];
    foreach ( array_slice( $history, -10 ) as $turn ) {
        if ( empty( $turn['role'] ) || empty( $turn['content'] ) ) { continue; }
        $history_norm[] = [
            'role'    => $turn['role'],
            'content' => substr( $turn['content'], 0, 4000 ),
        ];
    }
    unset( $history );

    $reply         = null;
    $last_err      = '';
    $provider_used = '';

    $build_oai_messages = function() use ( &$oai_messages, $history_norm, $new_user_text, $system ) {
        if ( $oai_messages !== null ) { return; }
        $oai_messages = [ [ 'role' => 'system', 'content' => $system ] ];
        foreach ( $history_norm as $t ) {
            $oai_messages[] = [ 'role' => ( $t['role'] === 'assistant' ) ? 'assistant' : 'user', 'content' => $t['content'] ];
        }
        $oai_messages[] = [ 'role' => 'user', 'content' => $new_user_text ];
    };

    /* Cerebras */
    $call_cerebras = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages ) {
        if ( get_transient( 'mlp_quota_cerebras_sql' ) ) { $last_err = 'Cerebras quota exhausted (cached)'; return; }
        $key = defined( 'MLP_CEREBRAS_API_KEY' ) ? MLP_CEREBRAS_API_KEY : '';
        if ( empty( $key ) ) { $last_err = 'Cerebras: MLP_CEREBRAS_API_KEY not defined'; return; }
        $build_oai_messages();
        $res = wp_remote_post( 'https://api.cerebras.ai/v1/chat/completions', [
            'timeout'    => 12,
            'user-agent' => 'MobileLivePreview-ChatSQL/1.0',
            'headers'    => [ 'Content-Type' => 'application/json', 'Authorization' => 'Bearer ' . $key ],
            'body'       => wp_json_encode( [ 'model' => 'llama-3.3-70b', 'messages' => $oai_messages, 'temperature' => 0.3, 'max_tokens' => 4096, 'top_p' => 0.95 ] ),
        ] );
        $code = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
        if ( $code === 200 ) {
            $body = json_decode( wp_remote_retrieve_body( $res ), true );
            $text = $body['choices'][0]['message']['content'] ?? '';
            if ( $text ) { $reply = $text; $provider_used = 'Cerebras · llama-3.3-70b'; return; }
            $last_err = 'Cerebras empty response';
        } elseif ( $code === 429 ) {
            $last_err = 'Cerebras rate-limited (429)';
            set_transient( 'mlp_quota_cerebras_sql', 1, HOUR_IN_SECONDS );
        } else { $last_err = 'Cerebras HTTP ' . $code; }
    };

    /* Groq */
    $call_groq = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages ) {
        if ( get_transient( 'mlp_quota_groq_sql' ) ) { $last_err = 'Groq quota exhausted (cached)'; return; }
        $key = defined( 'MLP_GROQ_API_KEY' ) ? MLP_GROQ_API_KEY : '';
        if ( empty( $key ) ) { $last_err = 'Groq: MLP_GROQ_API_KEY not defined'; return; }
        $build_oai_messages();
        $res = wp_remote_post( 'https://api.groq.com/openai/v1/chat/completions', [
            'timeout'    => 12,
            'user-agent' => 'MobileLivePreview-ChatSQL/1.0',
            'headers'    => [ 'Content-Type' => 'application/json', 'Authorization' => 'Bearer ' . $key ],
            'body'       => wp_json_encode( [ 'model' => 'llama-3.3-70b-versatile', 'messages' => $oai_messages, 'temperature' => 0.3, 'max_tokens' => 4096, 'top_p' => 0.95 ] ),
        ] );
        $code = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
        if ( $code === 200 ) {
            $body = json_decode( wp_remote_retrieve_body( $res ), true );
            $text = $body['choices'][0]['message']['content'] ?? '';
            if ( $text ) { $reply = $text; $provider_used = 'Groq · llama-3.3-70b'; return; }
            $last_err = 'Groq empty response';
        } elseif ( $code === 429 ) {
            $last_err = 'Groq rate-limited (429)';
            set_transient( 'mlp_quota_groq_sql', 1, HOUR_IN_SECONDS );
        } else { $last_err = 'Groq HTTP ' . $code; }
    };

    /* Try providers: Cerebras → Groq */
    $call_cerebras();
    if ( empty( $reply ) ) { $call_groq(); }

    if ( empty( $reply ) ) {
        wp_send_json_error( [ 'message' => 'All AI providers failed. ' . $last_err ], 503 );
        return;
    }

    wp_send_json_success( [ 'reply' => $reply, 'provider' => $provider_used ] );
}
