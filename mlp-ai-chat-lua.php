<?php
/**
 * Plugin Name: MLP AI Chat Lua Edition
 * Plugin URI:  https://pterocos.eu.org
 * Description: Adds AI chat assistant sidebar to Lua editor. 
 * Version:     1.0.0-lua
 * Author:      Pterocos
 * Author URI:  https://pterocos.eu.org
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

add_action( 'wp_ajax_mlp_ai_chat_lua',        'mlp_ai_chat_lua_handler' );
add_action( 'wp_ajax_nopriv_mlp_ai_chat_lua', 'mlp_ai_chat_lua_handler' );

function mlp_ai_chat_lua_handler() {
    $_mlp_guard_key   = 'mlp_in_flight_lu';
    $_mlp_guard_group = 'mlp';
    $_mlp_max         = 4;

    $_mlp_in_flight = (int) wp_cache_get( $_mlp_guard_key, $_mlp_guard_group );
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
        $_SERVER['HTTP_CF_CONNECTING_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR']
        ?? '0.0.0.0'
    );
    if ( str_contains( $ip, ',' ) ) { $ip = trim( explode( ',', $ip )[0] ); }
    $ip_key = md5( $ip );

    /* Turnstile verification */
    $_ts_verified_key = 'mlp_ts_v_lu_' . $ip_key;
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

    /* Abuse protection */
    $_banned_fast = wp_cache_get( 'mlp_banned_ips_lu', 'mlp' );
    if ( false === $_banned_fast ) {
        $_banned_fast = (array) get_option( 'mlp_banned_ips_lu', [] );
        wp_cache_set( 'mlp_banned_ips_lu', $_banned_fast, 'mlp', 300 );
    }
    if ( in_array( $ip, $_banned_fast, true ) ) {
        wp_send_json_error( [ 'message' => 'Access denied.' ], 403 );
        return;
    }
    unset( $_banned_fast );

    $burst_key  = 'mlp_burst_lu_' . $ip_key;
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

    $hour_key   = 'mlp_hr_lu_' . $ip_key;
    $hour_count = (int) get_transient( $hour_key );
    if ( $hour_count >= 40 ) {
        wp_send_json_error( [ 'message' => 'Hourly limit reached. Please try again later.' ], 429 );
        return;
    }
    set_transient( $hour_key, $hour_count + 1, HOUR_IN_SECONDS );

    $banned = wp_cache_get( 'mlp_banned_ips_lu', 'mlp' );
    if ( false === $banned ) {
        $banned = (array) get_option( 'mlp_banned_ips_lu', [] );
        wp_cache_set( 'mlp_banned_ips_lu', $banned, 'mlp', 300 );
    }

    $strike_key   = 'mlp_strikes_lu_' . $ip_key;
    $strike_count = (int) get_transient( $strike_key );
    if ( $hour_count + 1 >= 40 ) {
        $strike_count++;
        set_transient( $strike_key, $strike_count, DAY_IN_SECONDS );
        if ( $strike_count >= 3 ) {
            $banned[] = $ip;
            update_option( 'mlp_banned_ips_lu', array_unique( $banned ) );
            wp_cache_delete( 'mlp_banned_ips_lu', 'mlp' );
        }
    }

    $referer   = wp_get_referer();
    $origin_ok = ! empty( $referer ) && (
        str_contains( $referer, home_url() ) ||
        str_contains( $referer, wp_parse_url( home_url(), PHP_URL_HOST ) )
    );
    if ( ! $origin_ok ) {
        $burst_data[] = $now;
        set_transient( $burst_key, $burst_data, 10 );
    }

    /* Lua-specific inputs */
    $user_msg = sanitize_textarea_field( wp_unslash( $_POST['message'] ?? '' ) );
    $lua_code = wp_unslash( $_POST['lua_code'] ?? '' );
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

    /* Lua code context */
    $lua_t = trim( $lua_code );
    unset( $lua_code );
    $code_context = '';
    if ( $lua_t ) {
        $code_context = "\n\n--- CURRENT LUA CODE ---\n" . substr( $lua_t, 0, 6000 ) . "\n--- END OF CODE ---\n";
    }
    unset( $lua_t );

    /* Lua-specific system prompt */
    $system = <<<'SYS'
You are an elite Lua developer embedded inside a live Monaco code editor running Lua via Fengari (Lua 5.4 in the browser). You have deep expertise in Lua 5.x, metatables, coroutines, closures, the standard library, and LuaJIT-compatible idioms.

━━━ YOUR ROLE ━━━
You assist developers in writing, editing, explaining, debugging, optimizing, and refactoring Lua code. You always read the provided editor code before answering — never assume what code looks like. The runtime is Fengari (Lua 5.4 semantics in JavaScript), so avoid C-extension-dependent libraries that won't be available.

━━━ CODE OUTPUT FORMAT (MANDATORY — NEVER SKIP) ━━━
1. When producing or modifying code, wrap it in a labeled Lua fence:
   ```lua
   -- full lua code here
   ```
2. Always output the COMPLETE file content inside the fence — never partial snippets, "... rest stays the same", or "add this to your code" comments.
3. When doing a small targeted edit, still output the whole modified file so the Apply button works correctly.
4. If you only explain without changing code, use zero code fences.
5. CRITICAL: If the user asks you to build, create, add, fix, change, update, make, generate, or modify ANYTHING in their code — you MUST output the full modified code inside fences. Never describe the change without showing the code. A response without code fences when code was requested is a failure.

━━━ RESPONSE QUALITY RULES ━━━
• Think step-by-step before answering complex requests.
• For bugs: identify root cause first, then fix. Briefly explain what was wrong.
• For new features: consider edge cases, performance, and error handling.
• For explanations: be clear and educational. Use concrete examples.
• Prefer idiomatic Lua: tables as objects/arrays, metatables for OOP, coroutines for async patterns.
• Remember: Fengari runs Lua 5.4 semantics — integer division `//`, bitwise operators, `<const>` and `<close>` attributes are all available. `io.read()` and `os.*` are restricted in browser environments, so use `print()` and `io.write()` for output.
• Write clean, readable code with descriptive variable names and comments on non-obvious logic.
• Always include required `require` calls in your output.
• Use `local` for variables unless global scope is intentional.
• Prefer `pcall`/`xpcall` for error handling.

━━━ TONE & STYLE ━━━
• Be direct, confident, and concise. No filler phrases.
• Use markdown: **bold** for key terms, `inline code` for identifiers, numbered lists for steps.
• If a request is ambiguous, make a reasonable assumption and state it, then proceed.
• If you notice other bugs or improvements beyond what was asked, mention them briefly at the end as "💡 Bonus tip:" without changing unrequested code.
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
            $oai_messages[] = [
                'role'    => ( $t['role'] === 'assistant' ) ? 'assistant' : 'user',
                'content' => $t['content'],
            ];
        }
        $oai_messages[] = [ 'role' => 'user', 'content' => $new_user_text ];
    };

    $call_cerebras = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages ) {
        if ( get_transient( 'mlp_quota_cerebras_lu' ) ) {
            $last_err = 'Cerebras quota exhausted (cached)';
            return;
        }
        $cerebras_key = defined( 'MLP_CEREBRAS_API_KEY' ) ? MLP_CEREBRAS_API_KEY : '';
        if ( empty( $cerebras_key ) ) {
            $last_err = 'Cerebras: MLP_CEREBRAS_API_KEY not defined';
            return;
        }
        $build_oai_messages();

        $c_res = wp_remote_post( 'https://api.cerebras.ai/v1/chat/completions', [
            'timeout'    => 12,
            'user-agent' => 'MobileLivePreview-ChatLua/1.0',
            'headers'    => [
                'Content-Type'  => 'application/json',
                'Authorization' => 'Bearer ' . $cerebras_key,
            ],
            'body' => wp_json_encode( [
                'model'       => 'llama-3.3-70b',
                'messages'    => $oai_messages,
                'temperature' => 0.4,
                'max_tokens'  => 4096,
                'top_p'       => 0.95,
            ] ),
        ] );

        $http_code = is_wp_error( $c_res ) ? 0 : (int) wp_remote_retrieve_response_code( $c_res );
        if ( $http_code === 200 ) {
            $c_body = json_decode( wp_remote_retrieve_body( $c_res ), true );
            $c_text = $c_body['choices'][0]['message']['content'] ?? '';
            if ( $c_text ) {
                $reply         = $c_text;
                $provider_used = 'Cerebras · llama-3.3-70b';
                return;
            }
            $last_err = 'Cerebras empty response';
        } elseif ( $http_code === 429 ) {
            $last_err = 'Cerebras rate-limited (429)';
            set_transient( 'mlp_quota_cerebras_lu', 1, HOUR_IN_SECONDS );
        } else {
            $last_err = 'Cerebras HTTP ' . $http_code;
        }
    };

    $call_groq = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages ) {
        if ( get_transient( 'mlp_quota_groq_lu' ) ) {
            $last_err = 'Groq quota exhausted (cached)';
            return;
        }
        $groq_key = defined( 'MLP_GROQ_API_KEY' ) ? MLP_GROQ_API_KEY : '';
        if ( empty( $groq_key ) ) {
            $last_err = 'Groq: MLP_GROQ_API_KEY not defined';
            return;
        }
        $build_oai_messages();

        $g_res = wp_remote_post( 'https://api.groq.com/openai/v1/chat/completions', [
            'timeout'    => 12,
            'user-agent' => 'MobileLivePreview-ChatLua/1.0',
            'headers'    => [
                'Content-Type'  => 'application/json',
                'Authorization' => 'Bearer ' . $groq_key,
            ],
            'body' => wp_json_encode( [
                'model'       => 'llama-3.3-70b-versatile',
                'messages'    => $oai_messages,
                'temperature' => 0.4,
                'max_tokens'  => 4096,
                'top_p'       => 0.95,
            ] ),
        ] );

        $http_code = is_wp_error( $g_res ) ? 0 : (int) wp_remote_retrieve_response_code( $g_res );
        if ( $http_code === 200 ) {
            $g_body = json_decode( wp_remote_retrieve_body( $g_res ), true );
            $g_text = $g_body['choices'][0]['message']['content'] ?? '';
            if ( $g_text ) {
                $reply         = $g_text;
                $provider_used = 'Groq · llama-3.3-70b';
                return;
            }
            $last_err = 'Groq empty response';
        } elseif ( $http_code === 429 ) {
            $last_err = 'Groq rate-limited (429)';
            set_transient( 'mlp_quota_groq_lu', 1, HOUR_IN_SECONDS );
        } else {
            $last_err = 'Groq HTTP ' . $http_code;
        }
    };

    /* Try providers in order: Cerebras → Groq */
    $call_cerebras();
    if ( empty( $reply ) ) {
        $call_groq();
    }

    if ( empty( $reply ) ) {
        wp_send_json_error( [
            'message' => 'All AI providers failed. ' . $last_err,
        ], 503 );
        return;
    }

    wp_send_json_success( [
        'reply'    => $reply,
        'provider' => $provider_used,
    ] );
}
