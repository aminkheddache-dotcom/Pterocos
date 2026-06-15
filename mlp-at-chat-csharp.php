<?php
/**
 * Plugin Name: MLP AI Chat C# Edition
 * Plugin URI:  https://pterocos.eu.org
 * Description: Adds AI chat assistant sidebar to C# editor.
 * Version:     1.0.0-csharp
 * Author:      Pterocos
 * License:     GPL v2 or later
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

add_action( 'wp_ajax_mlp_ai_chat_csharp',        'mlp_ai_chat_csharp_handler' );
add_action( 'wp_ajax_nopriv_mlp_ai_chat_csharp', 'mlp_ai_chat_csharp_handler' );

function mlp_ai_chat_csharp_handler() {
    $_mlp_guard_key   = 'mlp_in_flight_cs';
    $_mlp_guard_group = 'mlp';
    $_mlp_max         = 4;

    $_mlp_in_flight = (int) wp_cache_get( $_mlp_guard_key, $_mlp_guard_group );
    if ( $_mlp_in_flight >= $_mlp_max ) {
        wp_send_json_error( [ 'message' => 'Please try again later.' ], 503 );
        return;
    }
    wp_cache_set( $_mlp_guard_key, $_mlp_in_flight + 1, $_mlp_guard_group, 120 );

    register_shutdown_function( function() use ( $_mlp_guard_key, $_mlp_guard_group ) {
        $c = (int) wp_cache_get( $_mlp_guard_key, $_mlp_guard_group );
        wp_cache_set( $_mlp_guard_key, max( 0, $c - 1 ), $_mlp_guard_group, 120 );
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
    $_ts_key = 'mlp_ts_v_cs_' . $ip_key;
    if ( ! get_transient( $_ts_key ) ) {
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
        set_transient( $_ts_key, 1, DAY_IN_SECONDS );
    }
    unset( $_ts_key );

    /* Banned IPs */
    $_banned = wp_cache_get( 'mlp_banned_ips_cs', 'mlp' );
    if ( false === $_banned ) {
        $_banned = (array) get_option( 'mlp_banned_ips_cs', [] );
        wp_cache_set( 'mlp_banned_ips_cs', $_banned, 'mlp', 300 );
    }
    if ( in_array( $ip, $_banned, true ) ) {
        wp_send_json_error( [ 'message' => 'Access denied.' ], 403 );
        return;
    }
    unset( $_banned );

    /* Burst limit */
    $burst_key  = 'mlp_burst_cs_' . $ip_key;
    $burst_data = get_transient( $burst_key );
    if ( ! is_array( $burst_data ) ) { $burst_data = []; }
    $now = time();
    $burst_data = array_filter( $burst_data, fn( $t ) => $now - $t < 10 );
    if ( count( $burst_data ) >= 5 ) {
        wp_send_json_error( [ 'message' => 'Too many requests. Please slow down.' ], 429 );
        return;
    }
    $burst_data[] = $now;
    set_transient( $burst_key, array_values( $burst_data ), 10 );

    /* Hourly limit */
    $hour_key   = 'mlp_hr_cs_' . $ip_key;
    $hour_count = (int) get_transient( $hour_key );
    if ( $hour_count >= 40 ) {
        wp_send_json_error( [ 'message' => 'Hourly limit reached. Please try again later.' ], 429 );
        return;
    }
    set_transient( $hour_key, $hour_count + 1, HOUR_IN_SECONDS );

    /* Strike tracking */
    $banned       = (array) get_option( 'mlp_banned_ips_cs', [] );
    $strike_key   = 'mlp_strikes_cs_' . $ip_key;
    $strike_count = (int) get_transient( $strike_key );
    if ( $hour_count + 1 >= 40 ) {
        $strike_count++;
        set_transient( $strike_key, $strike_count, DAY_IN_SECONDS );
        if ( $strike_count >= 3 ) {
            $banned[] = $ip;
            update_option( 'mlp_banned_ips_cs', array_unique( $banned ) );
            wp_cache_delete( 'mlp_banned_ips_cs', 'mlp' );
        }
    }

    /* Inputs */
    $user_msg   = sanitize_textarea_field( wp_unslash( $_POST['message']     ?? '' ) );
    $csharp_code = wp_unslash( $_POST['csharp_code'] ?? '' );
    $history    = json_decode( wp_unslash( $_POST['history'] ?? '[]' ), true );
    if ( ! is_array( $history ) ) { $history = []; }

    $provider = sanitize_text_field( wp_unslash( $_POST['provider'] ?? 'replit' ) );
    if ( ! in_array( $provider, [ 'replit', 'mistral', 'cerebras', 'groq', 'github', 'gemini', 'cohere', 'siliconflow' ], true ) ) { $provider = 'replit'; }

    if ( empty( $user_msg ) ) {
        wp_send_json_error( [ 'message' => 'Message cannot be empty.' ], 400 );
        return;
    }
    if ( strlen( $user_msg ) > 8000 ) {
        wp_send_json_error( [ 'message' => 'Message too long (max 8000 chars).' ], 400 );
        return;
    }

    /* Code context */
    $cs_t = trim( $csharp_code );
    unset( $csharp_code );
    $code_context = '';
    if ( $cs_t ) {
        $code_context = "\n\n--- CURRENT C# CODE ---\n" . substr( $cs_t, 0, 6000 ) . "\n--- END OF CODE ---\n";
    }
    unset( $cs_t );

    /* C#-specific system prompt */
    $system = <<<'SYS'
You are an elite C# and .NET developer embedded inside a live Monaco code editor. You have deep expertise in C# (all versions up to C# 13), .NET, ASP.NET Core, LINQ, async/await, design patterns, and clean architecture.

━━━ YOUR ROLE ━━━
You assist developers in writing, editing, explaining, debugging, optimizing, and refactoring C# code. You always read the provided editor code before answering — never assume what code looks like.

━━━ EXECUTION CONTEXT ━━━
The code runs via the Wandbox API using Mono/mcs. Standard console I/O works. NuGet packages are NOT available. Use only BCL (Base Class Library) types. Code must have a static Main method as the entry point.

━━━ CODE OUTPUT FORMAT (MANDATORY — NEVER SKIP) ━━━
1. When producing or modifying code, wrap it in a labeled C# fence:
   ```csharp
   // full C# code here
   ```
2. Always output the COMPLETE file content inside the fence — never partial snippets or "... rest stays the same" comments.
3. When doing a small targeted edit, still output the whole modified file so the Apply button works correctly.
4. If you only explain without changing code, use zero code fences.
5. CRITICAL: If the user asks you to build, create, add, fix, change, update, make, generate, or modify ANYTHING — you MUST output the full modified code. Never describe the change without showing the code.

━━━ RESPONSE QUALITY RULES ━━━
• Think step-by-step before answering complex requests.
• For bugs: identify root cause first, then fix. Briefly explain what was wrong.
• For new features: consider edge cases, null safety, and exception handling.
• For explanations: be clear and educational. Use concrete examples.
• Prefer modern C# idioms: records, pattern matching, nullable reference types, LINQ, async/await, expression-bodied members, top-level statements when appropriate.
• Write clean, readable code with descriptive names, XML docs on public APIs, and proper access modifiers.
• Always include required `using` statements in your output.
• Follow Microsoft C# coding conventions and naming guidelines (PascalCase for types/methods, camelCase for locals).
• Prefer value types (structs, records) for immutable data. Use `var` where the type is obvious.
• Handle exceptions specifically — avoid bare `catch (Exception)` unless re-throwing.

━━━ TONE & STYLE ━━━
• Be direct, confident, and concise. No filler phrases.
• Use markdown: **bold** for key terms, `inline code` for identifiers, numbered lists for steps.
• If a request is ambiguous, make a reasonable assumption and state it, then proceed.
• If you notice other bugs or improvements beyond what was asked, mention them briefly at the end as "💡 Tip:" without changing unrequested code.
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

    /* ── Cerebras ── */
    $call_cerebras = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages ) {
        if ( get_transient( 'mlp_quota_cerebras_cs' ) ) { $last_err = 'Cerebras quota exhausted'; return; }
        $key = defined( 'MLP_CEREBRAS_API_KEY' ) ? MLP_CEREBRAS_API_KEY : '';
        if ( empty( $key ) ) { $last_err = 'Cerebras key missing'; return; }
        $build_oai_messages();
        $res = wp_remote_post( 'https://api.cerebras.ai/v1/chat/completions', [
            'timeout' => 20,
            'headers' => [ 'Content-Type' => 'application/json', 'Authorization' => 'Bearer ' . $key ],
            'body'    => wp_json_encode( [ 'model' => 'llama-3.3-70b', 'messages' => $oai_messages, 'temperature' => 0.4, 'max_tokens' => 4096 ] ),
        ] );
        $code = is_wp_error($res) ? 0 : (int) wp_remote_retrieve_response_code($res);
        if ($code === 200) {
            $body = json_decode(wp_remote_retrieve_body($res), true);
            $txt  = $body['choices'][0]['message']['content'] ?? '';
            if ($txt) { $reply = $txt; $provider_used = 'Cerebras · llama-3.3-70b'; return; }
            $last_err = 'Cerebras empty response';
        } elseif ($code === 429) {
            set_transient('mlp_quota_cerebras_cs', 1, 600);
            $last_err = 'Cerebras rate-limited';
        } else {
            $last_err = 'Cerebras HTTP ' . $code;
        }
    };

    /* ── Groq ── */
    $call_groq = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages ) {
        if ( get_transient( 'mlp_quota_groq_cs' ) ) { $last_err = 'Groq quota exhausted'; return; }
        $key = defined( 'MLP_GROQ_API_KEY' ) ? MLP_GROQ_API_KEY : '';
        if ( empty( $key ) ) { $last_err = 'Groq key missing'; return; }
        $build_oai_messages();
        $res = wp_remote_post( 'https://api.groq.com/openai/v1/chat/completions', [
            'timeout' => 20,
            'headers' => [ 'Content-Type' => 'application/json', 'Authorization' => 'Bearer ' . $key ],
            'body'    => wp_json_encode( [ 'model' => 'llama-3.3-70b-versatile', 'messages' => $oai_messages, 'temperature' => 0.4, 'max_tokens' => 4096 ] ),
        ] );
        $code = is_wp_error($res) ? 0 : (int) wp_remote_retrieve_response_code($res);
        if ($code === 200) {
            $body = json_decode(wp_remote_retrieve_body($res), true);
            $txt  = $body['choices'][0]['message']['content'] ?? '';
            if ($txt) { $reply = $txt; $provider_used = 'Groq · llama-3.3-70b'; return; }
            $last_err = 'Groq empty response';
        } elseif ($code === 429) {
            set_transient('mlp_quota_groq_cs', 1, 600);
            $last_err = 'Groq rate-limited';
        } else {
            $last_err = 'Groq HTTP ' . $code;
        }
    };

    /* ── Mistral ── */
    $call_mistral = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages ) {
        $key = defined( 'MLP_MISTRAL_API_KEY' ) ? MLP_MISTRAL_API_KEY : '';
        if ( empty( $key ) ) { $last_err = 'Mistral key missing'; return; }
        $build_oai_messages();
        $res = wp_remote_post( 'https://api.mistral.ai/v1/chat/completions', [
            'timeout' => 20,
            'headers' => [ 'Content-Type' => 'application/json', 'Authorization' => 'Bearer ' . $key ],
            'body'    => wp_json_encode( [ 'model' => 'mistral-large-latest', 'messages' => $oai_messages, 'temperature' => 0.4, 'max_tokens' => 4096 ] ),
        ] );
        $code = is_wp_error($res) ? 0 : (int) wp_remote_retrieve_response_code($res);
        if ($code === 200) {
            $body = json_decode(wp_remote_retrieve_body($res), true);
            $txt  = $body['choices'][0]['message']['content'] ?? '';
            if ($txt) { $reply = $txt; $provider_used = 'Mistral · mistral-large'; return; }
            $last_err = 'Mistral empty response';
        } else {
            $last_err = 'Mistral HTTP ' . $code;
        }
    };

    /* ── Try providers in order ── */
    foreach ( [ $call_cerebras, $call_groq, $call_mistral ] as $provider_fn ) {
        $provider_fn();
        if ( $reply !== null ) { break; }
    }

    if ( $reply === null ) {
        error_log( '[MLP CS Chat] All providers failed. Last error: ' . $last_err );
        wp_send_json_error( [ 'message' => 'AI unavailable. Try again in a moment.' ], 503 );
        return;
    }

    error_log( '[MLP CS Chat] Reply via ' . $provider_used );
    wp_send_json_success( [ 'reply' => $reply, 'provider' => $provider_used ] );
}
