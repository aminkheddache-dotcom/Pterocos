<?php
/**
 * MLP AI Chat Rust Edition
 * Adds AI chat assistant sidebar to Rust editor.
 * Rust-specific system prompt. Uses same providers as other language chats.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

add_action( 'wp_ajax_mlp_ai_chat_rust',        'mlp_ai_chat_rust_handler' );
add_action( 'wp_ajax_nopriv_mlp_ai_chat_rust', 'mlp_ai_chat_rust_handler' );

function mlp_ai_chat_rust_handler() {
    $_mlp_guard_key   = 'mlp_in_flight_rs';
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
        $_SERVER['HTTP_CF_CONNECTING_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR']
        ?? '0.0.0.0'
    );
    if ( str_contains( $ip, ',' ) ) { $ip = trim( explode( ',', $ip )[0] ); }
    $ip_key = md5( $ip );

    /* ── Turnstile verification ── */
    $_ts_verified_key = 'mlp_ts_v_rs_' . $ip_key;
    if ( ! get_transient( $_ts_verified_key ) ) {
        $ts_token  = sanitize_text_field( wp_unslash( $_POST['turnstile_token'] ?? '' ) );
        $ts_secret = defined( 'MLP_TURNSTILE_SECRET_KEY' ) ? MLP_TURNSTILE_SECRET_KEY : '';
        if ( empty( $ts_token ) ) {
            wp_send_json_error( [ 'message' => 'Please complete the human verification first.' ], 403 );
            return;
        }
        if ( ! empty( $ts_secret ) ) {
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
        }
        set_transient( $_ts_verified_key, 1, DAY_IN_SECONDS );
    }

    /* ── Abuse protection ── */
    $_banned_fast = wp_cache_get( 'mlp_banned_ips_rs', 'mlp' );
    if ( false === $_banned_fast ) {
        $_banned_fast = (array) get_option( 'mlp_banned_ips_rs', [] );
        wp_cache_set( 'mlp_banned_ips_rs', $_banned_fast, 'mlp', 300 );
    }
    if ( in_array( $ip, $_banned_fast, true ) ) {
        wp_send_json_error( [ 'message' => 'Access denied.' ], 403 );
        return;
    }

    $burst_key  = 'mlp_burst_rs_' . $ip_key;
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

    $hour_key   = 'mlp_hr_rs_' . $ip_key;
    $hour_count = (int) get_transient( $hour_key );
    if ( $hour_count >= 40 ) {
        wp_send_json_error( [ 'message' => 'Hourly limit reached. Please try again later.' ], 429 );
        return;
    }
    set_transient( $hour_key, $hour_count + 1, HOUR_IN_SECONDS );

    $strike_key   = 'mlp_strikes_rs_' . $ip_key;
    $strike_count = (int) get_transient( $strike_key );
    if ( $hour_count + 1 >= 40 ) {
        $strike_count++;
        set_transient( $strike_key, $strike_count, DAY_IN_SECONDS );
        if ( $strike_count >= 3 ) {
            $banned   = (array) get_option( 'mlp_banned_ips_rs', [] );
            $banned[] = $ip;
            update_option( 'mlp_banned_ips_rs', array_unique( $banned ) );
            wp_cache_delete( 'mlp_banned_ips_rs', 'mlp' );
        }
    }

    /* ── Inputs ── */
    $user_msg  = sanitize_textarea_field( wp_unslash( $_POST['message']   ?? '' ) );
    $rust_code = wp_unslash( $_POST['rust_code'] ?? '' );
    $history   = json_decode( wp_unslash( $_POST['history'] ?? '[]' ), true );
    if ( ! is_array( $history ) ) { $history = []; }

    if ( empty( $user_msg ) ) {
        wp_send_json_error( [ 'message' => 'Message cannot be empty.' ], 400 );
        return;
    }
    if ( strlen( $user_msg ) > 8000 ) {
        wp_send_json_error( [ 'message' => 'Message too long (max 8000 chars).' ], 400 );
        return;
    }

    /* ── Rust code context ── */
    $rust_t       = trim( $rust_code );
    $code_context = '';
    if ( $rust_t ) {
        $code_context = "\n\n--- CURRENT RUST CODE ---\n" . substr( $rust_t, 0, 6000 ) . "\n--- END OF CODE ---\n";
    }

    /* ── Rust-specific system prompt ── */
    $system = <<<'SYS'
You are an elite Rust developer embedded inside a live Monaco code editor running against the Rust Playground (play.rust-lang.org, stable channel). You have deep expertise in Rust's ownership model, borrow checker, lifetimes, traits, async/await, generics, macros, and the broader ecosystem.

━━━ YOUR ROLE ━━━
You assist developers writing, debugging, optimising, and refactoring Rust code. You always inspect the provided editor code before answering — never assume what it looks like. You understand Rust error messages (E0XXX codes) deeply and can explain and fix them clearly.

━━━ PLAYGROUND CONSTRAINTS (CRITICAL) ━━━
- The code runs on play.rust-lang.org — stable channel, 2021 edition by default.
- No file I/O, network access, or external crates beyond what the Playground allows.
- Playground supports a curated set of popular crates (serde, rand, rayon, tokio, regex, chrono, etc.) declared with `// Cargo.toml` comment blocks at the top.
- Always write a valid `fn main()` binary unless the user specifically requests a library snippet.
- When suggesting crate dependencies, show the Playground-style Cargo.toml comment block format:
  ```rust
  // [dependencies]
  // serde = { version = "1", features = ["derive"] }
  ```

━━━ CODE OUTPUT FORMAT (MANDATORY — NEVER SKIP) ━━━
1. When producing or modifying code, wrap it in a labeled Rust fence:
   ```rust
   // full rust code here
   ```
2. Always output the COMPLETE file content — never partial snippets or "… rest stays the same".
3. Small targeted edits still require the full modified file so the Apply button works.
4. If you only explain without changing code, use zero code fences.
5. CRITICAL: If the user asks you to build, create, add, fix, change, update, make, generate, or modify ANYTHING — you MUST output the full modified code inside fences. A response without code fences when code was requested is a failure.

━━━ RESPONSE QUALITY RULES ━━━
• Think through the borrow checker before writing code — never produce code that has ownership/lifetime errors.
• For borrow-checker errors: name the exact rule being violated (e.g. "cannot move out of borrowed context"), explain why it fires, then show the fix.
• For lifetime errors: draw the lifetime diagram in a comment before writing the fix.
• For E0XXX errors: cite the error code, explain it in plain English, then fix it.
• Prefer idiomatic Rust: use iterators over raw loops, `?` over `unwrap()`, `match` over `if let` chains when exhaustive, `thiserror`/`anyhow` for error types.
• Suggest `clippy` improvements proactively when you spot non-idiomatic code.
• Write memory-safe code — no `unsafe` unless explicitly requested and justified.
• Include relevant `use` statements in the output.
• For async code, default to `tokio` unless the user specifies otherwise.
• When the user asks about performance, consider zero-copy approaches, iterator fusion, and SIMD where relevant.

━━━ TONE & STYLE ━━━
• Be direct, confident, and precise. Rust devs value technical accuracy over hand-holding.
• Use markdown: **bold** for key Rust concepts, `inline code` for identifiers and types, numbered lists for steps.
• When explaining ownership, use short analogies ("single owner like a unique key").
• If a request is ambiguous, make a reasonable assumption, state it, then proceed.
• If you spot other issues beyond what was asked, mention them briefly as "**Clippy tip:**" without changing unrequested code.
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

    /* ── Cerebras ── */
    $call_cerebras = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages ) {
        if ( get_transient( 'mlp_quota_cerebras_rs' ) ) { $last_err = 'Cerebras quota exhausted (cached)'; return; }
        $key = defined( 'MLP_CEREBRAS_API_KEY' ) ? MLP_CEREBRAS_API_KEY : '';
        if ( empty( $key ) ) { $last_err = 'Cerebras: key not defined'; return; }
        $build_oai_messages();
        $res = wp_remote_post( 'https://api.cerebras.ai/v1/chat/completions', [
            'timeout'    => 12,
            'user-agent' => 'MobileLivePreview-ChatRust/1.0',
            'headers'    => [ 'Content-Type' => 'application/json', 'Authorization' => 'Bearer ' . $key ],
            'body'       => wp_json_encode( [ 'model' => 'llama-3.3-70b', 'messages' => $oai_messages, 'temperature' => 0.4, 'max_tokens' => 4096, 'top_p' => 0.95 ] ),
        ] );
        $code = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
        if ( $code === 200 ) {
            $body = json_decode( wp_remote_retrieve_body( $res ), true );
            $text = $body['choices'][0]['message']['content'] ?? '';
            if ( $text ) { $reply = $text; $provider_used = 'Cerebras · llama-3.3-70b'; return; }
            $last_err = 'Cerebras empty response';
        } elseif ( $code === 429 ) {
            $last_err = 'Cerebras rate-limited (429)'; set_transient( 'mlp_quota_cerebras_rs', 1, HOUR_IN_SECONDS );
        } else { $last_err = 'Cerebras HTTP ' . $code; }
    };

    /* ── Groq ── */
    $call_groq = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages ) {
        if ( get_transient( 'mlp_quota_groq_rs' ) ) { $last_err = 'Groq quota exhausted (cached)'; return; }
        $key = defined( 'MLP_GROQ_API_KEY' ) ? MLP_GROQ_API_KEY : '';
        if ( empty( $key ) ) { $last_err = 'Groq: key not defined'; return; }
        $build_oai_messages();
        $res = wp_remote_post( 'https://api.groq.com/openai/v1/chat/completions', [
            'timeout'    => 12,
            'user-agent' => 'MobileLivePreview-ChatRust/1.0',
            'headers'    => [ 'Content-Type' => 'application/json', 'Authorization' => 'Bearer ' . $key ],
            'body'       => wp_json_encode( [ 'model' => 'llama-3.3-70b-versatile', 'messages' => $oai_messages, 'temperature' => 0.4, 'max_tokens' => 4096, 'top_p' => 0.95 ] ),
        ] );
        $code = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
        if ( $code === 200 ) {
            $body = json_decode( wp_remote_retrieve_body( $res ), true );
            $text = $body['choices'][0]['message']['content'] ?? '';
            if ( $text ) { $reply = $text; $provider_used = 'Groq · llama-3.3-70b'; return; }
            $last_err = 'Groq empty response';
        } elseif ( $code === 429 ) {
            $last_err = 'Groq rate-limited (429)'; set_transient( 'mlp_quota_groq_rs', 1, HOUR_IN_SECONDS );
        } else { $last_err = 'Groq HTTP ' . $code; }
    };

    /* ── Try providers: Cerebras → Groq ── */
    $call_cerebras();
    if ( empty( $reply ) ) { $call_groq(); }

    if ( empty( $reply ) ) {
        wp_send_json_error( [ 'message' => 'All AI providers failed. ' . $last_err ], 503 );
        return;
    }

    wp_send_json_success( [ 'reply' => $reply, 'provider' => $provider_used ] );
}
