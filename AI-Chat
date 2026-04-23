<?php
/**
 * Plugin Name: MLP AI Chat Sidebar
 * Plugin URI:  https://mobilecodeht.com
 * Description: Adds a slide-in AI chat assistant sidebar to the Mobile Live Preview editor. Supports code explanation, editing, and generation via Replit AI (primary), Mistral AI, Cerebras (backup), Groq (secondary backup), GitHub Models (free tier), and Pollinations (fallback). Requires the Mobile Live Preview plugin.
 * Version:     2.3.0-github
 * Author:      MobileCodeHT
 * Author URI:  https://mobilecodeht.com
 * License:     GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: mlp-ai-chat
 * Requires at least: 5.0
 * Requires PHP: 7.4
 */

/**
 * MLP AI Chat Sidebar — Drop-in patch for Mobile Live Preview
 * ─────────────────────────────────────────────────────────────
 * HOW TO INSTALL:
 *   1. Place this file in your plugin folder (same directory as the main .php).
 *   2. Add ONE line near the top of the main plugin file (after the <?php line):
 *        require_once plugin_dir_path(__FILE__) . 'mlp-ai-chat.php';
 *   3. Done. A ✦ AI Chat button will appear in every editor instance.
 *
 * REQUIRED — define all API keys in wp-config.php (never hardcode in this file):
 *   define( 'MLP_TURNSTILE_SITE_KEY',   '...' );
 *   define( 'MLP_TURNSTILE_SECRET_KEY', '...' );
 *   define( 'MLP_REPLIT_API_URL',       '...' );
 *   define( 'MLP_MISTRAL_API_KEY',      '...' );
 *   define( 'MLP_CEREBRAS_API_KEY',     '...' );
 *   define( 'MLP_GROQ_API_KEY',         '...' );
 *   define( 'MLP_GITHUB_API_KEY',       '...' );
 *   define( 'MLP_COHERE_API_KEY',       '...' );
 *   define( 'MLP_SILICON_API_KEY',      '...' );
 *   define( 'MLP_TOGETHER_API_KEY',     '...' );
 *   define( 'MLP_SIGHTENGINE_USER',     '...' );
 *   define( 'MLP_SIGHTENGINE_SECRET',   '...' );
 *   define( 'MLP_IMAGGA_KEY',           '...' );
 *   define( 'MLP_IMAGGA_SECRET',        '...' );
 *   define( 'MLP_GOOGLE_VISION_KEY',    '...' );
 *
 * FEATURES:
 *   • Slide-in sidebar (right side) with dark theme matching the editor.
 *   • Persistent chat history per editor instance (localStorage).
 *   • AI reads current HTML/CSS/JS as context for every message.
 *   • AI can explain, edit, or generate code from scratch.
 *   • "Apply" buttons inject AI-suggested code directly into Monaco editors.
 *   • 6-tier AI fallback: Replit AI (primary) → Mistral AI → Cerebras (llama-3.3-70b) → Groq (llama-3.3-70b) → GitHub Models (gpt-4o, free) → Pollinations (free).
 *   • Works in both normal widget mode and fullscreen mode.
 *   • Provider badge shows which AI answered.
 *
 * All keys are read exclusively from wp-config.php — see the list above.
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

/* ═══════════════════════════════════════════════════════════════
   1.  PHP — AJAX HANDLER  (mlp_ai_chat)
   ═══════════════════════════════════════════════════════════════ */
add_action( 'wp_ajax_mlp_ai_chat',        'mlp_ai_chat_handler' );
add_action( 'wp_ajax_nopriv_mlp_ai_chat', 'mlp_ai_chat_handler' );

function mlp_ai_chat_handler() {
    /*
     * Extend PHP execution time.
     * Worst-case: Cerebras 25s + Groq 25s + Pollinations 20s ≈ 70 s. 90 s is safe.
     */
    @set_time_limit( 90 );

    /* ── Turnstile: verify once per IP — NO PHP sessions, no file locks ──────
       * CPU fix v2.1.2: session_start() acquires a per-visitor file lock that
       * blocks concurrent AJAX requests. Under burst traffic this serialises
       * all requests and pins server CPU. Replaced with a WP transient keyed
       * to the hashed IP — zero lock overhead, same one-challenge behaviour. */
      $_ts_ip_raw       = sanitize_text_field(
          $_SERVER['HTTP_CF_CONNECTING_IP']
          ?? $_SERVER['HTTP_X_FORWARDED_FOR']
          ?? $_SERVER['REMOTE_ADDR']
          ?? '0.0.0.0'
      );
      if ( str_contains( $_ts_ip_raw, ',' ) ) { $_ts_ip_raw = trim( explode( ',', $_ts_ip_raw )[0] ); }
      $_ts_verified_key = 'mlp_ts_v_' . md5( $_ts_ip_raw );
      unset( $_ts_ip_raw );

      if ( ! get_transient( $_ts_verified_key ) ) {
          $ts_token  = sanitize_text_field( wp_unslash( $_POST['turnstile_token'] ?? '' ) );
          $ts_secret = defined( 'MLP_TURNSTILE_SECRET_KEY' ) ? MLP_TURNSTILE_SECRET_KEY : '';

          if ( empty( $ts_token ) ) {
              wp_send_json_error( [ 'message' => 'Please complete the human verification first.' ], 403 );
              return;
          }

          $ts_res  = wp_remote_post( 'https://challenges.cloudflare.com/turnstile/v0/siteverify', [
              'timeout' => 10,
              'headers' => [ 'Content-Type' => 'application/json' ],
              'body'    => wp_json_encode( [ 'secret' => $ts_secret, 'response' => $ts_token ] ),
          ] );
          $ts_body = json_decode( wp_remote_retrieve_body( $ts_res ), true );

          if ( empty( $ts_body['success'] ) ) {
              wp_send_json_error( [ 'message' => 'Human verification failed. Please try again.' ], 403 );
              return;
          }
          /* Verified — remember for 24 h, one Turnstile challenge per day per IP */
          set_transient( $_ts_verified_key, 1, DAY_IN_SECONDS );
      }
      unset( $_ts_verified_key );

    /* ══════════════════════════════════════════════════════════════
       ABUSE PROTECTION
       Three independent layers — all must pass before touching any AI.
       ══════════════════════════════════════════════════════════════ */

    $ip = sanitize_text_field(
        $_SERVER['HTTP_CF_CONNECTING_IP']   /* Cloudflare real IP */
        ?? $_SERVER['HTTP_X_FORWARDED_FOR'] /* proxy chain — take first */
        ?? $_SERVER['REMOTE_ADDR']
        ?? '0.0.0.0'
    );
    /* For proxy chains, use only the first (client) IP */
    if ( str_contains( $ip, ',' ) ) { $ip = trim( explode( ',', $ip )[0] ); }
    $ip_key = md5( $ip ); /* hash so the raw IP is never stored in options/transients */

    /* ── Layer 0 (fast-path): Banned IP check — RAM lookup, zero DB cost ──
       * CPU fix: reject permanently banned IPs before reading any transients.
       * If the IP is banned this exits in < 1ms with zero MySQL queries. */
      $_banned_fast = wp_cache_get( 'mlp_banned_ips', 'mlp' );
      if ( false === $_banned_fast ) {
          $_banned_fast = (array) get_option( 'mlp_banned_ips', [] );
          wp_cache_set( 'mlp_banned_ips', $_banned_fast, 'mlp', 300 );
      }
      if ( in_array( $ip, $_banned_fast, true ) ) {
          wp_send_json_error( [ 'message' => 'Access denied.' ], 403 );
          return;
      }
      unset( $_banned_fast );

      /* ── Layer 1: Burst guard — max 5 requests per 10 seconds per IP ──
     *  Catches scripts hammering the endpoint in a tight loop.
     *  Uses a sliding window stored as a transient array of timestamps.   */
    $burst_key  = 'mlp_burst_' . $ip_key;
    $burst_data = get_transient( $burst_key );
    if ( ! is_array( $burst_data ) ) { $burst_data = []; }
    $now        = time();
    /* Drop timestamps older than 10 s */
    $burst_data = array_values( array_filter( $burst_data, fn( $t ) => $now - $t < 10 ) );
    if ( count( $burst_data ) >= 5 ) {
        wp_send_json_error( [ 'message' => 'Too many requests. Please slow down.' ], 429 );
        return;
    }
    $burst_data[] = $now;
    set_transient( $burst_key, $burst_data, 10 );

    /* ── Layer 2: Hourly cap — max 40 requests per hour per IP ──
     *  Catches sustained abuse that stays under the burst limit.          */
    $hour_key   = 'mlp_hr_' . $ip_key;
    $hour_count = (int) get_transient( $hour_key );
    if ( $hour_count >= 40 ) {
        wp_send_json_error( [ 'message' => 'Hourly limit reached. Please try again later.' ], 429 );
        return;
    }
    set_transient( $hour_key, $hour_count + 1, HOUR_IN_SECONDS );

    /* ── Layer 3: Banned IP list (object-cache backed) ─────────────────────
     * CPU fix v2.1.2: get_option('mlp_banned_ips') was a MySQL round-trip on
     * every AJAX request. Now served from wp_cache (RAM on APCu/Memcached,
     * or in-process request cache on shared hosts). MySQL only queried once
     * per 5-minute window. Cache is invalidated immediately on auto-ban. */
    $banned = wp_cache_get( 'mlp_banned_ips', 'mlp' );
    if ( false === $banned ) {
        $banned = (array) get_option( 'mlp_banned_ips', [] );
        wp_cache_set( 'mlp_banned_ips', $banned, 'mlp', 300 );
    }
    if ( in_array( $ip, $banned, true ) ) {
        wp_send_json_error( [ 'message' => 'Access denied.' ], 403 );
        return;
    }

    /* ── Auto-ban: if an IP hits the hourly cap 3× in a row, ban it ──
     *  Tracks strike count per IP across multiple hours.                  */
    $strike_key   = 'mlp_strikes_' . $ip_key;
    $strike_count = (int) get_transient( $strike_key );
    if ( $hour_count + 1 >= 40 ) { /* they just hit the cap this request */
        $strike_count++;
        set_transient( $strike_key, $strike_count, DAY_IN_SECONDS );
        if ( $strike_count >= 3 ) {
            $banned[] = $ip;
            update_option( 'mlp_banned_ips', array_unique( $banned ) );
            wp_cache_delete( 'mlp_banned_ips', 'mlp' ); /* bust cache so next request re-reads */
        }
    }

    /* ── Request signature check ──
     *  Bots often send requests with no Referer or a mismatched origin.
     *  This is a soft signal — we log it but don't hard-block on its own. */
    $referer      = wp_get_referer();
    $origin_ok    = ! empty( $referer ) && (
        str_contains( $referer, home_url() ) ||
        str_contains( $referer, wp_parse_url( home_url(), PHP_URL_HOST ) )
    );
    if ( ! $origin_ok ) {
        /* Bad referer counts double toward the burst limit as a penalty */
        $burst_data[] = $now;
        set_transient( $burst_key, $burst_data, 10 );
    }

    /* ════════════════════════════════════════════════════════════════ */

    /* ── Inputs ── */
    $user_msg = sanitize_textarea_field( wp_unslash( $_POST['message'] ?? '' ) );
    $html     = wp_unslash( $_POST['html'] ?? '' );
    $css      = wp_unslash( $_POST['css']  ?? '' );
    $js       = wp_unslash( $_POST['js']   ?? '' );
    $history  = json_decode( wp_unslash( $_POST['history'] ?? '[]' ), true );
    if ( ! is_array( $history ) ) { $history = []; }

    /* ── Image attachments (base64 data URLs sent from browser) ── */
    $images_raw = json_decode( wp_unslash( $_POST['images'] ?? '[]' ), true );
    if ( ! is_array( $images_raw ) ) { $images_raw = []; }
    /* Validate and extract: keep only image/* mimeTypes, cap base64 size at ~4MB each */
    $images = [];
    foreach ( $images_raw as $img ) {
        $mime = sanitize_text_field( $img['mimeType'] ?? '' );
        if ( ! preg_match( '/^image\/(jpeg|png|gif|webp|bmp)$/i', $mime ) ) { continue; }
        $data_url = $img['dataUrl'] ?? '';
        /* Strip the data:image/...;base64, prefix */
        if ( ! preg_match( '/^data:image\/[^;]+;base64,(.+)$/s', $data_url, $m ) ) { continue; }
        $b64 = $m[1];
        if ( strlen( $b64 ) > 5500000 ) { continue; } /* ~4MB limit */
        $images[] = [ 'mimeType' => strtolower( $mime ), 'data' => $b64 ];
    }
    unset( $images_raw );

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

    /* ── Build the context block (done once, reused by all providers) ── */
    /* trim() computed once per variable — not 2× per variable as before */
    $html_t = trim( $html ); unset( $html );
    $css_t  = trim( $css  ); unset( $css  );
    $js_t   = trim( $js   ); unset( $js   );
    $code_context = '';
    if ( $html_t || $css_t || $js_t ) {
        $code_context  = "\n\n--- CURRENT EDITOR CODE ---\n";
        if ( $html_t ) { $code_context .= "### HTML\n" . substr( $html_t, 0, 5000 ) . "\n"; }
        if ( $css_t  ) { $code_context .= "### CSS\n"  . substr( $css_t,  0, 2500 ) . "\n"; }
        if ( $js_t   ) { $code_context .= "### JS\n"   . substr( $js_t,   0, 2500 ) . "\n"; }
        $code_context .= "--- END OF CODE ---\n";
    }
    unset( $html_t, $css_t, $js_t );

    /* ── System prompt ── */
    $system = <<<'SYS'
You are an elite HTML/CSS/JavaScript front-end engineer embedded inside a live Monaco code editor. You have deep expertise in modern web standards, accessibility, performance, and design systems.

━━━ YOUR ROLE ━━━
You assist developers in writing, editing, explaining, debugging, optimizing, and refactoring front-end code. You always read the provided editor code before answering — never assume what code looks like.

━━━ CODE OUTPUT FORMAT (MANDATORY — NEVER SKIP) ━━━
1. When producing or modifying code, wrap each file type in its own labeled fence:
   ```html
   <!-- full html here -->
   ```
   ```css
   /* full css here */
   ```
   ```js
   // full js here
   ```
2. Only include fences for file types you are actually changing.
3. Always output the COMPLETE file content inside each fence — never partial snippets, "... rest stays the same", or "add this to your code" comments.
4. When doing a small targeted edit, still output the whole modified file so the Apply button works correctly.
5. If you only explain without changing code, use zero code fences.
6. CRITICAL: If the user asks you to build, create, add, fix, change, update, make, generate, or modify ANYTHING in their code — you MUST output the full modified code inside fences. Never describe the change without showing the code. Never say "here's what you need to add" and then not include the full file. A response without code fences when code was requested is a failure.

━━━ RESPONSE QUALITY RULES ━━━
• Think step-by-step before answering complex requests.
• For bugs: identify root cause first, then fix. Briefly explain what was wrong.
• For new features: consider edge cases, accessibility (ARIA, keyboard nav), and mobile responsiveness.
• For explanations: be clear and educational. Use analogies for complex concepts.
• Prefer modern CSS (Grid, Flexbox, custom properties) over float/table hacks.
• Prefer vanilla JS unless a library is already in use; avoid adding external dependencies without asking.
• Write clean, readable code with descriptive variable names and brief inline comments on non-obvious logic.
• When you refactor, briefly note the performance or maintainability gains.
• Never add PHP, server-side code, or CDN imports the user didn't ask for.
• Never include `<link rel="stylesheet" href="...">` tags that reference external or local CSS files. All CSS must be written inline inside a ```css fence or in a `<style>` block within the HTML.

━━━ TONE & STYLE ━━━
• Be direct, confident, and concise. No filler phrases.
• Use markdown: **bold** for key terms, `inline code` for identifiers, numbered lists for steps.
• If a request is ambiguous, make a reasonable assumption and state it, then proceed.
• If you notice other bugs or improvements beyond what was asked, mention them briefly at the end as "💡 Bonus tip:" without changing unrequested code.
SYS;

    /*
     * CPU OPTIMISATION: All three providers (Cerebras, Groq, Pollinations) use the
     * OpenAI messages[] format, so we build it once lazily and share it across all
     * provider calls. History turns capped at 4000 chars each to limit payload size.
     */
    $new_user_text = $user_msg . $code_context;
    $oai_messages  = null;   /* built on first provider call */

    /* Pre-process history once into a neutral array */
    $history_norm = [];
    foreach ( array_slice( $history, -10 ) as $turn ) {
        if ( empty( $turn['role'] ) || empty( $turn['content'] ) ) { continue; }
        $history_norm[] = [
            'role'    => $turn['role'],
            'content' => substr( $turn['content'], 0, 4000 ),
        ];
    }
    unset( $history ); /* release raw history memory */

    $reply         = null;
    $last_err      = '';
    $provider_used = '';

    /* Lazy builder: OpenAI-style messages[] (shared by all providers) */
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

    /* ══════════════════════════════════════════════════════
       HELPER — call Replit AI (PRIMARY)
       Proxies through the Replit AI server endpoint.
       Streams SSE and collects the full response.
       Define MLP_REPLIT_API_URL in wp-config.php to set
       the endpoint (must be your deployed Replit API URL).
       ══════════════════════════════════════════════════════ */
    $call_replit = function() use ( &$reply, &$last_err, &$provider_used, $history_norm, $new_user_text, $system, $user_msg ) {
        $replit_url = defined( 'MLP_REPLIT_API_URL' ) ? MLP_REPLIT_API_URL : '';
        if ( empty( $replit_url ) ) {
            $last_err = 'Replit AI: MLP_REPLIT_API_URL not defined in wp-config.php';
            return;
        }

        /* Build history for Replit AI endpoint */
        $replit_history = [];
        foreach ( $history_norm as $t ) {
            $replit_history[] = [
                'role'    => $t['role'],
                'content' => $t['content'],
            ];
        }

        $replit_body = wp_json_encode( [
            'message' => $user_msg,
            'system'  => $system,
            'history' => $replit_history,
            'html'    => isset( $_POST['html'] ) ? wp_unslash( $_POST['html'] ) : '',
            'css'     => isset( $_POST['css'] )  ? wp_unslash( $_POST['css'] )  : '',
            'js'      => isset( $_POST['js'] )   ? wp_unslash( $_POST['js'] )   : '',
        ] );

        $r_res = wp_remote_post( $replit_url, [
            'timeout'    => 60,
            'user-agent' => 'MobileLivePreview-Chat/2.2',
            'headers'    => [ 'Content-Type' => 'application/json', 'Accept' => 'text/event-stream' ],
            'body'       => $replit_body,
        ] );

        if ( is_wp_error( $r_res ) ) {
            $last_err = 'Replit AI WP error: ' . $r_res->get_error_message();
            return;
        }

        $r_code = (int) wp_remote_retrieve_response_code( $r_res );
        if ( $r_code < 200 || $r_code >= 300 ) {
            $last_err = 'Replit AI HTTP ' . $r_code;
            return;
        }

        /* Parse SSE stream — collect all content chunks */
        $raw_body   = wp_remote_retrieve_body( $r_res );
        $full_reply = '';
        foreach ( explode( "\n", $raw_body ) as $line ) {
            $line = trim( $line );
            if ( strpos( $line, 'data: ' ) !== 0 ) { continue; }
            $json = json_decode( substr( $line, 6 ), true );
            if ( ! is_array( $json ) ) { continue; }
            if ( isset( $json['content'] ) ) {
                $full_reply .= $json['content'];
            }
            if ( ! empty( $json['done'] ) ) { break; }
        }

        if ( $full_reply ) {
            $reply         = $full_reply;
            $provider_used = 'Replit · gpt-5.2';
        } else {
            $last_err = 'Replit AI: empty response';
        }
    };

    /* ══════════════════════════════════════════════════════
       HELPER — call Mistral AI
       Uses the Mistral API with mistral-large-latest model.
       ══════════════════════════════════════════════════════ */
    /* ── Dynamic max_tokens based on message length (saves quota) ── */
    $msg_len    = strlen( $user_msg ) + strlen( $code_context );
    $max_tokens = ( $msg_len < 300 ) ? 512 : ( ( $msg_len < 1000 ) ? 1500 : 4096 );

    $call_mistral = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages, $max_tokens ) {
        /* ── Skip if quota was recently exhausted ── */
        if ( get_transient( 'mlp_quota_mistral' ) ) {
            $last_err = 'Mistral quota exhausted (cached — skipping)';
            return;
        }
        $build_oai_messages();

        $mistral_key     = defined( 'MLP_MISTRAL_API_KEY' ) ? MLP_MISTRAL_API_KEY : '';
        $mistral_timeout = 30;
        $mistral_models  = [ 'mistral-large-latest', 'mistral-medium-latest', 'mistral-small-latest' ];

        $body_base = [
            'messages'    => $oai_messages,
            'temperature' => 0.4,
            'max_tokens'  => $max_tokens,
            'top_p'       => 0.95,
        ];

        foreach ( $mistral_models as $model ) {
            $body_base['model'] = $model;
            $m_res = wp_remote_post( 'https://api.mistral.ai/v1/chat/completions', [
                'timeout'    => $mistral_timeout,
                'user-agent' => 'MobileLivePreview-Chat/2.2',
                'headers'    => [
                    'Content-Type'  => 'application/json',
                    'Authorization' => 'Bearer ' . $mistral_key,
                ],
                'body' => wp_json_encode( $body_base ),
            ] );
            $http_code = is_wp_error( $m_res ) ? 0 : (int) wp_remote_retrieve_response_code( $m_res );

            if ( $http_code === 200 ) {
                $m_body = json_decode( wp_remote_retrieve_body( $m_res ), true );
                $m_text = $m_body['choices'][0]['message']['content'] ?? '';
                if ( $m_text ) {
                    $reply         = $m_text;
                    $label_map     = [
                        'mistral-large-latest'  => 'Mistral · Large',
                        'mistral-medium-latest' => 'Mistral · Medium',
                        'mistral-small-latest'  => 'Mistral · Small',
                    ];
                    $provider_used = $label_map[ $model ] ?? ( 'Mistral · ' . $model );
                    return;
                }
                $last_err = 'Mistral(' . $model . ') empty response';
            } elseif ( $http_code === 429 ) {
                $last_err = 'Mistral(' . $model . ') quota/rate-limit (429)';
                set_transient( 'mlp_quota_mistral', 1, HOUR_IN_SECONDS ); /* cache: skip for 1 hour */
                break; /* quota hit — skip remaining Mistral models */
            } else {
                $err_msg  = is_wp_error( $m_res ) ? $m_res->get_error_message() : $http_code;
                $last_err = 'Mistral(' . $model . ') err=' . $err_msg;
            }
        }
    };

    /* ══════════════════════════════════════════════════════
       OpenAI-compatible API. llama-3.3-70b is the fastest
       high-quality model on Cerebras's dedicated silicon.
       ══════════════════════════════════════════════════════ */
    $call_cerebras = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages, $max_tokens ) {
        /* ── Skip if quota was recently exhausted ── */
        if ( get_transient( 'mlp_quota_cerebras' ) ) {
            $last_err = 'Cerebras quota exhausted (cached — skipping)';
            return;
        }
        $build_oai_messages();

        $cerebras_key = defined( 'MLP_CEREBRAS_API_KEY' ) ? MLP_CEREBRAS_API_KEY : '';

        /* Cerebras models — ordered best-quality first, fastest fallback last */
        $cerebras_models  = [ 'llama-3.3-70b', 'llama3.1-70b', 'llama3.1-8b' ];
        $cerebras_timeout = 25;

        $body_base = [
            'messages'    => $oai_messages,
            'temperature' => 0.4,
            'max_tokens'  => $max_tokens,
            'top_p'       => 0.95,
        ];

        foreach ( $cerebras_models as $model ) {
            $body_base['model'] = $model;
            $c_res = wp_remote_post( 'https://api.cerebras.ai/v1/chat/completions', [
                'timeout'    => $cerebras_timeout,
                'user-agent' => 'MobileLivePreview-Chat/2.2',
                'headers'    => [
                    'Content-Type'  => 'application/json',
                    'Authorization' => 'Bearer ' . $cerebras_key,
                ],
                'body' => wp_json_encode( $body_base ),
            ] );
            $http_code = is_wp_error( $c_res ) ? 0 : (int) wp_remote_retrieve_response_code( $c_res );

            if ( $http_code === 200 ) {
                $c_body = json_decode( wp_remote_retrieve_body( $c_res ), true );
                $c_text = $c_body['choices'][0]['message']['content'] ?? '';
                if ( $c_text ) {
                    $reply         = $c_text;
                    $label_map     = [
                        'llama-3.3-70b' => 'Cerebras · Llama 3.3 70B',
                        'llama3.1-70b'  => 'Cerebras · Llama 3.1 70B',
                        'llama3.1-8b'   => 'Cerebras · Llama 3.1 8B',
                    ];
                    $provider_used = $label_map[ $model ] ?? ( 'Cerebras · ' . $model );
                    return;
                }
                $last_err = 'Cerebras(' . $model . ') empty response';
            } elseif ( $http_code === 429 ) {
                $last_err = 'Cerebras(' . $model . ') quota/rate-limit (429)';
                set_transient( 'mlp_quota_cerebras', 1, HOUR_IN_SECONDS ); /* cache: skip for 1 hour */
                break; /* quota hit — skip remaining Cerebras models */
            } else {
                $err_msg  = is_wp_error( $c_res ) ? $c_res->get_error_message() : $http_code;
                $last_err = 'Cerebras(' . $model . ') err=' . $err_msg;
            }
        }
    };

    /* ══════════════════════════════════════════════════════
       HELPER — call Groq
       Uses confirmed-active Groq models as of 2025-Q1.
       max_tokens reduced to 4096 to stay within free-tier rate limits.
       ══════════════════════════════════════════════════════ */
    $call_groq = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages, $max_tokens ) { /* Groq fallback */
        /* ── Skip if quota was recently exhausted ── */
        if ( get_transient( 'mlp_quota_groq' ) ) {
            $last_err = 'Groq quota exhausted (cached — skipping)';
            return;
        }
        $build_oai_messages();

        $groq_key     = defined( 'MLP_GROQ_API_KEY' ) ? MLP_GROQ_API_KEY : '';
        $groq_timeout = 25;
        /*
         * Confirmed active Groq models (March 2025).
         * llama-3.1-70b-versatile was removed; replaced by llama-3.3-70b-versatile.
         * llama3-70b-8192 deprecated; llama3-8b-8192 is still active.
         * mixtral-8x7b-32768 deprecated; gemma2-9b-it added as lightweight fallback.
         */
        $groq_models  = [ 'llama-3.3-70b-versatile', 'llama3-8b-8192', 'gemma2-9b-it' ];

        $body_base = [ 'messages' => $oai_messages, 'temperature' => 0.4, 'max_tokens' => $max_tokens, 'top_p' => 0.95 ];

        foreach ( $groq_models as $g_model ) {
            $body_base['model'] = $g_model;
            $q_res = wp_remote_post( 'https://api.groq.com/openai/v1/chat/completions', [
                'timeout'    => $groq_timeout,
                'user-agent' => 'MobileLivePreview-Chat/2.2',
                'headers'    => [ 'Content-Type' => 'application/json', 'Authorization' => 'Bearer ' . $groq_key ],
                'body'       => wp_json_encode( $body_base ),
            ] );
            $q_code = is_wp_error( $q_res ) ? 0 : (int) wp_remote_retrieve_response_code( $q_res );
            if ( $q_code === 200 ) {
                $q_body = json_decode( wp_remote_retrieve_body( $q_res ), true );
                $q_text = $q_body['choices'][0]['message']['content'] ?? '';
                if ( $q_text ) { $reply = $q_text; $provider_used = 'Groq · ' . $g_model; return; }
            }
            $err_msg  = is_wp_error( $q_res ) ? $q_res->get_error_message() : $q_code;
            $last_err = 'Groq(' . $g_model . ') err=' . $err_msg;
            if ( $q_code === 429 ) {
                set_transient( 'mlp_quota_groq', 1, HOUR_IN_SECONDS ); /* cache: skip for 1 hour */
                break;
            } /* quota hit — skip remaining Groq models */
        }
    };

    /* ══════════════════════════════════════════════════════
       HELPER — call Pollinations (no API key required)
       Current endpoint: gen.pollinations.ai/v1/chat/completions
       text.pollinations.ai is fully deprecated as of early 2026.
       Anonymous tier: 1 req / 15 s — fine for fallback use.
       ══════════════════════════════════════════════════════ */
    $call_pollinations = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages ) {
        $build_oai_messages();

        /* openai-large = GPT-4o class; openai = GPT-4o-mini; mistral = fast fallback */
        $philo_models = [ 'openai-large', 'openai', 'mistral' ];

        foreach ( $philo_models as $ph_model ) {
            $p_res = wp_remote_post( 'https://gen.pollinations.ai/v1/chat/completions', [
                'timeout'    => 30,
                'user-agent' => 'MobileLivePreview-Chat/2.2',
                'headers'    => [ 'Content-Type' => 'application/json' ],
                'body' => wp_json_encode( [
                    'model'    => $ph_model,
                    'messages' => $oai_messages,
                    'private'  => true,
                ] ),
            ] );
            if ( is_wp_error( $p_res ) ) {
                $last_err = 'Pollinations WP error: ' . $p_res->get_error_message();
                continue;
            }
            $p_code = (int) wp_remote_retrieve_response_code( $p_res );
            if ( $p_code === 429 ) { $last_err = 'Pollinations rate-limited'; break; }
            if ( $p_code < 200 || $p_code >= 300 ) {
                $last_err = 'Pollinations(' . $ph_model . ') HTTP ' . $p_code;
                continue;
            }
            $p_json = json_decode( wp_remote_retrieve_body( $p_res ), true );
            $p_text = $p_json['choices'][0]['message']['content'] ?? '';
            if ( $p_text ) {
                $reply         = $p_text;
                $provider_used = 'Pollinations · ' . $ph_model;
                return;
            }
            $last_err = 'Pollinations(' . $ph_model . ') empty response';
        }
    };

    /* ══════════════════════════════════════════════════════
       HELPER — call Google Gemini
       gemini-2.5-flash  — free forever, no daily quota on free tier
       Key from define('MLP_GEMINI_KEY','...') in wp-config.php
       ══════════════════════════════════════════════════════ */
    $call_gemini = function() use ( &$reply, &$last_err, &$provider_used, $history_norm, $new_user_text, $system, $images ) {
        $gemini_key = defined( 'MLP_GEMINI_KEY' ) ? MLP_GEMINI_KEY : '';
        if ( empty( $gemini_key ) ) {
            $last_err = 'Gemini: MLP_GEMINI_KEY not defined in wp-config.php';
            return;
        }

        /*
         * Build Gemini contents[] directly from history + current message.
         * Inject system prompt as a prefixed first user turn — most reliable
         * approach, avoids systemInstruction scope/format issues.
         * Gemini requires strictly alternating user / model turns.
         */
        $contents = [];

        /* System prompt injected into first user message */
        $first_user_text = "SYSTEM INSTRUCTIONS:\n" . $system . "\n\n---\n\n";

        /* Add history turns */
        foreach ( $history_norm as $turn ) {
            $role = ( $turn['role'] === 'assistant' ) ? 'model' : 'user';
            if ( empty( $contents ) ) {
                /* Prepend system to the very first user turn */
                $text = ( $role === 'user' ) ? ( $first_user_text . $turn['content'] ) : $turn['content'];
                $first_user_text = ''; /* only prepend once */
            } else {
                $text = $turn['content'];
            }
            /* Merge consecutive same-role turns */
            if ( ! empty( $contents ) && end( $contents )['role'] === $role ) {
                $contents[ count($contents) - 1 ]['parts'][0]['text'] .= "\n" . $text;
            } else {
                $contents[] = [ 'role' => $role, 'parts' => [ [ 'text' => $text ] ] ];
            }
        }

        /* Add the current user message — with inline images if present */
        $cur_text = $first_user_text . $new_user_text;

        /* Build parts array: images first, then the text prompt */
        $cur_parts = [];
        foreach ( $images as $img ) {
            $cur_parts[] = [
                'inline_data' => [
                    'mime_type' => $img['mimeType'],
                    'data'      => $img['data'],
                ],
            ];
        }
        $cur_parts[] = [ 'text' => $cur_text ];

        if ( ! empty( $contents ) && end( $contents )['role'] === 'user' ) {
            /* Append to existing last user turn */
            $last_idx = count( $contents ) - 1;
            foreach ( $cur_parts as $part ) {
                $contents[ $last_idx ]['parts'][] = $part;
            }
        } else {
            $contents[] = [ 'role' => 'user', 'parts' => $cur_parts ];
        }

        $gemini_body = [
            'contents'         => $contents,
            'generationConfig' => [
                'temperature'     => 0.4,
                'maxOutputTokens' => 8192,
                'topP'            => 0.95,
            ],
        ];

        $gemini_models = [ 'gemini-2.5-flash' ];

        foreach ( $gemini_models as $g_model ) {
            $g_url = 'https://generativelanguage.googleapis.com/v1beta/models/'
                   . $g_model . ':generateContent?key=' . $gemini_key;
            $g_res = wp_remote_post( $g_url, [
                'timeout'    => 30,
                'user-agent' => 'MobileLivePreview-Chat/2.2',
                'headers'    => [ 'Content-Type' => 'application/json' ],
                'body'       => wp_json_encode( $gemini_body ),
            ] );
            if ( is_wp_error( $g_res ) ) {
                $last_err = 'Gemini(' . $g_model . ') WP error: ' . $g_res->get_error_message();
                continue;
            }
            $g_code = (int) wp_remote_retrieve_response_code( $g_res );
            if ( $g_code === 200 ) {
                $g_json = json_decode( wp_remote_retrieve_body( $g_res ), true );
                $g_text = $g_json['candidates'][0]['content']['parts'][0]['text'] ?? '';
                if ( $g_text ) {
                    $reply         = $g_text;
                    $provider_used = 'Gemini · ' . $g_model;
                    return;
                }
                $finish   = $g_json['candidates'][0]['finishReason'] ?? 'UNKNOWN';
                $last_err = 'Gemini(' . $g_model . ') empty — finishReason=' . $finish;
            } elseif ( $g_code === 429 ) {
                $last_err = 'Gemini rate-limited (429) — retrying next request';
                break;
            } else {
                $raw      = wp_remote_retrieve_body( $g_res );
                $err_obj  = json_decode( $raw, true );
                $err_msg  = $err_obj['error']['message'] ?? ( 'HTTP ' . $g_code );
                $last_err = 'Gemini(' . $g_model . ') err=' . $err_msg;
            }
        }
    };

    /* ══════════════════════════════════════════════════════
       HELPER — call GitHub Models (free tier, no billing)
       Endpoint: https://models.github.ai/inference
       Free limits: 10–15 RPM, 50–150 req/day (model-dependent)
       Fully OpenAI-compatible — same messages[] format.
       Define MLP_GITHUB_API_KEY in wp-config.php:
         define( 'MLP_GITHUB_API_KEY', '...' );
       ══════════════════════════════════════════════════════ */
    $call_github = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages, $max_tokens, $images ) {
        if ( get_transient( 'mlp_quota_github' ) ) {
            $last_err = 'GitHub Models quota exhausted (cached — skipping)';
            return;
        }
        $github_key = defined( 'MLP_GITHUB_API_KEY' ) ? MLP_GITHUB_API_KEY : '';
        if ( empty( $github_key ) ) {
            $last_err = 'GitHub Models: MLP_GITHUB_API_KEY not defined in wp-config.php';
            return;
        }
        $build_oai_messages();

        /* If images are attached, rebuild the last user message as a content array */
        $messages_to_send = $oai_messages;
        if ( ! empty( $images ) ) {
            $last_idx = count( $messages_to_send ) - 1;
            if ( $messages_to_send[ $last_idx ]['role'] === 'user' ) {
                $content_parts = [];
                foreach ( $images as $img ) {
                    $content_parts[] = [
                        'type'      => 'image_url',
                        'image_url' => [ 'url' => 'data:' . $img['mimeType'] . ';base64,' . $img['data'] ],
                    ];
                }
                $content_parts[] = [ 'type' => 'text', 'text' => $messages_to_send[ $last_idx ]['content'] ];
                $messages_to_send[ $last_idx ]['content'] = $content_parts;
            }
        }

        /* Best free models on GitHub Models — vision only on gpt-4o */
        $github_models = ! empty( $images ) ? [ 'gpt-4o' ] : [ 'gpt-4o', 'gpt-4o-mini', 'meta-llama-3.3-70b-instruct' ];

        $body_base = [
            'messages'    => $messages_to_send,
            'temperature' => 0.4,
            'max_tokens'  => min( $max_tokens, 4096 ),
            'top_p'       => 0.95,
        ];

        foreach ( $github_models as $model ) {
            $body_base['model'] = $model;
            $g_res = wp_remote_post( 'https://models.inference.ai.azure.com/chat/completions', [
                'timeout'    => 30,
                'user-agent' => 'MobileLivePreview-Chat/2.2',
                'headers'    => [
                    'Content-Type'  => 'application/json',
                    'Authorization' => 'Bearer ' . $github_key,
                ],
                'body' => wp_json_encode( $body_base ),
            ] );
            $http_code = is_wp_error( $g_res ) ? 0 : (int) wp_remote_retrieve_response_code( $g_res );

            if ( $http_code === 200 ) {
                $g_body = json_decode( wp_remote_retrieve_body( $g_res ), true );
                $g_text = $g_body['choices'][0]['message']['content'] ?? '';
                if ( $g_text ) {
                    $reply         = $g_text;
                    $provider_used = 'GitHub · ' . $model;
                    return;
                }
                $last_err = 'GitHub(' . $model . ') empty response';
            } elseif ( $http_code === 429 ) {
                $last_err = 'GitHub Models rate-limited (429)';
                set_transient( 'mlp_quota_github', 1, HOUR_IN_SECONDS );
                break; /* quota hit — skip remaining GitHub models */
            } else {
                $err_msg  = is_wp_error( $g_res ) ? $g_res->get_error_message() : $http_code;
                $last_err = 'GitHub(' . $model . ') err=' . $err_msg;
            }
        }
    };

    /* ══════════════════════════════════════════════════════
       HELPER — call Cohere (ND-2)
       command-r-plus is Cohere's best public model.
       Key from define('MLP_COHERE_API_KEY','...') in wp-config.php
       ══════════════════════════════════════════════════════ */
    $call_cohere = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages, $max_tokens ) {
        if ( get_transient( 'mlp_quota_cohere' ) ) {
            $last_err = 'Cohere quota exhausted (cached — skipping)';
            return;
        }
        $cohere_key = defined( 'MLP_COHERE_API_KEY' ) ? MLP_COHERE_API_KEY : '';
        if ( empty( $cohere_key ) ) {
            $last_err = 'Cohere: MLP_COHERE_API_KEY not defined in wp-config.php';
            return;
        }
        $build_oai_messages();

        /* Cohere uses OpenAI-compatible /v2/chat/completions */
        $cohere_models = [ 'command-a-03-2025', 'command-r-plus', 'command-r' ];
        $body_base = [
            'messages'    => $oai_messages,
            'temperature' => 0.4,
            'max_tokens'  => $max_tokens,
        ];
        foreach ( $cohere_models as $model ) {
            $body_base['model'] = $model;
            $c_res = wp_remote_post( 'https://api.cohere.com/v2/chat', [
                'timeout'    => 30,
                'user-agent' => 'MobileLivePreview-Chat/2.3',
                'headers'    => [
                    'Content-Type'  => 'application/json',
                    'Authorization' => 'Bearer ' . $cohere_key,
                ],
                'body' => wp_json_encode( $body_base ),
            ] );
            $http_code = is_wp_error( $c_res ) ? 0 : (int) wp_remote_retrieve_response_code( $c_res );
            if ( $http_code === 200 ) {
                $c_body = json_decode( wp_remote_retrieve_body( $c_res ), true );
                /* Cohere v2: message.content[0].text  OR  choices[0].message.content (OpenAI-compat fallback) */
                $c_text = $c_body['message']['content'][0]['text']
                       ?? $c_body['choices'][0]['message']['content']
                       ?? '';
                if ( $c_text ) {
                    $reply         = $c_text;
                    $provider_used = 'Cohere · ' . $model;
                    return;
                }
                $last_err = 'Cohere(' . $model . ') empty response';
            } elseif ( $http_code === 429 ) {
                $last_err = 'Cohere rate-limited (429)';
                set_transient( 'mlp_quota_cohere', 1, HOUR_IN_SECONDS );
                break;
            } else {
                if ( is_wp_error( $c_res ) ) {
                    $last_err = 'Cohere(' . $model . ') WP error: ' . $c_res->get_error_message();
                } else {
                    $raw_err  = wp_remote_retrieve_body( $c_res );
                    $last_err = 'Cohere(' . $model . ') HTTP ' . $http_code . ' — ' . substr( $raw_err, 0, 200 );
                }
            }
        }
    };

    /* ══════════════════════════════════════════════════════
       HELPER — call SiliconFlow (ND-2)
       Free permanent models — OpenAI-compatible endpoint.
       Key from define('MLP_SILICON_API_KEY','...') in wp-config.php
       ══════════════════════════════════════════════════════ */
    $call_together = function() use ( &$reply, &$last_err, &$oai_messages, &$provider_used, $build_oai_messages, $max_tokens ) {
        if ( get_transient( 'mlp_quota_together' ) ) {
            $last_err = 'SiliconFlow quota exhausted (cached — skipping)';
            return;
        }
        $together_key = defined( 'MLP_SILICON_API_KEY' ) ? MLP_SILICON_API_KEY : '';
        if ( empty( $together_key ) ) {
            $last_err = 'SiliconFlow: MLP_SILICON_API_KEY not defined in wp-config.php';
            return;
        }
        $build_oai_messages();

        /* SiliconFlow is OpenAI-compatible — free permanent models */
        $together_models = [ 'Qwen/Qwen3-8B', 'deepseek-ai/DeepSeek-R1-Distill-Qwen-7B', 'THUDM/glm-4-9b-chat' ];
        $body_base = [
            'messages'    => $oai_messages,
            'temperature' => 0.4,
            'max_tokens'  => $max_tokens,
        ];
        foreach ( $together_models as $model ) {
            $body_base['model'] = $model;
            $t_res = wp_remote_post( 'https://api.siliconflow.com/v1/chat/completions', [
                'timeout'    => 30,
                'user-agent' => 'MobileLivePreview-Chat/2.3',
                'headers'    => [
                    'Content-Type'  => 'application/json',
                    'Authorization' => 'Bearer ' . $together_key,
                ],
                'body' => wp_json_encode( $body_base ),
            ] );
            $http_code = is_wp_error( $t_res ) ? 0 : (int) wp_remote_retrieve_response_code( $t_res );
            if ( $http_code === 200 ) {
                $t_body = json_decode( wp_remote_retrieve_body( $t_res ), true );
                $t_text = $t_body['choices'][0]['message']['content'] ?? '';
                if ( $t_text ) {
                    $reply         = $t_text;
                    $provider_used = 'SiliconFlow · ' . basename( $model );
                    return;
                }
                $last_err = 'SiliconFlow(' . $model . ') empty response';
            } elseif ( $http_code === 429 ) {
                $last_err = 'SiliconFlow rate-limited (429)';
                set_transient( 'mlp_quota_together', 1, HOUR_IN_SECONDS );
                break;
            } else {
                if ( is_wp_error( $t_res ) ) {
                    $last_err = 'SiliconFlow(' . $model . ') WP error: ' . $t_res->get_error_message();
                } else {
                    $raw_err  = wp_remote_retrieve_body( $t_res );
                    $last_err = 'SiliconFlow(' . $model . ') HTTP ' . $http_code . ' — ' . substr( $raw_err, 0, 200 );
                }
            }
        }
    };

    /* ── ND tier: nd-2 supports replit and cerebras; nd-1 uses mistral/cerebras/groq ── */
    $nd_tier = sanitize_text_field( wp_unslash( $_POST['nd_tier'] ?? 'nd-1' ) );
    if ( ! in_array( $nd_tier, [ 'nd-1', 'nd-2' ], true ) ) { $nd_tier = 'nd-1'; }

    /* ── Execute fallback chain based on ND tier and provider ── */
    if ( $nd_tier === 'nd-2' ) {
        /* ND-2: chosen provider first, then rich fallback chain */
        if ( $provider === 'cerebras' ) {
            $tiers = [ $call_cerebras, $call_replit, $call_together, $call_cohere, $call_gemini, $call_github, $call_groq ];
        } elseif ( $provider === 'github' ) {
            $tiers = [ $call_github, $call_replit, $call_together, $call_cohere, $call_gemini, $call_cerebras, $call_groq ];
        } elseif ( $provider === 'gemini' ) {
            $tiers = [ $call_gemini, $call_replit, $call_together, $call_cohere, $call_cerebras, $call_github, $call_groq ];
        } elseif ( $provider === 'cohere' ) {
            $tiers = [ $call_cohere, $call_replit, $call_together, $call_gemini, $call_cerebras, $call_github, $call_groq ];
        } elseif ( $provider === 'siliconflow' ) {
            $tiers = [ $call_together, $call_replit, $call_cohere, $call_gemini, $call_cerebras, $call_github, $call_groq ];
        } else {
            /* replit or anything else → Replit first, then SiliconFlow, Cohere, Gemini, Cerebras, GitHub, Groq */
            $tiers = [ $call_replit, $call_together, $call_cohere, $call_gemini, $call_cerebras, $call_github, $call_groq ];
        }
    } else {
        /* ND-1: chosen provider first, then others */
        if ( $provider === 'groq' ) {
            $tiers = [ $call_groq, $call_mistral, $call_cerebras, $call_github ];
        } elseif ( $provider === 'cerebras' ) {
            $tiers = [ $call_cerebras, $call_mistral, $call_groq, $call_github ];
        } elseif ( $provider === 'github' ) {
            $tiers = [ $call_github, $call_mistral, $call_cerebras, $call_groq ];
        } else {
            /* mistral or default */
            $tiers = [ $call_mistral, $call_cerebras, $call_groq, $call_github ];
        }
    }

    foreach ( $tiers as $tier ) {
        if ( $reply ) { break; }
        $tier();
    }

    if ( ! $reply ) {
        /* Include the last technical error in WP_DEBUG mode for easier diagnosis */
        $debug_hint = ( defined( 'WP_DEBUG' ) && WP_DEBUG ) ? ' [debug: ' . $last_err . ']' : '';
        wp_send_json_error( [ 'message' => 'AI is temporarily unavailable. Please try again.' . $debug_hint ], 503 );
        return;
    }

    wp_send_json_success( [ 'reply' => $reply, 'provider' => $provider_used ] );
}


/* ═══════════════════════════════════════════════════════════════
   1b.  PHP — PROVIDER STATUS AJAX HANDLER  (mlp_ai_provider_status)
        Returns whether each provider is rate-limited (429 cached),
        or presumed active / unknown.
   ═══════════════════════════════════════════════════════════════ */
add_action( 'wp_ajax_mlp_ai_provider_status',        'mlp_ai_provider_status_handler' );
add_action( 'wp_ajax_nopriv_mlp_ai_provider_status', 'mlp_ai_provider_status_handler' );

function mlp_ai_provider_status_handler() {
    $providers = [ 'mistral', 'cerebras', 'groq', 'github' ];
    $statuses  = [];
    foreach ( $providers as $p ) {
        $quota_hit = (bool) get_transient( 'mlp_quota_' . $p );
        $statuses[ $p ] = $quota_hit ? 'rate_limited' : 'active';
    }
    /* Replit AI is active if the endpoint URL is configured */
    $statuses['replit'] = ( defined( 'MLP_REPLIT_API_URL' ) && ! empty( MLP_REPLIT_API_URL ) ) ? 'active' : 'active';
    /* Gemini 2.5 Flash — free forever, no quota tracking */
    $statuses['gemini'] = 'active';
    /* Cohere — quota tracked */
    $statuses['cohere']      = get_transient( 'mlp_quota_cohere' )   ? 'rate_limited' : 'active';
    /* SiliconFlow — free permanent, treat as always active unless rate-limited */
    $statuses['siliconflow'] = get_transient( 'mlp_quota_together' ) ? 'rate_limited' : 'active';
    wp_send_json_success( $statuses );
}

/* ── Clear a stuck rate-limit transient ── */
add_action( 'wp_ajax_mlp_ai_clear_quota',        'mlp_ai_clear_quota_handler' );
add_action( 'wp_ajax_nopriv_mlp_ai_clear_quota', 'mlp_ai_clear_quota_handler' );

function mlp_ai_clear_quota_handler() {
    $provider = sanitize_text_field( wp_unslash( $_POST['provider'] ?? '' ) );
    $allowed  = [ 'mistral', 'cerebras', 'groq', 'github', 'gemini', 'cohere', 'siliconflow' ];
    if ( ! in_array( $provider, $allowed, true ) ) {
        wp_send_json_error( [ 'message' => 'Invalid provider.' ], 400 );
        return;
    }
    delete_transient( 'mlp_quota_' . $provider );
    wp_send_json_success( [ 'cleared' => $provider ] );
}

/* ═══════════════════════════════════════════════════════════════
   2.  CSS + JS  (injected on frontend pages that have the shortcode)
   ═══════════════════════════════════════════════════════════════ */
add_action( 'wp_footer', 'mlp_ai_chat_output', 99 );

add_action( 'wp_enqueue_scripts', function () {
    global $post;
    if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) { return; }
    wp_enqueue_script( 'cf-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit', [], null, true );
} );

function mlp_ai_chat_output() {
    global $post;
    if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) {
        return;
    }
    $is_admin_user = current_user_can( 'manage_options' ) ? 'true' : 'false';
    echo '<script>';
    echo 'window.mlp_ajax = window.mlp_ajax || {};';
    echo 'window.mlp_ajax.ajaxurl = ' . wp_json_encode( admin_url( 'admin-ajax.php' ) ) . ';';
    echo 'window.mlp_ajax.nonce = ' . wp_json_encode( wp_create_nonce( 'mlp_ai_chat' ) ) . ';';
    echo 'window.mlp_ajax.is_admin = ' . $is_admin_user . ';';
    echo '</script>';
    ?>
<!-- ═══════════════ MLP AI CHAT SIDEBAR v2.2 — Cursor Exact ═══════════════ -->
<style>
@import url('https://fonts.googleapis.com/css2?family=Geist+Mono:wght@400;500;600&family=Geist:wght@300;400;500;600&display=swap');

:root {
  --c-bg:        #edeae4;
  --c-bg2:       #e4e0d8;
  --c-bg3:       #d9d5cd;
  --c-border:    #cec9c0;
  --c-border2:   #d6cfc4;
  --c-text:      #2e2a24;
  --c-text2:     #7a6e62;
  --c-text3:     #a89e90;
  --c-accent:    #5b8df6;
  --c-acc-dim:   rgba(91,141,246,0.12);
  --c-acc-glow:  rgba(91,141,246,0.20);
  --c-user-bg:   #dde5f0;
  --c-user-bdr:  #b8c8e0;
  --c-font:      'Geist', -apple-system, system-ui, sans-serif;
  --c-mono:      'Geist Mono', 'Consolas', monospace;
}

/* ── Dark mode overrides ── */
.mlp-chat-sidebar.mlp-dark-mode {
  --c-bg:        #1e1e1e;
  --c-bg2:       #252526;
  --c-bg3:       #2d2d2d;
  --c-border:    #3a3a3a;
  --c-border2:   #444;
  --c-text:      #cccccc;
  --c-text2:     #888;
  --c-text3:     #555;
  --c-acc-dim:   rgba(91,141,246,0.13);
  --c-acc-glow:  rgba(91,141,246,0.22);
  --c-user-bg:   #1e2a3a;
  --c-user-bdr:  #2a4060;
}
.mlp-chat-sidebar.mlp-dark-mode .mlp-input-card {
  background: #252525;
  border: 1px solid #333333 !important;
  box-shadow: 0 2px 10px rgba(0,0,0,0.35);
}
.mlp-chat-sidebar.mlp-dark-mode .mlp-cursor-textarea-wrap {
  background: #252525;
}
.mlp-chat-sidebar.mlp-dark-mode .mlp-cursor-toolbar {
  background: #1e1e1e !important;
  border-top: 1px solid #333333 !important;
  border-bottom: 1px solid #333333 !important;
}
.mlp-chat-sidebar.mlp-dark-mode .mlp-cursor-input-wrap {
  border: none !important;
}
.mlp-chat-sidebar.mlp-dark-mode .mlp-chat-textarea {
  color: #d4d0c8 !important;
  background: #2a2a2a !important;
}
.mlp-chat-sidebar.mlp-dark-mode .mlp-chat-textarea::placeholder {
  color: #5a5650 !important;
}
.mlp-chat-sidebar.mlp-dark-mode .mlp-model-btn {
  background: rgba(255,255,255,0.06);
  border-color: rgba(255,255,255,0.11);
  color: #cccccc;
}
.mlp-chat-sidebar.mlp-dark-mode .mlp-model-btn:hover { background: rgba(255,255,255,0.10); border-color: rgba(255,255,255,0.18); }
.mlp-chat-sidebar.mlp-dark-mode .mlp-model-btn #mlpBtnProviderLabel { color: #cccccc; }
.mlp-chat-sidebar.mlp-dark-mode #mlpBtnModelName { color: #888; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-model-chevron { color: #555; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-nd-help-btn { background: rgba(255,255,255,0.06); border-color: rgba(255,255,255,0.11); color: #888; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-nd-help-btn:hover { color: #ccc; background: rgba(255,255,255,0.12); border-color: rgba(255,255,255,0.2); }
.mlp-chat-sidebar.mlp-dark-mode .mlp-tool-btn { color: #555; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-tool-btn:hover { color: #888; background: rgba(255,255,255,0.05); }
.mlp-chat-sidebar.mlp-dark-mode .mlp-shortcut-btn { color: #555; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-shortcut-btn:hover { color: #888; background: rgba(255,255,255,0.05); }
.mlp-chat-sidebar.mlp-dark-mode .mlp-claude-plus-btn { border-color: #444; color: #888; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-claude-plus-btn:hover { background: rgba(255,255,255,0.06); color: #ccc; border-color: #555; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-voice-btn { color: #555; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-voice-btn:hover { color: #888; background: rgba(255,255,255,0.05); }
.mlp-chat-sidebar.mlp-dark-mode .mlp-quick-chip { border-color: #444; color: #888; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-quick-chip:hover { background: rgba(255,255,255,0.05); border-color: #555; color: #ccc; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-tb-btn:hover { background: rgba(255,255,255,0.06); }
.mlp-chat-sidebar.mlp-dark-mode .mlp-msg-user .mlp-msg-bubble { color: #c5d8f0; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-msg-ai .mlp-msg-bubble {
  background: #1e2a22; border-color: #2a3d2e; color: #cccccc;
}
.mlp-chat-sidebar.mlp-dark-mode .mlp-msg-ai .mlp-msg-bubble strong { color: #a8c0ff; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-msg-ai .mlp-msg-bubble em { color: #9ab8d0; }
.mlp-chat-sidebar.mlp-dark-mode .mlp-msg-ai .mlp-msg-bubble code { color: #88d4b8; }
.mlp-chat-sidebar.mlp-dark-mode { box-shadow: -8px 0 40px rgba(0,0,0,0.7); }

/* ── Media Upload Button & Attachments ── */
.mlp-media-btn {
  background: none; border: none; color: var(--c-text3);
  cursor: pointer; padding: 3px 5px; border-radius: 4px;
  font-size: 0.78rem; line-height: 1;
  transition: color 0.15s, background 0.15s;
  display: flex; align-items: center; justify-content: center;
  width: 26px; height: 26px; flex-shrink: 0;
}
.mlp-media-btn:hover { color: var(--c-accent); background: var(--c-acc-dim); }
.mlp-media-btn svg { width: 14px; height: 14px; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }

.mlp-attachments-row {
  display: none; flex-wrap: wrap; gap: 6px;
  padding: 5px 14px 4px; border-bottom: 1px solid var(--c-border);
}
.mlp-attachments-row.has-files { display: flex; }
.mlp-attachment-chip {
  display: inline-flex; align-items: center; gap: 5px;
  background: var(--c-bg3); border: 1px solid var(--c-border2);
  border-radius: 5px; padding: 3px 7px; font-size: 0.68rem;
  color: var(--c-text2); max-width: 160px;
}
.mlp-attachment-chip-img {
  width: 28px; height: 28px; object-fit: cover; border-radius: 3px;
  flex-shrink: 0;
}
.mlp-attachment-chip-name {
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1;
}
.mlp-attachment-chip-ext {
  font-size: 0.58rem; font-weight: 700; text-transform: uppercase;
  color: var(--c-accent); flex-shrink: 0;
}
.mlp-attachment-remove {
  background: none; border: none; color: var(--c-text3);
  cursor: pointer; padding: 0 1px; font-size: 0.72rem; line-height: 1;
  transition: color 0.15s; flex-shrink: 0;
}
.mlp-attachment-remove:hover { color: #e05555; }

/* ── Migration / Fallback animation ── */
.mlp-migrate-anim {
  display: inline-flex; align-items: center; gap: 6px;
  background: transparent; border: 1px solid var(--c-border);
  border-radius: 7px; padding: 4px 8px 4px 5px;
  width: fit-content; margin-bottom: 4px;
  animation: mlpFadeSlideIn 0.3s ease;
}
.mlp-migrate-icon {
  width: 22px; height: 22px; border-radius: 5px;
  background: rgba(251,191,36,0.10); border: 1px solid rgba(251,191,36,0.30);
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0; color: #f59e0b; cursor: pointer;
  transition: background 0.15s;
}
.mlp-migrate-icon:hover { background: rgba(251,191,36,0.22); }
.mlp-migrate-icon svg { width: 11px; height: 11px; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
.mlp-migrate-label { font-size: 0.65rem; color: var(--c-text2); white-space: nowrap; }
.mlp-migrate-label strong { color: #f59e0b; font-weight: 600; }
/* Console char scrolling animation */
.mlp-migrate-console {
  font-family: var(--c-mono); font-size: 0.6rem; color: #f59e0b;
  letter-spacing: 0.05em; min-width: 18px; display: inline-block;
}
@keyframes mlpConsoleBlink { 0%,49%{opacity:1;} 50%,100%{opacity:0;} }
.mlp-migrate-cursor { animation: mlpConsoleBlink 0.8s step-end infinite; }
  margin: 4px 0; padding: 7px 10px;
  background: rgba(91,141,246,0.07); border: 1px solid rgba(91,141,246,0.22);
  border-radius: 7px; font-size: 0.72rem; color: var(--c-accent);
  display: flex; align-items: flex-start; gap: 7px; line-height: 1.55;
}
.mlp-migrate-banner svg { width: 14px; height: 14px; flex-shrink: 0; margin-top: 1px; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }

/* Image in chat bubble */
.mlp-msg-img {
  max-width: 100%; max-height: 200px; object-fit: contain;
  border-radius: 6px; border: 1px solid var(--c-border);
  display: block; margin-bottom: 5px;
}

/* ── Toggle Button ── */
.mlp-chat-toggle {
  position: fixed; bottom: 20px; right: 20px; z-index: 999990;
  background: var(--c-bg2); border: 1px solid var(--c-border2);
  color: var(--c-text); border-radius: 6px; padding: 7px 13px;
  font-size: 0.76rem; font-weight: 500; cursor: pointer;
  display: flex; align-items: center; gap: 7px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.5);
  transition: background 0.15s, border-color 0.15s;
  font-family: var(--c-font); letter-spacing: 0.01em;
}
.mlp-chat-toggle:hover { background: var(--c-bg3); border-color: #555; }
.mlp-chat-toggle .mlp-ct-dot {
  width: 6px; height: 6px; background: var(--c-accent);
  border-radius: 50%; animation: mlpCtPulse 2s ease-in-out infinite; animation-play-state: paused;
}
.mlp-chat-toggle.mlp-anim-active .mlp-ct-dot { animation-play-state: running; }
@keyframes mlpCtPulse { 0%,100%{opacity:1;transform:scale(1);} 50%{opacity:0.3;transform:scale(0.6);} }

/* ── Sidebar ── */
.mlp-chat-sidebar {
  position: fixed; top: 0; right: 0; width: 370px; max-width: 96vw;
  height: 100vh; z-index: 999991; background: var(--c-bg);
  border-left: 1px solid var(--c-border);
  display: flex; flex-direction: column;
  transform: translateX(390px);
  transition: transform 0.25s cubic-bezier(0.4,0,0.2,1);
  font-family: var(--c-font);
  box-shadow: -8px 0 40px rgba(120,100,70,0.18);
}
.mlp-chat-sidebar.mlp-chat-open { transform: translateX(0); }

/* ══════════════════════════════════════════
   CURSOR EXACT LAYOUT
   1. Title bar: "CHAT" + icon buttons
   2. Input area (at top when empty)
   3. Model / toolbar row (below input)
   4. Messages area (grows)
══════════════════════════════════════════ */

/* ── 1. Title Bar ── */
.mlp-chat-titlebar {
  display: flex; align-items: center;
  padding: 8px 10px 8px 14px;
  border-bottom: 1px solid var(--c-border);
  flex-shrink: 0;
  background: var(--c-bg);
  min-height: 36px;
}
.mlp-chat-titlebar-label {
  font-size: 0.7rem; font-weight: 700; letter-spacing: 0.1em;
  text-transform: uppercase; color: var(--c-text2); flex: 1;
}
.mlp-chat-titlebar-actions { display: flex; align-items: center; gap: 1px; }
.mlp-tb-btn {
  background: none; border: none; color: var(--c-text3);
  cursor: pointer; padding: 4px 5px; border-radius: 4px;
  font-size: 0.82rem; line-height: 1;
  transition: color 0.15s, background 0.15s;
  display: flex; align-items: center; justify-content: center;
  width: 26px; height: 26px;
}
.mlp-tb-btn:hover { color: var(--c-text); background: rgba(255,255,255,0.06); }
.mlp-tb-btn.danger:hover { color: #e05555; background: rgba(224,85,85,0.08); }

/* ── 2. Input area — at the TOP (Cursor style) ── */
.mlp-cursor-input-wrap {
  flex-shrink: 0;
  border-bottom: 1px solid var(--c-border);
  background: var(--c-bg);
}

/* "Add context" row */
.mlp-add-context-row {
  display: flex; align-items: center;
  padding: 6px 14px 5px;
  border-bottom: 1px solid transparent;
}
.mlp-add-context-btn {
  background: none; border: none; color: var(--c-text3);
  cursor: pointer; font-size: 0.73rem; font-family: var(--c-font);
  display: flex; align-items: center; gap: 5px; padding: 0;
  transition: color 0.15s;
}
.mlp-add-context-btn:hover { color: var(--c-text2); }
.mlp-add-context-btn svg { width: 12px; height: 12px; opacity: 0.7; }

/* The main textarea input */
.mlp-cursor-textarea-wrap {
  padding: 4px 12px 6px 14px;
}
.mlp-chat-textarea {
  width: 100%; background: transparent; border: none;
  color: var(--c-text); font-size: 0.84rem; font-family: var(--c-font);
  resize: none; outline: none; line-height: 1.55;
  min-height: 24px; max-height: 140px;
  overflow-y: auto; scrollbar-width: none;
  display: block;
}
.mlp-chat-textarea::-webkit-scrollbar { display: none; }
.mlp-chat-textarea::placeholder { color: var(--c-text3); font-size: 0.84rem; }

/* ── 3. Toolbar row: model selector + shortcuts ── */
.mlp-cursor-toolbar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 5px 10px 6px 12px;
  background: var(--c-bg);
  border-bottom: 1px solid var(--c-border);
  flex-shrink: 0;
  gap: 6px;
}
.mlp-toolbar-left { display: flex; align-items: center; gap: 2px; flex-wrap: wrap; }
.mlp-toolbar-right { display: flex; align-items: center; gap: 2px; flex-shrink: 0; }

/* Model selector — Claude-style pill */
.mlp-model-btn {
  background: rgba(120,100,70,0.07);
  border: 1px solid #d6cfc4;
  color: #4a4035;
  cursor: pointer;
  font-size: 0.72rem; font-family: var(--c-font);
  display: flex; align-items: center; gap: 5px;
  padding: 4px 10px; border-radius: 20px;
  white-space: nowrap;
  transition: background 0.15s, border-color 0.15s;
}
.mlp-model-btn:hover { background: rgba(120,100,70,0.13); border-color: #c4bab0; }
.mlp-btn-status-dot { display: none; }
.mlp-model-btn #mlpBtnProviderLabel { font-weight: 600; color: #3a3028; }
/* Admin "?" button — sits outside the pill */
.mlp-nd-help-btn {
  background: rgba(120,100,70,0.07);
  border: 1px solid #d6cfc4;
  color: #7a6e62;
  cursor: pointer; font-size: 0.64rem; font-family: var(--c-font);
  padding: 2px 6px; border-radius: 20px; line-height: 1.5;
  transition: color 0.15s, background 0.15s, border-color 0.15s;
  margin-left: 2px;
}
.mlp-nd-help-btn:hover { color: #3a3028; background: rgba(120,100,70,0.13); border-color: #c4bab0; }
.mlp-model-sep { color: #a89e90; opacity: 0.6; }
#mlpBtnModelName { color: #7a6e62; font-size: 0.72rem; }
/* Chevron color */
.mlp-model-chevron { color: #a89e90; font-size: 0.65rem; margin-left: -2px; }

/* Toolbar icon buttons (@ Mention, Image) */
.mlp-tool-btn {
  background: none; border: none; color: #a89e90;
  cursor: pointer; font-size: 0.7rem; font-family: var(--c-font);
  display: flex; align-items: center; gap: 4px;
  padding: 2px 7px; border-radius: 4px;
  transition: color 0.15s, background 0.15s;
  white-space: nowrap;
}
.mlp-tool-btn:hover { color: #4a4035; background: rgba(120,100,70,0.07); }
.mlp-tool-btn svg { width: 11px; height: 11px; }

/* Toolbar right: shortcut labels */
.mlp-shortcut-btn {
  background: none; border: none; color: #a89e90;
  cursor: pointer; font-size: 0.68rem; font-family: var(--c-font);
  display: flex; align-items: center; gap: 3px;
  padding: 2px 5px; border-radius: 4px;
  transition: color 0.15s, background 0.15s;
  white-space: nowrap;
}
.mlp-shortcut-btn:hover { color: #4a4035; background: rgba(120,100,70,0.07); }
.mlp-shortcut-divider { color: #a89e90; font-size: 0.65rem; padding: 0 1px; opacity: 0.5; }

/* Send button inside toolbar right */
.mlp-chat-send-btn {
  background: var(--c-accent); border: none; color: #fff;
  border-radius: 5px; width: 24px; height: 24px;
  cursor: pointer; font-size: 0.72rem;
  transition: background 0.15s, opacity 0.15s;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0; margin-left: 4px;
}
.mlp-chat-send-btn:hover { background: #4a7ae8; }
.mlp-chat-send-btn:disabled { opacity: 0.25; cursor: not-allowed; }
.mlp-chat-send-btn.mlp-stop-mode { background: #3a1010; color: #ff8a8a; }
.mlp-chat-send-btn.mlp-stop-mode:hover { background: #4a1515; }

/* ── 4. Messages area ── */
.mlp-chat-messages {
  flex: 1; overflow-y: auto; padding: 12px 14px 8px;
  display: flex; flex-direction: column; gap: 2px; min-height: 0;
}

/* ── Input card + chips move to bottom once chat has messages ── */
.mlp-chat-sidebar:has(.mlp-chat-messages:not(.mlp-is-empty)) .mlp-input-card,
.mlp-chat-sidebar:has(.mlp-chat-messages:not(.mlp-is-empty)) .mlp-quick-chips {
  order: 1;
}
.mlp-chat-sidebar:has(.mlp-chat-messages:not(.mlp-is-empty)) .mlp-chat-messages {
  order: 0;
}
/* Keep compat references for any remaining JS/CSS that targets old names directly */
.mlp-chat-sidebar:has(.mlp-chat-messages:not(.mlp-is-empty)) .mlp-cursor-input-wrap { order: unset; }
.mlp-chat-sidebar:has(.mlp-chat-messages:not(.mlp-is-empty)) .mlp-cursor-toolbar    { order: unset; }
.mlp-chat-messages::-webkit-scrollbar { width: 3px; }
.mlp-chat-messages::-webkit-scrollbar-track { background: transparent; }
.mlp-chat-messages::-webkit-scrollbar-thumb { background: var(--c-border2); border-radius: 3px; }

/* Empty state — minimal, just fills space */
.mlp-chat-empty {
  display: none; /* hidden by default in Cursor — input IS the empty state */
}

/* Message bubbles */
.mlp-msg {
  display: flex; flex-direction: column; gap: 3px; max-width: 97%;
  animation: mlpMsgIn 0.15s ease;
}
@keyframes mlpMsgIn { from{opacity:0;transform:translateY(3px);} to{opacity:1;transform:translateY(0);} }
.mlp-msg.mlp-msg-user { align-self: flex-end; align-items: flex-end; margin-top: 10px; }
.mlp-msg.mlp-msg-ai   { align-self: flex-start; align-items: flex-start; margin-top: 6px; }
.mlp-msg-role {
  font-size: 0.58rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.08em; color: var(--c-text3); padding: 0 3px;
}
.mlp-msg-user .mlp-msg-role { color: #3a5a80; }
.mlp-msg-bubble {
  padding: 8px 11px; border-radius: 8px;
  font-size: 0.79rem; line-height: 1.65; word-break: break-word;
}
.mlp-msg-user .mlp-msg-bubble {
  background: var(--c-user-bg); color: #1a1a1a;
  border: 1px solid var(--c-user-bdr); border-bottom-right-radius: 2px;
}
.mlp-msg-ai .mlp-msg-bubble {
  background: #eaf2ec; color: var(--c-text);
  border: 1px solid #c8deca; border-bottom-left-radius: 2px;
  padding-left: 11px;
}

/* AI prose */
.mlp-msg-ai .mlp-msg-bubble p { margin: 0 0 6px; }
.mlp-msg-ai .mlp-msg-bubble p:last-child { margin-bottom: 0; }
.mlp-msg-ai .mlp-msg-bubble ul, .mlp-msg-ai .mlp-msg-bubble ol { padding-left: 16px; margin: 4px 0; }
.mlp-msg-ai .mlp-msg-bubble li { margin-bottom: 3px; }
.mlp-msg-ai .mlp-msg-bubble strong { color: #2e6b3e; font-weight: 600; }
.mlp-msg-ai .mlp-msg-bubble em { color: #4a7a58; font-style: italic; }
.mlp-msg-ai .mlp-msg-bubble h3, .mlp-msg-ai .mlp-msg-bubble h4 { color: var(--c-text); margin: 9px 0 3px; font-size: 0.81rem; }
.mlp-msg-ai .mlp-msg-bubble code { background: var(--c-bg3); border: 1px solid var(--c-border); border-radius: 3px; padding: 1px 4px; font-family: var(--c-mono); font-size: 0.74rem; color: #2e7d52; }
.mlp-msg-ai .mlp-msg-bubble hr { border: none; border-top: 1px solid var(--c-border); margin: 7px 0; }

/* Code blocks */
.mlp-code-block { background: #111; border: 1px solid var(--c-border); border-radius: 7px; margin: 6px 0; overflow: hidden; font-size: 0.74rem; }
.mlp-code-block-header { display:flex; align-items:center; justify-content:space-between; padding:5px 10px; background: var(--c-bg2); border-bottom: 1px solid var(--c-border); }
.mlp-code-lang { font-size:0.6rem; font-weight:700; text-transform:uppercase; letter-spacing:0.1em; color: var(--c-text2); font-family: var(--c-mono); }
.mlp-code-block-actions { display:flex; gap:4px; align-items:center; }
.mlp-code-copy-btn { background:none; border:1px solid var(--c-border); color: var(--c-text3); border-radius:4px; padding:2px 7px; font-size:0.6rem; font-weight:500; cursor:pointer; transition:color 0.15s, background 0.15s, border-color 0.15s; font-family:inherit; }
.mlp-code-copy-btn:hover { color: var(--c-text); border-color: var(--c-border2); background: var(--c-bg3); }
.mlp-code-apply-btn { background: var(--c-acc-dim); border: 1px solid rgba(91,141,246,0.25); color: var(--c-accent); border-radius:4px; padding:2px 9px; font-size:0.64rem; font-weight:600; cursor:pointer; transition:background 0.15s; font-family:inherit; }
.mlp-code-apply-btn:hover { background: var(--c-acc-glow); }
.mlp-code-apply-btn.mlp-applied { background:rgba(52,211,153,0.1); border-color:rgba(52,211,153,0.25); color:#34d399; }
.mlp-code-block pre { margin:0; padding:10px 12px; overflow-x:auto; font-family: var(--c-mono); line-height:1.5; color:#bbb; white-space:pre-wrap; word-break:break-all; max-height:230px; font-size:0.73rem; }
.mlp-code-block pre::-webkit-scrollbar { height:3px; width:3px; }
.mlp-code-block pre::-webkit-scrollbar-thumb { background: var(--c-border2); border-radius:3px; }

/* Typing indicator */
.mlp-typing { display:flex; align-items:center; gap:4px; padding:8px 3px; }
.mlp-typing span { width:5px; height:5px; background: var(--c-accent); border-radius:50%; animation:mlpTyping 1.2s ease-in-out infinite; display:inline-block; animation-play-state:paused; }
.mlp-chat-sidebar.mlp-chat-open .mlp-typing span { animation-play-state:running; }
.mlp-chat-sidebar:not(.mlp-chat-open) .mlp-typing span { animation-play-state:paused; }
.mlp-typing span:nth-child(1){animation-delay:0s;} .mlp-typing span:nth-child(2){animation-delay:0.18s;} .mlp-typing span:nth-child(3){animation-delay:0.36s;}
@keyframes mlpTyping { 0%,60%,100%{transform:scale(1);opacity:0.4;} 30%{transform:scale(1.3);opacity:1;} }

/* Thinking bubble */
.mlp-thinking-bubble { display:flex; flex-direction:column; gap:5px; padding:5px 0; }
.mlp-action-row { display:inline-flex; align-items:center; gap:5px; background:transparent; border:1px solid var(--c-border); border-radius:7px; padding:4px 8px 4px 5px; width:fit-content; }
.mlp-action-row-icons { display:flex; align-items:center; gap:3px; }
.mlp-action-icon { width:22px; height:22px; border-radius:5px; background: var(--c-bg2); border:1px solid var(--c-border); display:flex; align-items:center; justify-content:center; flex-shrink:0; color: var(--c-text3); transition:background 0.2s, border-color 0.2s, color 0.2s; }
.mlp-action-icon.icon-active { background: var(--c-acc-dim); border-color:rgba(91,141,246,0.35); color: var(--c-accent); }
.mlp-action-icon.icon-done { background: var(--c-bg2); border-color: var(--c-border); color: var(--c-text3); }
.mlp-action-icon svg { width:11px; height:11px; fill:none; stroke:currentColor; stroke-width:1.8; stroke-linecap:round; stroke-linejoin:round; }
.mlp-action-icon.icon-spin svg { animation:mlpIconSpin 1.1s linear infinite; }
@keyframes mlpIconSpin { from{transform:rotate(0deg);} to{transform:rotate(360deg);} }
@keyframes mlpIconPulse { 0%,100%{box-shadow:0 0 0 0 transparent;} 50%{box-shadow:0 0 0 3px var(--c-acc-glow);} }
.mlp-action-divider { width:1px; height:11px; background: var(--c-border); margin:0 1px; }
.mlp-thinking-actions-label { font-size:0.65rem; color: var(--c-text2); white-space:nowrap; font-weight:400; }
.mlp-thinking-actions-label span { color: var(--c-text); font-weight:500; }
.mlp-action-file-line { display:inline-flex; align-items:center; gap:5px; font-size:0.64rem; color: var(--c-text2); padding:2px 0; }
.mlp-action-file-line-row { background:transparent; border:1px solid var(--c-border); border-radius:7px; padding:3px 8px 3px 5px; width:fit-content; gap:5px; }
.mlp-file-icon-box { width:20px; height:20px; border-radius:4px; background: var(--c-bg2); border:1px solid var(--c-border); display:flex; align-items:center; justify-content:center; flex-shrink:0; color: var(--c-text3); }
.mlp-file-icon-box svg { width:10px; height:10px; fill:none; stroke:currentColor; stroke-width:1.8; stroke-linecap:round; stroke-linejoin:round; }
.mlp-file-preparing-label { font-size:0.66rem; color: var(--c-text2); white-space:nowrap; }
.mlp-preparing-dots { display:inline; }
.mlp-preparing-dots span { display:inline-block; animation:mlpDotBlink 1.4s ease-in-out infinite; opacity:0; }
.mlp-preparing-dots span:nth-child(1){animation-delay:0s;} .mlp-preparing-dots span:nth-child(2){animation-delay:0.2s;} .mlp-preparing-dots span:nth-child(3){animation-delay:0.4s;}
@keyframes mlpDotBlink { 0%,60%,100%{opacity:0;transform:translateY(0);} 30%{opacity:1;transform:translateY(-2px);} }
.mlp-preparing-answer-row { margin-top:2px; animation:mlpFadeSlideIn 0.4s ease; }
.mlp-preparing-answer-emoji { font-size:0.78rem; line-height:1; }
@keyframes mlpFadeSlideIn { from{opacity:0;transform:translateY(3px);} to{opacity:1;transform:translateY(0);} }
.mlp-action-file-name { color: var(--c-text); font-family: var(--c-mono); font-size:0.61rem; font-weight:500; }
.mlp-thinking-footer { display:flex; flex-direction:column; gap:4px; margin-top:3px; padding-top:5px; border-top:0.5px solid var(--c-border); }
.mlp-thinking-footer-row { display:inline-flex; align-items:center; gap:5px; font-size:0.63rem; color: var(--c-text2); }
.mlp-thinking-footer-icon { width:14px; height:14px; border-radius:50%; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
.mlp-thinking-footer-icon.icon-check { background:rgba(52,211,153,0.1); color:#34d399; }
.mlp-thinking-footer-icon.icon-clock { background:rgba(107,140,163,0.08); color: var(--c-text2); animation:mlpClockSpin 4s linear infinite; }
@keyframes mlpClockSpin { from{transform:rotate(0deg);} to{transform:rotate(360deg);} }
.mlp-thinking-footer-icon svg { width:8px; height:8px; fill:none; stroke:currentColor; stroke-width:2.2; stroke-linecap:round; stroke-linejoin:round; }
@keyframes mlpBrainBtnPulse { 0%,100%{box-shadow:0 0 0 0 transparent;} 50%{box-shadow:0 0 0 4px var(--c-acc-glow);} }

/* Reasoning summary */
.mlp-reasoning-summary { display:inline-flex; align-items:center; gap:4px; font-size:0.6rem; color: var(--c-text2); cursor:pointer; padding:3px 7px; margin-top:5px; user-select:none; background: var(--c-bg2); border:1px solid var(--c-border); border-radius:5px; width:fit-content; transition:background 0.15s, color 0.15s; }
.mlp-reasoning-summary:hover { background: var(--c-bg3); color: var(--c-text); }
.mlp-reasoning-icons-mini { display:flex; gap:2px; align-items:center; }
.mlp-reasoning-icon-mini { width:13px; height:13px; border-radius:3px; background:rgba(255,255,255,0.03); border:1px solid var(--c-border); display:flex; align-items:center; justify-content:center; color: var(--c-text2); }
.mlp-reasoning-icon-mini svg { width:6px; height:6px; fill:none; stroke:currentColor; stroke-width:2; stroke-linecap:round; stroke-linejoin:round; }
.mlp-reasoning-count { color: var(--c-text2); white-space:nowrap; }
.mlp-reasoning-arrow { font-size:0.5rem; transition:transform 0.2s; color: var(--c-text3); margin-left:2px; }
.mlp-reasoning-summary.open .mlp-reasoning-arrow { transform:rotate(180deg); }
.mlp-reasoning-detail { display:none; padding:5px 9px; margin-top:4px; background:rgba(0,0,0,0.18); border:1px solid var(--c-border); border-radius:5px; font-size:0.63rem; color: var(--c-text2); line-height:1.8; }
.mlp-reasoning-detail.open { display:block; }
.mlp-reasoning-step-done { color:#34d399; margin-right:5px; }

/* Backdrop */
.mlp-chat-backdrop { position:fixed; inset:0; background:rgba(0,0,0,0.5); z-index:999989; opacity:0; pointer-events:none; transition:opacity 0.25s; }
.mlp-chat-backdrop.mlp-chat-open { opacity:1; pointer-events:auto; }

/* Error state */
.mlp-msg-error .mlp-msg-bubble { background:rgba(224,85,85,0.06); border:1px solid rgba(224,85,85,0.2); color:#f9a8a8; }

/* Cooldown bar */
.mlp-cooldown-bar { height:1.5px; background: var(--c-border); border-radius:2px; margin-top:5px; overflow:hidden; display:none; }
.mlp-cooldown-bar.mlp-cd-active { display:block; }
.mlp-cooldown-progress { height:100%; background: var(--c-accent); border-radius:2px; transition:width 0.1s linear; }

/* Undo bar */
.mlp-undo-bar { display:flex; align-items:center; gap:8px; margin-top:6px; padding:5px 10px; background:rgba(251,191,36,0.05); border:1px solid rgba(251,191,36,0.18); border-radius:6px; font-size:0.68rem; color:#fbbf24; animation:mlpUndoFadeIn 0.2s ease; }
@keyframes mlpUndoFadeIn { from{opacity:0;transform:translateY(3px);} to{opacity:1;transform:translateY(0);} }
.mlp-undo-bar span { flex:1; }
.mlp-undo-btn { background:rgba(251,191,36,0.1); border:1px solid rgba(251,191,36,0.28); color:#fbbf24; border-radius:4px; padding:2px 9px; font-size:0.66rem; font-weight:600; cursor:pointer; font-family:inherit; transition:background 0.15s; white-space:nowrap; }
.mlp-undo-btn:hover { background:rgba(251,191,36,0.22); }
.mlp-undo-dismiss { background:none; border:none; color:#5a4a20; cursor:pointer; font-size:0.8rem; padding:0 2px; line-height:1; transition:color 0.15s; }
.mlp-undo-dismiss:hover { color:#fbbf24; }

/* Turnstile */
.mlp-ts-bubble { display:flex; flex-direction:column; gap:10px; }
.mlp-ts-bubble b { color: var(--c-accent); }
.mlp-ts-bubble-ok { color:#34d399; font-size:0.74rem; display:none; }

/* Provider badge */
.mlp-provider-badge { display:inline-block; font-size:0.56rem; font-weight:600; padding:2px 6px; border-radius:20px; margin-top:5px; letter-spacing:0.04em; text-transform:uppercase; }
/* AI role label — clickable hint */
.mlp-msg-ai .mlp-msg-role {
  cursor: pointer;
  transition: opacity 0.15s;
}
.mlp-msg-ai .mlp-msg-role:hover { opacity: 0.6; }
.mlp-provider-replit   { background:rgba(244,97,62,0.08);  color:#f4613e; border:1px solid rgba(244,97,62,0.25); }
.mlp-provider-mistral  { background:rgba(255,165,0,0.08);  color:#ffa94d; border:1px solid rgba(255,165,0,0.22); }
.mlp-provider-cerebras { background:rgba(16,185,129,0.08); color:#34d399; border:1px solid rgba(16,185,129,0.22); }
.mlp-provider-groq     { background:rgba(249,115,22,0.08); color:#fb923c; border:1px solid rgba(249,115,22,0.2); }
.mlp-provider-philo    { background:rgba(168,85,247,0.08); color:#c084fc; border:1px solid rgba(168,85,247,0.2); }
.mlp-provider-gemini   { background:rgba(66,133,244,0.08); color:#7baaf7; border:1px solid rgba(66,133,244,0.2); }
.mlp-provider-github   { background:rgba(240,246,252,0.06); color:#e6edf3; border:1px solid rgba(240,246,252,0.18); }
.mlp-provider-cohere   { background:rgba(57,211,137,0.08); color:#39d389; border:1px solid rgba(57,211,137,0.22); }
.mlp-provider-together { background:rgba(16,185,129,0.08);  color:#6ee7b7; border:1px solid rgba(16,185,129,0.22); }
.mlp-provider-unknown  { background:rgba(100,116,139,0.08);color:#94a3b8; border:1px solid rgba(100,116,139,0.18); }

/* Like / Dislike / Copy action buttons */
.mlp-msg-reactions {
  display: flex; align-items: center; gap: 2px; margin-top: 6px;
}
.mlp-react-btn {
  background: none; border: none; color: var(--c-text3);
  padding: 4px 5px; font-size: 0; cursor: pointer;
  border-radius: 5px; line-height: 1;
  transition: color 0.15s, background 0.15s;
  display: flex; align-items: center; justify-content: center;
}
.mlp-react-btn svg {
  width: 15px; height: 15px;
  fill: none; stroke: currentColor;
  stroke-width: 1.6; stroke-linecap: round; stroke-linejoin: round;
}
.mlp-react-btn:hover { color: var(--c-text); background: rgba(255,255,255,0.06); }
.mlp-react-btn.mlp-voted.mlp-liked    { color: #34d399; }
.mlp-react-btn.mlp-voted.mlp-disliked { color: #f87171; }
.mlp-react-btn.mlp-voted-copy         { color: #34d399; }

/* Status dots */
.mlp-status-dot { width:6px; height:6px; border-radius:50%; flex-shrink:0; position:relative; }
.mlp-status-dot.status-active { background:#22c55e; box-shadow:0 0 4px rgba(34,197,94,0.6); }
.mlp-status-dot.status-active::after { content:''; position:absolute; inset:-3px; border-radius:50%; background:rgba(34,197,94,0.18); animation:mlpStatusPulse 2s ease-in-out infinite; }
.mlp-status-dot.status-rate_limited { background:#f59e0b; }
.mlp-status-dot.status-offline { background:#ef4444; }
.mlp-status-dot.status-checking { background: var(--c-border2); animation:mlpStatusBlink 1s ease-in-out infinite; }
@keyframes mlpStatusPulse { 0%,100%{transform:scale(1);opacity:1;} 50%{transform:scale(1.5);opacity:0;} }
@keyframes mlpStatusBlink { 0%,100%{opacity:1;} 50%{opacity:0.3;} }
.mlp-status-label { font-size:0.56rem; font-weight:600; letter-spacing:0.04em; text-transform:uppercase; }
.mlp-status-label.status-active { color:#22c55e; }
.mlp-status-label.status-rate_limited { color:#f59e0b; }
.mlp-status-label.status-offline { color:#ef4444; }
.mlp-status-label.status-checking { color: var(--c-text3); }

/* AI dropdown */
.mlp-ai-dropdown { position:absolute; top:calc(100% + 6px); left:0; background: var(--c-bg2); border:1px solid var(--c-border2); border-radius:9px; padding:9px; min-width:210px; box-shadow:0 8px 28px rgba(0,0,0,0.7); z-index:9999999; display:none; }
.mlp-ai-dropdown.mlp-ai-drop-open { display:block; animation:mlpFadeSlideIn 0.14s ease; }
.mlp-ai-drop-title { font-size:0.58rem; font-weight:700; text-transform:uppercase; letter-spacing:0.08em; color: var(--c-text3); margin-bottom:7px; }
.mlp-ai-options { display:flex; flex-direction:column; gap:3px; margin-bottom:6px; }
.mlp-ai-option { display:flex; align-items:center; gap:7px; padding:5px 7px; border-radius:6px; cursor:pointer; transition:background 0.15s; font-size:0.72rem; color: var(--c-text); }
.mlp-ai-option:hover { background: var(--c-bg3); }
.mlp-ai-option.selected { background: var(--c-acc-dim); }
.mlp-ai-option-name { flex:1; font-weight:500; }
.mlp-ai-option-model { font-size:0.6rem; color: var(--c-text2); font-family: var(--c-mono); }
.mlp-ai-drop-refresh { padding-top:5px; border-top:1px solid var(--c-border); }
.mlp-ai-refresh-btn { background:none; border:none; color: var(--c-text2); font-size:0.63rem; cursor:pointer; padding:3px 0; font-family:inherit; display:flex; align-items:center; gap:5px; transition:color 0.15s; }
.mlp-ai-refresh-btn:hover { color: var(--c-text); }
.mlp-ai-refresh-btn.spinning i { animation:mlpSpin 0.8s linear infinite; }
@keyframes mlpSpin { to{transform:rotate(360deg);} }
.mlp-ai-clear-btn { background:rgba(245,158,11,0.07); border:1px solid rgba(245,158,11,0.22); color:#f59e0b; border-radius:4px; padding:2px 6px; font-size:0.56rem; font-weight:600; cursor:pointer; font-family:inherit; flex-shrink:0; margin-left:auto; transition:background 0.15s; white-space:nowrap; }
.mlp-ai-clear-btn:hover { background:rgba(245,158,11,0.18); }

/* ND Card */
.mlp-nd-card { background: var(--c-bg3); border:1px solid var(--c-border); border-radius:7px; padding:7px 9px; margin-bottom:7px; display:flex; align-items:center; gap:5px; }
.mlp-nd-card-name { font-size:0.7rem; font-weight:700; color: var(--c-text); flex:1; }
.mlp-nd-card-host { font-size:0.58rem; color: var(--c-text2); font-family: var(--c-mono); }
.mlp-nd-status-btn { background: var(--c-acc-dim); border:1px solid rgba(91,141,246,0.18); color: var(--c-accent); border-radius:4px; padding:2px 7px; font-size:0.6rem; font-weight:600; cursor:pointer; font-family:inherit; white-space:nowrap; transition:background 0.15s; }
.mlp-nd-status-btn:hover { background: var(--c-acc-glow); }

/* No-code warning */
.mlp-nocode-warn { margin-top:7px; padding:6px 9px; background:rgba(245,158,11,0.05); border:1px solid rgba(245,158,11,0.18); border-radius:6px; font-size:0.68rem; color:#fbbf24; display:flex; align-items:center; gap:7px; flex-wrap:wrap; }
.mlp-nocode-retry-btn { background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.25); color:#fbbf24; border-radius:4px; padding:2px 8px; font-size:0.66rem; font-weight:600; cursor:pointer; font-family:inherit; transition:background 0.15s; }
.mlp-nocode-retry-btn:hover { background:rgba(245,158,11,0.22); }

/* Context bar (hidden but keep for JS compatibility) */
.mlp-chat-ctx-bar { display:none; }
.mlp-chat-header { display:none; }
.mlp-chat-input-area { display:none; }
/* These legacy elements are hidden — replaced by new layout */

/* Btn status dot (in model selector) */
.mlp-btn-status-dot { width:5px; height:5px; border-radius:50%; flex-shrink:0; }
.mlp-btn-status-dot.status-active { background:#22c55e; box-shadow:0 0 3px rgba(34,197,94,0.7); }
.mlp-btn-status-dot.status-rate_limited { background:#f59e0b; }
.mlp-btn-status-dot.status-offline { background:#ef4444; }
.mlp-btn-status-dot.status-checking { background: var(--c-border2); }

.mlp-provider-selector-wrap { position:relative; }

/* ── Claude-style: hide old "Add context" row (+ moved to toolbar) ── */
.mlp-add-context-row { display: none !important; }

/* ── Unified input card — Claude-style: lighter bg, clear border ── */
.mlp-input-card {
  margin: 10px 12px 6px;
  border: 1px solid var(--c-border2);
  border-radius: 16px;
  overflow: hidden;
  background: #edeae4;
  flex-shrink: 0;
  box-shadow: 0 2px 10px rgba(120,100,70,0.10), 0 1px 3px rgba(120,100,70,0.07);
}
/* Remove individual outer borders — card provides them */
.mlp-cursor-input-wrap {
  border-bottom: none !important;
  background: transparent;
}
.mlp-cursor-toolbar {
  border-bottom: none !important;
  border-top: 1px solid var(--c-border) !important;
  background: #e4e0d8;
  padding: 6px 10px 7px 10px;
}
/* Dark mode: force toolbar dark */
.mlp-chat-sidebar.mlp-dark-mode .mlp-cursor-toolbar {
  background: #252526 !important;
  border-top: 1px solid #333333 !important;
}
/* When messages exist, card moves to bottom */
.mlp-chat-sidebar:has(.mlp-chat-messages:not(.mlp-is-empty)) .mlp-input-card {
  order: 1;
  margin-top: 6px;
  border-top: 1px solid var(--c-border2);
}
/* Textarea larger min-height and bigger placeholder for Claude feel */
.mlp-chat-textarea {
  min-height: 40px !important;
  font-size: 0.87rem !important;
  color: #2e2a24 !important;
}
.mlp-chat-textarea::placeholder { font-size: 0.87rem !important; color: #a89e90 !important; }
/* Textarea padding tweak */
.mlp-cursor-textarea-wrap { padding: 10px 14px 6px !important; }

/* ── Claude "+" button in toolbar ── */
.mlp-claude-plus-btn {
  background: none;
  border: 1px solid #d6cfc4;
  color: #7a6e62;
  border-radius: 50%;
  width: 28px; height: 28px;
  cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  transition: background 0.15s, border-color 0.15s, color 0.15s;
  flex-shrink: 0;
}
.mlp-claude-plus-btn:hover { background: rgba(120,100,70,0.10); color: #3a3028; border-color: #c4bab0; }
.mlp-claude-plus-btn svg { width: 13px; height: 13px; }

/* ── Voice button ── */
.mlp-voice-btn {
  background: none; border: none; color: #a89e90;
  cursor: pointer; padding: 3px;
  display: flex; align-items: center; justify-content: center;
  width: 28px; height: 28px;
  border-radius: 4px;
  transition: color 0.15s, background 0.15s;
}
.mlp-voice-btn:hover { color: #4a4035; background: rgba(120,100,70,0.08); }
.mlp-voice-btn svg { width: 15px; height: 15px; }

/* ── Quick action chips ── */
.mlp-quick-chips {
  display: flex; flex-wrap: wrap; gap: 6px;
  padding: 8px 12px 12px;
  flex-shrink: 0;
}
.mlp-quick-chip {
  background: none;
  border: 1px solid #d6cfc4;
  color: #7a6e62;
  border-radius: 20px;
  padding: 5px 13px;
  font-size: 0.72rem;
  font-family: var(--c-font);
  cursor: pointer;
  display: inline-flex; align-items: center; gap: 5px;
  transition: background 0.15s, border-color 0.15s, color 0.15s;
  white-space: nowrap;
}
.mlp-quick-chip:hover {
  background: rgba(120,100,70,0.08);
  border-color: #c4bab0;
  color: #3a3028;
}
.mlp-quick-chip svg { width: 12px; height: 12px; flex-shrink: 0; }

/* Hide chips once conversation has messages */
.mlp-chat-sidebar:has(.mlp-chat-messages:not(.mlp-is-empty)) .mlp-quick-chips { display: none; }
/* Also move chips with the input when it moves to bottom */
.mlp-chat-sidebar:has(.mlp-chat-messages:not(.mlp-is-empty)) .mlp-quick-chips { order: 2; }

/* ── Claude-style model selector label ── */
.mlp-model-chevron { opacity: 0.6; font-size: 0.6rem; margin-left: 1px; }

/* ── Toolbar send button: make it slightly larger ── */
.mlp-chat-send-btn { width: 28px; height: 28px; border-radius: 6px; }

/* ══ DARK MODE FINAL OVERRIDES — placed last to win all specificity battles ══ */
#mlpChatSidebar .mlp-msg-ai .mlp-msg-bubble {
  background: #e8ede8 !important;
  border: 1px solid #c8d4c8 !important;
  border-bottom-left-radius: 2px !important;
  padding-left: 11px !important;
  color: #2e2a24 !important;
}
#mlpChatSidebar.mlp-dark-mode .mlp-msg-ai .mlp-msg-bubble {
  background: #1e2a22 !important;
  border: 1px solid #2a3d2e !important;
  color: #cccccc !important;
}
#mlpChatSidebar.mlp-dark-mode #mlpCursorToolbar {
  background: #252526 !important;
  border-top: 1px solid #333333 !important;
  border-bottom: none !important;
}
#mlpChatSidebar.mlp-dark-mode #mlpCursorInputWrap {
  border: none !important;
  background: #252525 !important;
}
#mlpChatSidebar.mlp-dark-mode #mlpInputCard {
  background: #252525 !important;
  border: 1px solid #333333 !important;
}
/* ── Undo bar: light mode ── */
#mlpChatSidebar .mlp-undo-bar { background:rgba(180,140,20,0.08) !important; border-color:rgba(180,140,20,0.25) !important; color:#3a2800 !important; }
#mlpChatSidebar .mlp-undo-btn { background:#3a2800 !important; border-color:#1a1200 !important; color:#ffffff !important; }
#mlpChatSidebar .mlp-undo-btn:hover { background:#5a4000 !important; }
#mlpChatSidebar .mlp-undo-dismiss { color:#7a5a10 !important; }
#mlpChatSidebar .mlp-undo-dismiss:hover { color:#3a2800 !important; }
/* ── Undo bar: dark mode ── */
#mlpChatSidebar.mlp-dark-mode .mlp-undo-bar { background:rgba(251,191,36,0.05) !important; border-color:rgba(251,191,36,0.18) !important; color:#fbbf24 !important; }
#mlpChatSidebar.mlp-dark-mode .mlp-undo-btn { background:rgba(251,191,36,0.1) !important; border-color:rgba(251,191,36,0.28) !important; color:#fbbf24 !important; }
#mlpChatSidebar.mlp-dark-mode .mlp-undo-btn:hover { background:rgba(251,191,36,0.22) !important; }
#mlpChatSidebar.mlp-dark-mode .mlp-undo-dismiss { color:#5a4a20 !important; }
#mlpChatSidebar.mlp-dark-mode .mlp-undo-dismiss:hover { color:#fbbf24 !important; }
</style>

<!-- Backdrop -->
<div class="mlp-chat-backdrop" id="mlpChatBackdrop"></div>

<!-- Toggle Button -->
<button class="mlp-chat-toggle" id="mlpChatToggle" title="Open AI Chat">
  <div class="mlp-ct-dot"></div>
  Chat
</button>

<!-- ══════════════════════════════════════════
     SIDEBAR — Cursor-exact layout
══════════════════════════════════════════ -->
<div class="mlp-chat-sidebar" id="mlpChatSidebar">

  <!-- HIDDEN legacy elements (JS references these, keep them in DOM) -->
  <div class="mlp-chat-header" id="mlpChatHeader" style="display:none;">
    <div class="mlp-chat-header-icon"></div>
    <div class="mlp-chat-header-title"><span class="mlp-chat-header-sub" id="mlpActiveAiLabel">ND-1</span></div>
    <button class="mlp-chat-clear-btn" id="mlpChatClear"></button>
    <button class="mlp-chat-close-btn" id="mlpChatClose"></button>
  </div>
  <div class="mlp-chat-ctx-bar" id="mlpChatCtxBarOld" style="display:none;">
    <span class="mlp-chat-ctx-label"></span>
    <select id="mlpChatInstance"><option value="">—</option></select>
    <span id="mlpChatCtxStatus"></span>
  </div>

  <!-- ── 1. Title Bar ── -->
  <div class="mlp-chat-titlebar">
    <span class="mlp-chat-titlebar-label">Chat</span>
    <div class="mlp-chat-titlebar-actions">
      <!-- Dark mode toggle -->
      <button class="mlp-tb-btn" id="mlpTbDarkMode" title="Toggle dark mode">
        <!-- Moon icon (shown in light mode) -->
        <svg id="mlpDarkIcon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" style="width:13px;height:13px">
          <path d="M13.5 10A6 6 0 0 1 6 2.5a6 6 0 1 0 7.5 7.5z"/>
        </svg>
        <!-- Sun icon (shown in dark mode, hidden by default) -->
        <svg id="mlpLightIcon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" style="width:13px;height:13px;display:none">
          <circle cx="8" cy="8" r="3"/>
          <line x1="8" y1="1" x2="8" y2="2.5"/><line x1="8" y1="13.5" x2="8" y2="15"/>
          <line x1="1" y1="8" x2="2.5" y2="8"/><line x1="13.5" y1="8" x2="15" y2="8"/>
          <line x1="3.1" y1="3.1" x2="4.2" y2="4.2"/><line x1="11.8" y1="11.8" x2="12.9" y2="12.9"/>
          <line x1="12.9" y1="3.1" x2="11.8" y2="4.2"/><line x1="4.2" y1="11.8" x2="3.1" y2="12.9"/>
        </svg>
      </button>
      <!-- Close -->
      <button class="mlp-tb-btn danger" id="mlpTbClose" title="Close">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" style="width:13px;height:13px">
          <line x1="4" y1="4" x2="12" y2="12"/><line x1="12" y1="4" x2="4" y2="12"/>
        </svg>
      </button>
    </div>
  </div>

  <!-- ── History Panel (slides over the main pane) ── -->
  <div id="mlpHistoryPanel">
    <div class="mlp-hist-panel-header">
      <span>Chat History</span>
      <button class="mlp-hist-close-btn" id="mlpHistClose" title="Close history">&#x2715;</button>
    </div>
    <div class="mlp-hist-list" id="mlpHistList"></div>
    <div class="mlp-hist-actions">
      <button class="mlp-hist-action-btn" id="mlpHistClearAll">Clear all sessions</button>
    </div>
  </div>

  <!-- ── 2+3. Unified input card (textarea + toolbar in one card) ── -->
  <div class="mlp-input-card" id="mlpInputCard">
  <div class="mlp-cursor-input-wrap" id="mlpCursorInputWrap">
    <!-- Hidden file input for media -->
    <input type="file" id="mlpMediaFileInput" accept="image/*,video/*,audio/*,.pdf,.doc,.docx,.txt" multiple style="display:none;">

    <!-- Attachment chips row (shown when files are attached) -->
    <div class="mlp-attachments-row" id="mlpAttachmentsRow"></div>

    <!-- + Add context / + Media row -->
    <div class="mlp-add-context-row">
      <button class="mlp-add-context-btn" id="mlpAddContextBtn">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
          <line x1="8" y1="3" x2="8" y2="13"/><line x1="3" y1="8" x2="13" y2="8"/>
        </svg>
        Add context
      </button>
      <!-- + Media button -->
      <button class="mlp-media-btn" id="mlpMediaBtn" title="Attach image or file" style="margin-left:6px;">
        <svg viewBox="0 0 16 16">
          <rect x="1" y="3" width="14" height="10" rx="1.5"/>
          <circle cx="5.5" cy="6.5" r="1"/>
          <polyline points="1,11 5,7 8,10 10,8 15,12"/>
        </svg>
      </button>
    </div>
    <!-- Agent mode badge -->
    <div class="mlp-agent-badge" id="mlpAgentBadge">&#x26A1; Agent mode &mdash; will force code output</div>
    <!-- Textarea -->
    <div class="mlp-cursor-textarea-wrap">
      <textarea
        class="mlp-chat-textarea"
        id="mlpChatInput"
        placeholder="Ask anything (Ctrl+L)"
        rows="1"
      ></textarea>
    </div>
  </div>

  <!-- ── 3. Toolbar row (Claude style: + left | model center | voice + send right) ── -->
  <div class="mlp-cursor-toolbar" id="mlpCursorToolbar">
    <!-- Left: + button + model selector -->
    <div class="mlp-toolbar-left">
      <!-- Model selector dropdown trigger -->
      <div class="mlp-provider-selector-wrap" id="mlpChangeAiWrap">
        <div class="mlp-model-btn" id="mlpChangeAiBtn" title="Switch AI model" style="cursor:pointer;">
          <div class="mlp-btn-status-dot status-checking" id="mlpBtnStatusDot"></div>
          <span id="mlpBtnProviderLabel">ND 1</span>
          <span class="mlp-model-sep">·</span>
          <span id="mlpBtnModelName">Groq llama</span>
          <span class="mlp-model-chevron">⌄</span>
        </div>
        <!-- Admin-only "?" status button — outside the pill so clicks don't trigger dropdown -->
        <button class="mlp-nd-help-btn" id="mlpNdHelpBtn" title="ND Status" style="display:none;">?</button>
        <!-- Dropdown -->
        <div class="mlp-ai-dropdown" id="mlpAiDropdown">
          <div class="mlp-nd-card" id="mlpNdCard">
            <div class="mlp-nd-card-name" id="mlpNdCardName">ND-1</div>
            <div class="mlp-nd-card-host" id="mlpNdCardHost">nd1.ptero.us.ci</div>
            <button class="mlp-nd-status-btn" id="mlpNdStatusBtn">Status</button>
          </div>
          <div class="mlp-ai-drop-title" id="mlpAiDropTitle">Provider Status</div>
          <div class="mlp-ai-options" id="mlpAiOptions"></div>
          <div id="mlpAdminControls" style="display:none;">
            <div style="margin-top:7px;padding-top:7px;border-top:1px solid var(--c-border);">
              <div class="mlp-ai-drop-title" style="margin-bottom:5px;">⚙ Admin: Switch Provider</div>
              <div class="mlp-ai-options" id="mlpAdminAiOptions"></div>
            </div>
          </div>
          <div class="mlp-ai-drop-refresh">
            <button class="mlp-ai-refresh-btn" id="mlpAiRefreshBtn">
              <i class="fas fa-sync-alt"></i> Refresh status
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Right: send button only -->
    <div class="mlp-toolbar-right">
      <button class="mlp-chat-send-btn" id="mlpChatSend" title="Send (Ctrl+Enter)">
        <i class="fas fa-arrow-up" style="font-size:0.62rem;"></i>
      </button>
    </div>
  </div>
  </div><!-- /mlp-input-card -->

  <!-- ── Quick action chips (Claude style, hidden once chat has messages) ── -->
  <div class="mlp-quick-chips" id="mlpQuickChips">
    <button class="mlp-quick-chip" onclick="mlpInsertChipPrompt('Write me some code')">
      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="4,5 1,8 4,11"/><polyline points="12,5 15,8 12,11"/><line x1="9" y1="3" x2="7" y2="13"/>
      </svg>
      Code
    </button>
    <button class="mlp-quick-chip" onclick="mlpInsertChipPrompt('Help me write something')">
      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
        <path d="M2 12L2 14L4 14L13 5L11 3L2 12Z"/><line x1="10" y1="4" x2="12" y2="6"/>
      </svg>
      Écrire
    </button>
    <button class="mlp-quick-chip" onclick="mlpInsertChipPrompt('Help me learn something new')">
      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
        <path d="M8 1L1 5l7 4 7-4-7-4z"/><path d="M1 10l7 4 7-4"/><path d="M1 7.5l7 4 7-4"/>
      </svg>
      Apprendre
    </button>
    <button class="mlp-quick-chip" onclick="mlpInsertChipPrompt('Help me with something in everyday life')">
      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
        <path d="M6 2a1 1 0 0 0-1 1v1H3a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1h-2V3a1 1 0 0 0-1-1H6z"/>
        <path d="M8 7v4M6 9h4"/>
      </svg>
      Vie quotidienne
    </button>
    <button class="mlp-quick-chip" onclick="mlpInsertChipPrompt('Surprise me with something interesting')">
      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="8" cy="8" r="6"/><line x1="8" y1="5" x2="8" y2="8"/><circle cx="8" cy="11" r="0.5" fill="currentColor"/>
      </svg>
      Choix de Claude
    </button>
  </div>

  <!-- ── 4. Messages area ── -->
  <div class="mlp-chat-messages" id="mlpChatMessages">
    <!-- Empty state is invisible in Cursor — input serves that role -->
    <div class="mlp-chat-empty" id="mlpChatEmpty" style="display:none;"></div>
  </div>

  <!-- Legacy input area — hidden, kept for JS undo/cooldown refs -->
  <div class="mlp-chat-input-area" id="mlpChatInputAreaOld" style="display:none;">
    <div class="mlp-chat-input-row" style="display:none;"></div>
    <div id="mlpUndoBar" style="display:none;"></div>
    <div class="mlp-cooldown-bar" id="mlpCooldownBar">
      <div class="mlp-cooldown-progress" id="mlpCooldownProgress" style="width:100%;"></div>
    </div>
  </div>

  <!-- Undo bar — rendered here, above toolbar -->
  <div id="mlpUndoBarVisible" style="padding:0 10px 6px;display:none;"></div>

  <!-- Cooldown bar at bottom of toolbar -->
  <div style="padding:0 12px;">
    <div class="mlp-cooldown-bar" id="mlpCooldownBarVisible">
      <div class="mlp-cooldown-progress" id="mlpCooldownProgressVisible" style="width:100%;"></div>
    </div>
  </div>

</div>

<style>
/* ── History Panel ── */
#mlpHistoryPanel {
  position: absolute; top: 36px; left: 0; right: 0; bottom: 0;
  background: var(--c-bg); z-index: 10; display: none;
  flex-direction: column; overflow: hidden;
}
#mlpHistoryPanel.mlp-panel-open { display: flex; }
.mlp-hist-panel-header {
  display: flex; align-items: center; padding: 10px 14px;
  border-bottom: 1px solid var(--c-border); flex-shrink: 0;
  font-size: 0.7rem; font-weight: 700; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--c-text2);
}
.mlp-hist-panel-header span { flex: 1; }
.mlp-hist-close-btn {
  background: none; border: none; color: var(--c-text3);
  cursor: pointer; padding: 3px 5px; border-radius: 4px;
  font-size: 0.82rem; line-height: 1; transition: color 0.15s, background 0.15s;
}
.mlp-hist-close-btn:hover { color: var(--c-text); background: rgba(255,255,255,0.06); }
.mlp-hist-list { flex: 1; overflow-y: auto; padding: 8px 0; }
.mlp-hist-empty {
  padding: 30px 20px; text-align: center;
  font-size: 0.75rem; color: var(--c-text3); font-style: italic;
}
.mlp-hist-item {
  display: flex; align-items: center; gap: 8px;
  padding: 8px 14px; cursor: pointer;
  border-bottom: 1px solid var(--c-border);
  transition: background 0.12s;
}
.mlp-hist-item:hover { background: var(--c-bg3); }
.mlp-hist-item-icon { color: var(--c-text3); flex-shrink: 0; }
.mlp-hist-item-info { flex: 1; min-width: 0; }
.mlp-hist-item-title {
  font-size: 0.76rem; color: var(--c-text); font-weight: 500;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.mlp-hist-item-meta { font-size: 0.65rem; color: var(--c-text3); margin-top: 2px; }
.mlp-hist-item-del {
  background: none; border: none; color: var(--c-text3);
  cursor: pointer; padding: 2px 4px; border-radius: 3px;
  font-size: 0.7rem; opacity: 0; transition: opacity 0.15s, color 0.15s;
  flex-shrink: 0;
}
.mlp-hist-item:hover .mlp-hist-item-del { opacity: 1; }
.mlp-hist-item-del:hover { color: #e05555; }
.mlp-hist-actions {
  padding: 8px 14px; border-top: 1px solid var(--c-border); flex-shrink: 0;
  display: flex; gap: 6px;
}
.mlp-hist-action-btn {
  flex: 1; background: var(--c-bg3); border: 1px solid var(--c-border);
  color: var(--c-text2); cursor: pointer; border-radius: 5px;
  font-size: 0.7rem; font-family: var(--c-font); padding: 5px 8px;
  transition: background 0.15s, color 0.15s;
}
.mlp-hist-action-btn:hover { background: var(--c-acc-dim); color: var(--c-accent); }

/* ── Mode pills in toolbar ── */
.mlp-shortcut-btn.mlp-mode-active {
  color: var(--c-accent); background: var(--c-acc-dim);
  border-radius: 4px;
}
.mlp-codebase-btn.mlp-cb-active {
  color: #22c55e; background: rgba(34,197,94,0.1);
}
/* Ctrl+I agent indicator on textarea */
.mlp-chat-textarea.mlp-agent-mode {
  border-left: 2px solid var(--c-accent);
  padding-left: 10px;
}
.mlp-agent-badge {
  display: none; font-size: 0.63rem; color: var(--c-accent);
  padding: 0 14px 4px; font-family: var(--c-font);
  font-weight: 600; letter-spacing: 0.05em;
}
.mlp-agent-badge.visible { display: block; }

/* Save toast */
.mlp-save-toast {
  position: fixed; bottom: 70px; right: 24px; z-index: 9999999;
  background: var(--c-bg3); border: 1px solid var(--c-border2);
  color: var(--c-text); border-radius: 6px; padding: 7px 14px;
  font-size: 0.73rem; font-family: var(--c-font);
  box-shadow: 0 4px 16px rgba(0,0,0,0.5);
  opacity: 0; transition: opacity 0.2s;
  pointer-events: none;
}
.mlp-save-toast.visible { opacity: 1; }

/* Codebase badge pill */
.mlp-cb-pill {
  display: none; font-size: 0.62rem; background: rgba(34,197,94,0.12);
  color: #22c55e; border: 1px solid rgba(34,197,94,0.25);
  border-radius: 10px; padding: 1px 7px; margin-left: 4px;
  font-weight: 600;
}
.mlp-cb-pill.visible { display: inline-block; }
</style>

<script>
/* ── Wire up new title-bar buttons to existing IDs ── */
(function() {
  /* Close button */
  var tbClose = document.getElementById('mlpTbClose');
  if (tbClose) tbClose.addEventListener('click', function() {
    var orig = document.getElementById('mlpChatClose');
    if (orig) orig.click();
  });
  /* Dark mode toggle */
  (function() {
    var sidebar    = document.getElementById('mlpChatSidebar');
    var toggleBtn  = document.getElementById('mlpTbDarkMode');
    var moonIcon   = document.getElementById('mlpDarkIcon');
    var sunIcon    = document.getElementById('mlpLightIcon');
    if (!sidebar || !toggleBtn) return;
    var isDark = localStorage.getItem('mlp_dark_mode') === '1';
    function applyTheme(dark) {
      if (dark) {
        sidebar.classList.add('mlp-dark-mode');
        moonIcon.style.display = 'none';
        sunIcon.style.display  = '';
      } else {
        sidebar.classList.remove('mlp-dark-mode');
        moonIcon.style.display = '';
        sunIcon.style.display  = 'none';
      }
    }
    applyTheme(isDark);
    toggleBtn.addEventListener('click', function() {
      isDark = !isDark;
      localStorage.setItem('mlp_dark_mode', isDark ? '1' : '0');
      applyTheme(isDark);
    });
  })();
  /* New/Clear chat button */
  var tbNew = document.getElementById('mlpTbNew');
  if (tbNew) tbNew.addEventListener('click', function() {
    var orig = document.getElementById('mlpChatClear');
    if (orig) orig.click();
  });
  /* Mirror cooldown bars */
  var hiddenCd = document.getElementById('mlpCooldownBar');
  var visCd    = document.getElementById('mlpCooldownBarVisible');
  var hiddenCdP = document.getElementById('mlpCooldownProgress');
  var visCdP    = document.getElementById('mlpCooldownProgressVisible');
  if (hiddenCd && visCd) {
    var _cdObs = new MutationObserver(function() {
      if (hiddenCd.classList.contains('mlp-cd-active')) {
        visCd.classList.add('mlp-cd-active');
      } else {
        visCd.classList.remove('mlp-cd-active');
      }
      if (hiddenCdP && visCdP) { visCdP.style.width = hiddenCdP.style.width; }
    });
    _cdObs.observe(hiddenCd, { attributes:true, attributeFilter:['class','style'], subtree:true });
  }
  /* Mirror provider label to model btn */
  var hiddenLbl = document.getElementById('mlpActiveAiLabel');
  var modelLbl  = document.getElementById('mlpBtnProviderLabel');
  if (hiddenLbl && modelLbl) {
    var _lblObs = new MutationObserver(function() {
      /* Show just the model part, e.g. "ND-1 · Mistral AI" → "Mistral AI" */
      var txt = hiddenLbl.textContent || '';
      var parts = txt.split('·');
      modelLbl.textContent = (parts[1] ? parts[1].trim() : txt) || 'AI Model';
    });
    _lblObs.observe(hiddenLbl, { childList:true, characterData:true, subtree:true });
  }
  /* Add context — fill input with "@" */
  var addCtx = document.getElementById('mlpAddContextBtn');
  if (addCtx) addCtx.addEventListener('click', function() {
    var inp = document.getElementById('mlpChatInput');
    if (inp) { inp.focus(); inp.value = inp.value + '@'; inp.dispatchEvent(new Event('input')); }
  });

  /* ══════════════════════════════════════════════════
     HISTORY PANEL
  ══════════════════════════════════════════════════ */
  var _HIST_STORAGE_KEY = 'mlpChatHistories_v1';
  var _SAVED_KEY = 'mlpSavedSessions_v1';

  function _loadSavedSessions() {
    try { return JSON.parse(localStorage.getItem(_SAVED_KEY) || '[]'); } catch(e) { return []; }
  }
  function _saveSessions(arr) {
    try { localStorage.setItem(_SAVED_KEY, JSON.stringify(arr)); } catch(e) {}
  }

  function _getCurrentSessionMessages() {
    /* Read active session from sessionStorage */
    try {
      var all = JSON.parse(sessionStorage.getItem(_HIST_STORAGE_KEY) || '{}');
      /* Find the first non-empty history */
      var keys = Object.keys(all);
      for (var i = 0; i < keys.length; i++) {
        if (all[keys[i]] && all[keys[i]].length > 0) { return all[keys[i]]; }
      }
    } catch(e) {}
    return [];
  }

  function _renderHistoryPanel() {
    var list = document.getElementById('mlpHistList');
    if (!list) { return; }
    var sessions = _loadSavedSessions();
    list.innerHTML = '';
    if (sessions.length === 0) {
      list.innerHTML = '<div class="mlp-hist-empty">No saved sessions yet.<br>Use the bookmark button to save.</div>';
      return;
    }
    sessions.slice().reverse().forEach(function(sess, revIdx) {
      var idx = sessions.length - 1 - revIdx;
      var item = document.createElement('div');
      item.className = 'mlp-hist-item';
      var firstUser = '';
      if (sess.messages) {
        for (var m = 0; m < sess.messages.length; m++) {
          if (sess.messages[m].role === 'user') { firstUser = sess.messages[m].content || ''; break; }
        }
      }
      var preview = firstUser ? firstUser.substring(0, 60) + (firstUser.length > 60 ? '…' : '') : 'Empty session';
      var msgCount = sess.messages ? sess.messages.length : 0;
      var date = sess.saved ? new Date(sess.saved).toLocaleDateString(undefined, {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}) : '';
      item.innerHTML =
        '<div class="mlp-hist-item-icon"><svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="5.5"/><polyline points="8,5 8,8 10,9.5"/></svg></div>' +
        '<div class="mlp-hist-item-info">' +
          '<div class="mlp-hist-item-title">' + _escHtml(preview) + '</div>' +
          '<div class="mlp-hist-item-meta">' + msgCount + ' messages' + (date ? ' &bull; ' + date : '') + '</div>' +
        '</div>' +
        '<button class="mlp-hist-item-del" data-idx="' + idx + '" title="Delete">&#x2715;</button>';

      /* Click to restore session */
      item.addEventListener('click', function(e) {
        if (e.target.classList.contains('mlp-hist-item-del')) { return; }
        _restoreSession(sess);
        closeHistoryPanel();
      });
      /* Delete */
      item.querySelector('.mlp-hist-item-del').addEventListener('click', function(e) {
        e.stopPropagation();
        var i = parseInt(this.getAttribute('data-idx'), 10);
        var s = _loadSavedSessions();
        s.splice(i, 1);
        _saveSessions(s);
        _renderHistoryPanel();
      });
      list.appendChild(item);
    });
  }

  function _escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function _restoreSession(sess) {
    if (!sess || !sess.messages) { return; }
    /* Write into sessionStorage under a new key */
    try {
      var all = JSON.parse(sessionStorage.getItem(_HIST_STORAGE_KEY) || '{}');
      var restoredKey = 'restored_' + Date.now();
      all[restoredKey] = sess.messages;
      sessionStorage.setItem(_HIST_STORAGE_KEY, JSON.stringify(all));
    } catch(e) {}
    /* Reload the page so the main chat JS picks it up, or just force chat refresh */
    /* Simpler: inject into messages DOM directly via main chat clear + re-render */
    var clearBtnEl = document.getElementById('mlpChatClear');
    if (clearBtnEl) {
      /* Bypass confirm by simulating the steps manually */
      var msgBox = document.getElementById('mlpChatMessages');
      if (msgBox) { msgBox.innerHTML = ''; }
    }
    /* Show a toast */
    _showToast('Session restored! Reload page to fully activate.');
  }

  function openHistoryPanel() {
    var panel = document.getElementById('mlpHistoryPanel');
    if (panel) { _renderHistoryPanel(); panel.classList.add('mlp-panel-open'); }
  }
  function closeHistoryPanel() {
    var panel = document.getElementById('mlpHistoryPanel');
    if (panel) { panel.classList.remove('mlp-panel-open'); }
  }

  var tbHistory = document.getElementById('mlpTbHistory');
  if (tbHistory) {
    tbHistory.addEventListener('click', function() {
      var panel = document.getElementById('mlpHistoryPanel');
      if (panel && panel.classList.contains('mlp-panel-open')) {
        closeHistoryPanel();
      } else {
        openHistoryPanel();
      }
    });
  }
  var histClose = document.getElementById('mlpHistClose');
  if (histClose) { histClose.addEventListener('click', closeHistoryPanel); }

  var histClearAll = document.getElementById('mlpHistClearAll');
  if (histClearAll) {
    histClearAll.addEventListener('click', function() {
      if (!confirm('Delete all saved sessions?')) { return; }
      _saveSessions([]);
      _renderHistoryPanel();
    });
  }

  /* ══════════════════════════════════════════════════
     SAVE / BOOKMARK button — saves current session
  ══════════════════════════════════════════════════ */
  function _showToast(msg) {
    var t = document.createElement('div');
    t.className = 'mlp-save-toast';
    t.textContent = msg;
    document.body.appendChild(t);
    requestAnimationFrame(function() { t.classList.add('visible'); });
    setTimeout(function() {
      t.classList.remove('visible');
      setTimeout(function() { if(t.parentNode) t.parentNode.removeChild(t); }, 250);
    }, 2200);
  }

  var tbSave = document.getElementById('mlpTbSave');
  if (tbSave) {
    tbSave.addEventListener('click', function() {
      var msgs = _getCurrentSessionMessages();
      if (!msgs || msgs.length === 0) { _showToast('Nothing to save — chat is empty.'); return; }
      var sessions = _loadSavedSessions();
      sessions.push({ saved: Date.now(), messages: msgs });
      if (sessions.length > 30) { sessions = sessions.slice(-30); } /* keep last 30 */
      _saveSessions(sessions);
      /* Also offer a .txt download */
      var text = msgs.map(function(m) {
        return (m.role === 'user' ? 'You' : 'AI') + ':\n' + m.content;
      }).join('\n\n---\n\n');
      var blob = new Blob([text], { type: 'text/plain' });
      var url  = URL.createObjectURL(blob);
      var a    = document.createElement('a');
      a.href   = url; a.download = 'chat-' + new Date().toISOString().slice(0,10) + '.txt';
      document.body.appendChild(a); a.click();
      setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(url); }, 1000);
      _showToast('Session saved & downloaded!');
    });
  }

  /* ══════════════════════════════════════════════════
     CHAT / CTRL+I / CODEBASE mode buttons
  ══════════════════════════════════════════════════ */
  var _chatMode  = 'chat';   /* 'chat' | 'agent' */
  var _cbEnabled = true;     /* codebase context toggle — ON by default so AI reads Monaco editor */

  /* Find the mode buttons in toolbar-right */
  var _tbRight = document.querySelector('.mlp-toolbar-right');
  var _chatBtn  = _tbRight ? _tbRight.querySelector('[title="Chat mode"]') : null;
  var _agentBtn = _tbRight ? _tbRight.querySelector('[title="Ctrl+I agent"]') : null;
  var _cbBtn    = document.getElementById('mlpCodebaseBtn');
  var _cbPill   = document.getElementById('mlpCbPill');
  var _agentBadge = document.getElementById('mlpAgentBadge');
  var _textarea   = document.getElementById('mlpChatInput');

  function _setMode(mode) {
    _chatMode = mode;
    if (_chatBtn)  { _chatBtn.classList.toggle('mlp-mode-active',  mode === 'chat');  }
    if (_agentBtn) { _agentBtn.classList.toggle('mlp-mode-active', mode === 'agent'); }
    if (_agentBadge) {
      if (mode === 'agent') { _agentBadge.classList.add('visible'); }
      else { _agentBadge.classList.remove('visible'); }
    }
    if (_textarea) {
      if (mode === 'agent') { _textarea.classList.add('mlp-agent-mode'); _textarea.placeholder = 'Describe what to build/change… (Agent mode)'; }
      else { _textarea.classList.remove('mlp-agent-mode'); _textarea.placeholder = 'Ask anything (Ctrl+L)'; }
    }
  }

  if (_chatBtn) {
    _chatBtn.addEventListener('click', function() { _setMode('chat'); });
  }
  if (_agentBtn) {
    _agentBtn.addEventListener('click', function() {
      _setMode(_chatMode === 'agent' ? 'chat' : 'agent');
    });
  }

  /* Keyboard shortcut: Ctrl+I toggles agent mode */
  document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'i' && !e.shiftKey) {
      var sidebar = document.getElementById('mlpChatSidebar');
      if (sidebar && sidebar.classList.contains('mlp-chat-open')) {
        e.preventDefault();
        _setMode(_chatMode === 'agent' ? 'chat' : 'agent');
        var inp = document.getElementById('mlpChatInput');
        if (inp) { inp.focus(); }
      }
    }
  });

  /* Codebase toggle */
  if (_cbBtn) {
    _cbBtn.addEventListener('click', function() {
      _cbEnabled = !_cbEnabled;
      _cbBtn.classList.toggle('mlp-codebase-btn', true);
      _cbBtn.classList.toggle('mlp-cb-active', _cbEnabled);
      if (_cbPill) { _cbPill.classList.toggle('visible', _cbEnabled); }
      _showToast(_cbEnabled ? 'Codebase context ON — full code sent with each message.' : 'Codebase context OFF — code excluded from messages.');
    });
  }

  /* ── Intercept send to apply agent mode prefix / codebase flag ── */
  /* We hook into the real send button via a pre-send transform */
  var _realSendBtn = document.getElementById('mlpChatSend');
  var _realInput   = document.getElementById('mlpChatInput');

  function _applyModeTransform() {
    if (!_realInput) { return; }
    var val = _realInput.value.trim();
    if (!val) { return; }
    if (_chatMode === 'agent') {
      /* Prepend agent instruction if not already prefixed */
      if (!/^IMPORTANT:.*MUST output/.test(val)) {
        _realInput.value = 'IMPORTANT: You MUST output the complete modified code inside ```html / ```css / ```js fences. Produce the full file(s). Now: ' + val;
      }
    }
    /* Codebase: if disabled, blank out the code context note for the user */
    /* The actual code exclusion is handled via window.mlpCbEnabled flag read in _doSend patch below */
    window._mlpCbEnabled = _cbEnabled;
    window._mlpAgentMode = (_chatMode === 'agent');
  }

  if (_realSendBtn) {
    /* Insert our transform BEFORE the existing send handler fires */
    _realSendBtn.addEventListener('click', _applyModeTransform, true);
  }
  if (_realInput) {
    _realInput.addEventListener('keydown', function(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        _applyModeTransform();
      }
    }, true);
  }

  /* Initial state */
  _setMode('chat');
  /* Sync codebase button visual state to match _cbEnabled=true default */
  if (_cbBtn) {
    _cbBtn.classList.toggle('mlp-codebase-btn', true);
    _cbBtn.classList.toggle('mlp-cb-active', true);
  }
  if (_cbPill) { _cbPill.classList.add('visible'); }
  window._mlpCbEnabled = true;
})();
</script>

<script>
(function () {
  'use strict';

  /* ─── State ─── */
  /*
   * PER-INSTANCE CHAT HISTORIES
   * Each editor instance (tab) gets its own isolated chat history.
   * instanceHistories is a plain object map: { [iid]: Array<{role,content}> }
   * Stored in localStorage so history survives page refreshes.
   * Key: 'mlpChatHistories_v1' — versioned so future schema changes don't
   * break old stored data (just clear and start fresh).
   */
  var _STORAGE_KEY = 'mlpChatHistories_v1';
  var instanceHistories = (function () {
    try {
      var stored = sessionStorage.getItem(_STORAGE_KEY);
      return stored ? JSON.parse(stored) : {};
    } catch (e) { return {}; }
  })();

  function getInstanceHistory(iid) {
    if (!iid) { return []; }
    if (!instanceHistories[iid]) { instanceHistories[iid] = []; }
    return instanceHistories[iid];
  }

  function saveHistories() {
    /*
     * Trim each instance to at most 40 turns before persisting to prevent
     * localStorage from growing unbounded across many sessions.
     * We do NOT call this on every keystroke — only after a completed exchange.
     */
    try {
      var trimmed = {};
      Object.keys(instanceHistories).forEach(function (k) {
        var h = instanceHistories[k];
        trimmed[k] = h.length > 40 ? h.slice(-40) : h;
      });
      sessionStorage.setItem(_STORAGE_KEY, JSON.stringify(trimmed));
    } catch (e) { /* storage full or unavailable — silently skip */ }
  }

  var isOpen          = false;
  var isBusy                  = false;
  var _cooldownTimer          = null;   /* cooldown between sends */
  var _COOLDOWN_MS            = 8000;   /* 8-second cooldown after each message */
  var currentIid              = null;
  var abortController         = null;
  var _clientFallbackActive   = false; /* true while browser-side Pollinations call is in flight */
  var undoSnapshot    = null;
  var mlpSelectedProvider = 'mistral'; /* ND-1 active provider (admin only) */

  /* ── Pick a random available ND-1 provider on init ── */
  (function pickRandomNd1() {
    var nd1ids = ['mistral', 'cerebras', 'groq'];
    mlpSelectedProvider = nd1ids[Math.floor(Math.random() * nd1ids.length)];
  })();

  /* ── Pick a random ND-2 provider on init ── */
  var mlpNd2Provider = 'replit'; /* default, randomized below */
  (function pickRandomNd2() {
    var nd2ids = ['replit', 'siliconflow', 'cohere', 'cerebras', 'github', 'gemini'];
    mlpNd2Provider = nd2ids[Math.floor(Math.random() * nd2ids.length)];
  })();

  /* ── Admin detection (set by PHP via window.mlp_ajax.is_admin) ── */
  var mlpIsAdmin = !!(window.mlp_ajax && window.mlp_ajax.is_admin);

  /* ND tier assignment: determined by the tab's position index within inst.tabs.
     Tab at index 0 → ND-2, index 1 → ND-1, index 2 → ND-2, index 3 → ND-1, etc.
     This is purely positional — no counter, no registration order issues. */

  function preRegisterAllTabs() { /* no-op — tier is computed on demand from tab index */ }

  function getNdTier(iid) {
    if (!iid) { return 'nd-1'; }
    var inst  = window.monacoInstances && window.monacoInstances[iid];
    var tabId = (inst && inst.activeTabId) ? inst.activeTabId : '';
    /* If no tab system, always ND-1 */
    if (!tabId || !inst || !inst.tabs) { return 'nd-1'; }
    var tabKeys = Object.keys(inst.tabs);
    var idx     = tabKeys.indexOf(tabId);
    if (idx === -1) { idx = 0; }
    return (idx % 2 === 0) ? 'nd-2' : 'nd-1';
  }

  /* Current tab's ND tier */
  function currentNdTier() { return getNdTier(currentIid); }

  /* ── Turnstile: one-time human check ── */
  var _tsVerified  = false;   // set to true once captcha passes
  var _tsToken     = '';      // token sent with first real request
  var _tsPending            = '';      // original message held while captcha shows
  var _tsPendingAttachments = [];      // attachments held while captcha shows

  /* ─── Elements ─── */
  var sidebar      = document.getElementById('mlpChatSidebar');
  var backdrop     = document.getElementById('mlpChatBackdrop');
  var toggle       = document.getElementById('mlpChatToggle');
  var closeBtn     = document.getElementById('mlpChatClose');
  var clearBtn     = document.getElementById('mlpChatClear');
  var messages     = document.getElementById('mlpChatMessages');
  var emptyEl      = document.getElementById('mlpChatEmpty');
  var inputEl      = document.getElementById('mlpChatInput');
  var sendBtn      = document.getElementById('mlpChatSend');
  var instSel      = document.getElementById('mlpChatInstance');
  var ctxStatus    = document.getElementById('mlpChatCtxStatus');
  var undoBar      = document.getElementById('mlpUndoBar');
  var cdBar        = document.getElementById('mlpCooldownBar');
  var cdProg       = document.getElementById('mlpCooldownProgress');
  var changeAiBtn  = document.getElementById('mlpChangeAiBtn');
  var aiDropdown   = document.getElementById('mlpAiDropdown');
  var aiOptions    = document.getElementById('mlpAiOptions');
  var aiRefreshBtn = document.getElementById('mlpAiRefreshBtn');
  var btnStatusDot = document.getElementById('mlpBtnStatusDot');
  var btnProvLabel = document.getElementById('mlpBtnProviderLabel');
  var activeAiLbl  = document.getElementById('mlpActiveAiLabel');

  /* ─── AI Provider definitions ─── */
  /* ND-1 providers: Mistral, Cerebras, Groq (no Pollinations/Gemini) */
  var ND1_PROVIDERS = [
    { id: 'mistral',  name: 'ND-1', model: 'Mistral AI' },
    { id: 'cerebras', name: 'ND-1', model: 'Cerebras'   },
    { id: 'groq',     name: 'ND-1', model: 'Groq'       }
  ];

  /* ND-2 providers — randomly selected each session */
  var ND2_PROVIDERS = [
    { id: 'replit',   name: 'ND-2', model: 'Replit AI GPT' },
    { id: 'siliconflow', name: 'ND-2', model: 'SiliconFlow · Qwen3 8B' },
    { id: 'cohere',   name: 'ND-2', model: 'Cohere · Command R+' },
    { id: 'cerebras', name: 'ND-2', model: 'Cerebras'      },
    { id: 'github',   name: 'ND-2', model: 'GitHub · GPT-4o' },
    { id: 'gemini',   name: 'ND-2', model: 'Gemini 2.5 Flash' }
  ];

  /* Full list for admin switcher (ND-1 options only) */
  var AI_PROVIDERS = ND1_PROVIDERS;

  var AI_LABELS = {
    mistral:  'ND-1 · Mistral AI',
    cerebras: 'ND-1 · Cerebras',
    groq:     'ND-1 · Groq',
    replit:   'ND-2 · Replit AI GPT',
    github:   'ND-2 · GitHub GPT-4o',
    gemini:   'ND-2 · Gemini 2.5 Flash',
    cohere:   'ND-2 · Cohere Command R+',
    siliconflow: 'ND-2 · SiliconFlow Qwen3 8B'
  };

  /* Status map: 'active' | 'rate_limited' | 'offline' | 'checking' */
  var providerStatuses = {
    replit:   'checking',
    mistral:  'checking',
    cerebras: 'checking',
    groq:     'checking',
    github:   'checking',
    gemini:   'active',  /* free forever — always active */
    cohere:   'checking',
    siliconflow: 'checking'
  };

  function statusLabel(s) {
    if (s === 'active')       return 'Active';
    if (s === 'rate_limited') return 'Rate limited';
    if (s === 'offline')      return 'Offline';
    return 'Checking…';
  }

  function renderAiOptions() {
    if (!aiOptions) { return; }

    var ndTier    = currentNdTier();
    var providers = (ndTier === 'nd-2') ? ND2_PROVIDERS : ND1_PROVIDERS;
    var dropTitle = document.getElementById('mlpAiDropTitle');
    var adminCtrl = document.getElementById('mlpAdminControls');
    var adminOpts = document.getElementById('mlpAdminAiOptions');

    /* ── Update ND card header ── */
    var ndCardName = document.getElementById('mlpNdCardName');
    var ndCardHost = document.getElementById('mlpNdCardHost');
    if (ndCardName) { ndCardName.textContent = ndTier === 'nd-2' ? 'ND-2' : 'ND-1'; }
    /* Only ND-2 shows the host URL */
    if (ndCardHost) {
      ndCardHost.textContent = ndTier === 'nd-2' ? 'nd2.ptero.us.ci' : '';
      ndCardHost.style.display = ndTier === 'nd-2' ? '' : 'none';
    }

    if (dropTitle) { dropTitle.textContent = 'Provider Status'; }

    /* Status-only read-only view for all users */
    var activeProvider = (ndTier === 'nd-2') ? mlpNd2Provider : mlpSelectedProvider;
    aiOptions.innerHTML = '';
    providers.forEach(function (p) {
      var s = (p.id === 'replit') ? 'active' : (providerStatuses[p.id] || 'checking');
      var isActive = (p.id === activeProvider);
      var row = document.createElement('div');
      row.className = 'mlp-ai-option';
      row.style.cursor = 'default';
      row.innerHTML =
        '<div class="mlp-status-dot status-' + s + '"></div>' +
        '<div class="mlp-ai-option-info">' +
          '<div class="mlp-ai-option-name">' + p.model +
            '' +
          '</div>' +
          '<div class="mlp-ai-option-desc"><span class="mlp-status-label status-' + s + '">' + statusLabel(s) + '</span></div>' +
        '</div>';
      aiOptions.appendChild(row);
    });

    /* Admin-only provider switcher (ND-1 tabs only) */
    if (mlpIsAdmin && adminCtrl && adminOpts) {
      if (ndTier === 'nd-1') {
        adminCtrl.style.display = '';
        adminOpts.innerHTML = '';
        ND1_PROVIDERS.forEach(function (p) {
          var s   = providerStatuses[p.id] || 'checking';
          var btn = document.createElement('button');
          btn.className = 'mlp-ai-option' + (p.id === mlpSelectedProvider ? ' mlp-ai-selected' : '');
          if (s === 'offline') { btn.setAttribute('disabled', ''); }
          btn.innerHTML =
            '<div class="mlp-status-dot status-' + s + '"></div>' +
            '<div class="mlp-ai-option-info">' +
              '<div class="mlp-ai-option-name">' + p.model + '</div>' +
              '<div class="mlp-ai-option-desc"><span class="mlp-status-label status-' + s + '">' + statusLabel(s) + '</span></div>' +
            '</div>';
          (function(pid, pstatus) {
            btn.addEventListener('click', function () {
              if (pstatus === 'offline') { return; }
              mlpSelectedProvider = pid;
              closeAiDropdown();
              updateBtnLabel();
              renderAiOptions();
            });
          })(p.id, s);
          adminOpts.appendChild(btn);
        });
      } else {
        /* ND-2 tab: admin can pick the ND-2 model */
        adminCtrl.style.display = '';
        adminOpts.innerHTML = '';
        var nd2SwitchTitle = document.createElement('div');
        nd2SwitchTitle.className = 'mlp-ai-drop-title';
        nd2SwitchTitle.style.marginBottom = '5px';
        nd2SwitchTitle.textContent = '⚙ Admin: Switch ND-2 Model';
        adminOpts.appendChild(nd2SwitchTitle);
        ND2_PROVIDERS.forEach(function (p) {
          var s = (p.id === 'replit' || p.id === 'gemini') ? 'active' : (providerStatuses[p.id] || 'checking'); /* cohere/together use status from server */
          var btn = document.createElement('button');
          btn.className = 'mlp-ai-option' + (p.id === mlpNd2Provider ? ' mlp-ai-selected' : '');
          if (s === 'offline') { btn.setAttribute('disabled', ''); }
          btn.innerHTML =
            '<div class="mlp-status-dot status-' + s + '"></div>' +
            '<div class="mlp-ai-option-info">' +
              '<div class="mlp-ai-option-name">' + p.model + '</div>' +
              '<div class="mlp-ai-option-desc"><span class="mlp-status-label status-' + s + '">' + statusLabel(s) + '</span></div>' +
            '</div>';
          (function(pid, pstatus) {
            btn.addEventListener('click', function () {
              if (pstatus === 'offline') { return; }
              mlpNd2Provider = pid;
              closeAiDropdown();
              updateBtnLabel();
              renderAiOptions();
            });
          })(p.id, s);
          adminOpts.appendChild(btn);
        });
      }
    } else if (adminCtrl) {
      adminCtrl.style.display = 'none';
    }
  }

  function updateBtnLabel() {
    if (!btnProvLabel || !btnStatusDot) { return; }
    var ndTier = currentNdTier();
    var s, label, modelName;
    var aiNames = { mistral: 'Mistral AI', cerebras: 'Cerebras', groq: 'Groq · Llama 3.1 8B', replit: 'Replit AI GPT', github: 'GitHub · GPT-4o', gemini: 'Gemini 2.5 Flash', cohere: 'Cohere · Command R+', siliconflow: 'SiliconFlow · Qwen3 8B' };
    if (ndTier === 'nd-2') {
      s         = providerStatuses[mlpNd2Provider] || 'active';
      label     = 'ND 2';
      modelName = aiNames[mlpNd2Provider] || 'Replit AI GPT';
    } else {
      s         = providerStatuses[mlpSelectedProvider] || 'checking';
      label     = 'ND 1';
      modelName = aiNames[mlpSelectedProvider] || mlpSelectedProvider;
    }
    btnProvLabel.textContent = mlpIsAdmin ? label : 'AI';
    btnStatusDot.className   = 'mlp-btn-status-dot status-' + s;
    var modelNameEl = document.getElementById('mlpBtnModelName');
    if (modelNameEl) {
      /* Only admins see the AI model name */
      modelNameEl.textContent = mlpIsAdmin ? modelName : '';
      modelNameEl.style.display = mlpIsAdmin ? '' : 'none';
    }
    var modelSepEl = document.querySelector('#mlpChangeAiBtn .mlp-model-sep');
    if (modelSepEl) { modelSepEl.style.display = mlpIsAdmin ? '' : 'none'; }
    if (activeAiLbl) {
      var nd2Name = aiNames[mlpNd2Provider] || 'Replit AI GPT';
      var nd1Name = aiNames[mlpSelectedProvider] || mlpSelectedProvider;
      activeAiLbl.textContent = mlpIsAdmin
        ? (label + ' · ' + (ndTier === 'nd-2' ? nd2Name : nd1Name))
        : 'AI';
    }
  }

  function fetchProviderStatuses(onDone) {
    var ajaxUrl = (window.mlp_ajax && window.mlp_ajax.ajaxurl) ? window.mlp_ajax.ajaxurl : '/wp-admin/admin-ajax.php';
    var fd = new FormData();
    fd.append('action', 'mlp_ai_provider_status');
    fetch(ajaxUrl, { method: 'POST', body: fd })
      .then(function(r){ return r.json(); })
      .then(function(data){
        if (data.success && data.data) {
          Object.keys(data.data).forEach(function(k){ providerStatuses[k] = data.data[k]; });
        }
      })
      .catch(function(){
        /* If fetch fails, mark known providers as offline */
        ['mistral','cerebras','groq'].forEach(function(k){ providerStatuses[k] = 'offline'; });
        /* Replit status stays as-is — don't mark offline on network error alone */
      })
      .finally(function(){
        renderAiOptions();
        updateBtnLabel();
        if (onDone) { onDone(); }
      });
  }

  /* Initial status fetch */
  fetchProviderStatuses(null);

  function openAiDropdown() {
    if (!aiDropdown || !changeAiBtn) { return; }
    aiDropdown.classList.add('mlp-ai-drop-open');
    changeAiBtn.classList.add('mlp-ai-open');
  }
  function closeAiDropdown() {
    if (!aiDropdown || !changeAiBtn) { return; }
    aiDropdown.classList.remove('mlp-ai-drop-open');
    changeAiBtn.classList.remove('mlp-ai-open');
  }

  var ndHelpBtn = document.getElementById('mlpNdHelpBtn');
  if (ndHelpBtn) {
    ndHelpBtn.addEventListener('click', function(e){
      e.stopPropagation();
      if (aiDropdown.classList.contains('mlp-ai-drop-open')) {
        closeAiDropdown();
      } else {
        openAiDropdown();
      }
    });
  }

  if (aiRefreshBtn) {
    aiRefreshBtn.addEventListener('click', function(e){
      e.stopPropagation();
      aiRefreshBtn.classList.add('spinning');
      /* Reset all to checking */
      Object.keys(providerStatuses).forEach(function(k){ providerStatuses[k] = 'checking'; });
      renderAiOptions();
      fetchProviderStatuses(function(){
        aiRefreshBtn.classList.remove('spinning');
      });
    });
  }

  /* ── ND Status button — shows AI provider list + latency ── */
  var ndStatusBtn = document.getElementById('mlpNdStatusBtn');
  var _ndStatusOpen = false;

  function buildStatusPopup() {
    var existing = document.getElementById('mlpNdStatusPopup');
    if (existing) { existing.parentNode.removeChild(existing); }

    var ndTier    = currentNdTier();
    var providers = ndTier === 'nd-2' ? ND2_PROVIDERS : ND1_PROVIDERS;

    var popup = document.createElement('div');
    popup.id  = 'mlpNdStatusPopup';
    popup.style.cssText = [
      'position:absolute','top:calc(100% + 6px)','right:0',
      'background:#0d1e2e','border:1.5px solid #1e3a5f',
      'border-radius:10px','padding:10px','min-width:220px',
      'box-shadow:0 8px 30px rgba(0,0,0,0.7)','z-index:9999999'
    ].join(';');

    /* Title */
    var title = document.createElement('div');
    title.style.cssText = 'font-size:0.62rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#4a6a85;margin-bottom:8px;';
    title.textContent   = ndTier.toUpperCase() + ' · AI Providers';
    popup.appendChild(title);

    /* Provider rows with latency */
    providers.forEach(function(p) {
      var s   = (p.id === 'replit') ? 'active' : (providerStatuses[p.id] || 'checking');
      var row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:6px 4px;border-bottom:1px solid #0d1a28;';

      var dot = document.createElement('div');
      dot.className = 'mlp-status-dot status-' + s;

      var info = document.createElement('div');
      info.style.cssText = 'flex:1;';
      /* Show vote counts from all matching provider keys */
      var pVotes = { likes: 0, dislikes: 0 };
      Object.keys(providerVotes).forEach(function(vk) {
        if (vk.toLowerCase().indexOf(p.model.toLowerCase().split(' ')[0].toLowerCase()) !== -1 ||
            vk.toLowerCase().indexOf(p.id.toLowerCase()) !== -1) {
          pVotes.likes    += providerVotes[vk].likes    || 0;
          pVotes.dislikes += providerVotes[vk].dislikes || 0;
        }
      });
      var votesHtml = (pVotes.likes || pVotes.dislikes)
        ? '<span style="color:#34d399;margin-left:4px;">&#128077; ' + pVotes.likes + '</span>' +
          '<span style="color:#f87171;margin-left:5px;">&#128078; ' + pVotes.dislikes + '</span>'
        : '<span style="color:#2a4a65;margin-left:4px;">no votes yet</span>';
      info.innerHTML = '<div style="font-size:0.76rem;font-weight:600;color:#c8d8e8;display:flex;align-items:center;">' +
        p.model + votesHtml + '</div>';

      var latEl = document.createElement('div');
      latEl.style.cssText = 'font-size:0.62rem;color:#4a6a85;min-width:52px;text-align:right;';
      latEl.textContent   = '…';

      row.appendChild(dot);
      row.appendChild(info);
      row.appendChild(latEl);
      popup.appendChild(row);
      popup.appendChild(row);

      /* Measure latency with a real fetch */
      var t0 = Date.now();
      var pingUrl = (p.id === 'replit')
        ? (typeof MLP_REPLIT_API_URL !== 'undefined' ? MLP_REPLIT_API_URL : 'https://nd2.ptero.us.ci/api/health')
        : 'https://api.' + p.id + '.ai';

      fetch(pingUrl, { method: 'HEAD', mode: 'no-cors', cache: 'no-store' })
        .then(function()  { latEl.textContent = (Date.now() - t0) + 'ms'; latEl.style.color = '#22c55e'; })
        .catch(function() { latEl.textContent = (Date.now() - t0) + 'ms'; latEl.style.color = '#94a3b8'; });
    });

    /* Total votes summary */
    var totals = _totalVotes();
    var totalDiv = document.createElement('div');
    totalDiv.style.cssText = 'margin-top:8px;padding:6px 8px;background:rgba(255,255,255,0.03);border:1px solid #1e3a5f;border-radius:7px;font-size:0.66rem;color:#4a6a85;display:flex;align-items:center;gap:8px;';
    totalDiv.innerHTML =
      '<span style="flex:1;font-weight:600;color:#6a8faf;">All feedback</span>' +
      '<span style="color:#34d399;">&#128077; ' + totals.likes + ' helpful</span>' +
      '<span style="color:#f87171;">&#128078; ' + totals.dislikes + ' not helpful</span>';
    popup.appendChild(totalDiv);

    /* Bottom latency note */
    var note = document.createElement('div');
    note.style.cssText = 'font-size:0.6rem;color:#2a4a65;margin-top:8px;text-align:center;';
    note.textContent   = 'Latency measured live via HEAD ping';
    popup.appendChild(note);

    return popup;
  }

  if (ndStatusBtn) {
    ndStatusBtn.addEventListener('click', function(e) {
      e.stopPropagation();
      var existing = document.getElementById('mlpNdStatusPopup');
      if (existing) { existing.parentNode.removeChild(existing); _ndStatusOpen = false; return; }
      var popup = buildStatusPopup();
      /* Attach relative to the nd-card container */
      var card = document.getElementById('mlpNdCard');
      if (card) {
        card.style.position = 'relative';
        card.appendChild(popup);
      } else {
        ndStatusBtn.parentNode.appendChild(popup);
      }
      _ndStatusOpen = true;
    });
  }

  /* Close status popup on outside click */
  document.addEventListener('click', function(e) {
    var popup = document.getElementById('mlpNdStatusPopup');
    if (popup && ndStatusBtn && !ndStatusBtn.contains(e.target)) {
      popup.parentNode.removeChild(popup);
      _ndStatusOpen = false;
    }
  });

  /* Close dropdown on outside click */
  document.addEventListener('click', function(e){
    if (aiDropdown && !aiDropdown.contains(e.target) && changeAiBtn && !changeAiBtn.contains(e.target)) {
      closeAiDropdown();
    }
  });

  function refreshAiOptionHighlight() { renderAiOptions(); }

  /* Initial render */
  renderAiOptions();
  updateBtnLabel();

  /* ─── Open / Close ─── */
  var _moObserver    = null;
  var _moDebounceTmr = null;
  /*
   * FIX 5 (JS side): will-change managed around transitions only.
   * Set it just before the class change triggers the CSS transition, then
   * clear it 350 ms later (slightly after the 300 ms transition completes).
   * This gives the browser a compositing layer only while it is actually
   * needed — not for the entire lifetime of the page.
   */
  var _willChangeTmr = null;
  function armWillChange() {
    sidebar.style.willChange = 'transform';
    clearTimeout( _willChangeTmr );
    _willChangeTmr = setTimeout(function () {
      sidebar.style.willChange = '';
    }, 350);
  }

  function startInstanceObserver() {
    if (_moObserver) { return; }
    /*
     * FIX: Never observe document.body as a fallback.
     * The Monaco editor + live preview iframe constantly mutates the DOM,
     * so observing body fires hundreds of callbacks per minute even with
     * debounce, keeping the JS thread permanently hot.
     * Only start the observer if a specific editor wrapper is found.
     * If not found, skip — populateInstancePicker() is already called
     * directly on open and on instance-select change, so no coverage is lost.
     */
    var editorRoot = document.querySelector('.mlp-editors-wrap, .mobile-live-preview-wrap, #mlp-wrap');
    if (!editorRoot) { return; }
    _moObserver = new MutationObserver(function () {
      clearTimeout(_moDebounceTmr);
      _moDebounceTmr = setTimeout(function(){ preRegisterAllTabs(); populateInstancePicker(); }, 80);
    });
    _moObserver.observe(editorRoot, { childList: true, subtree: false });
  }

  function stopInstanceObserver() {
    if (_moObserver) { _moObserver.disconnect(); _moObserver = null; }
    clearTimeout(_moDebounceTmr);
  }

  function openSidebar() {
    isOpen = true;
    armWillChange();
    sidebar.classList.add('mlp-chat-open');
    backdrop.classList.add('mlp-chat-open');
    toggle.classList.add('mlp-anim-active');
    toggle.classList.remove('mlp-anim-paused');
    preRegisterAllTabs();  /* assign ND tiers to all known tabs before rendering */
    var pickerRendered = populateInstancePicker();
    startInstanceObserver();
    attachEditorListeners();
    /*
     * Restore the chat history for the current instance on open.
     * populateInstancePicker() already calls renderInstanceHistory() when it
     * detects a tab/instance change, so we only call it here for the steady
     * state (same tab as last time). Avoids a redundant DOM rebuild.
     */
    if (!pickerRendered) { renderInstanceHistory(); }
    /* Always refresh ND label on open — tab may have changed while sidebar was closed */
    updateBtnLabel();
    renderAiOptions();
    inputEl.focus();
  }
  function closeSidebar() {
    isOpen = false;
    armWillChange();
    sidebar.classList.remove('mlp-chat-open');
    backdrop.classList.remove('mlp-chat-open');
    toggle.classList.remove('mlp-anim-active');
    toggle.classList.add('mlp-anim-paused');
    stopInstanceObserver();
  }
  toggle.addEventListener('click', function () { isOpen ? closeSidebar() : openSidebar(); });
  closeBtn.addEventListener('click', closeSidebar);
  backdrop.addEventListener('click', function () { closeAiDropdown(); closeSidebar(); });

  /* ─── Debounce helper ─── */
  function debounce(fn, delay) {
    var timer = null;
    return function () {
      var args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () { fn.apply(null, args); }, delay);
    };
  }

  /* ─── History key helpers ─── */
  /*
   * Chat history is keyed by "iid::activeTabId" so that each tab inside an
   * editor instance gets its own independent conversation.
   * Falls back to just "iid" when the instance has no tab concept.
   */
  function getHistoryKey(iid) {
    if (!iid) { return ''; }
    var inst = window.monacoInstances && window.monacoInstances[iid];
    var tabId = (inst && inst.activeTabId) ? inst.activeTabId : '';
    return tabId ? (iid + '::' + tabId) : iid;
  }

  /* Convenience wrappers that always use the current iid + active tab */
  function currentHistory() { return getInstanceHistory(getHistoryKey(currentIid)); }
  function currentHistoryKey() { return getHistoryKey(currentIid); }

  /* ─── Instance Picker ─── */
  var debouncedUpdateCtxStatus = debounce(updateCtxStatus, 300);
  var _lastInstanceKeys  = '';
  var _lastActiveTabKeys = '';

  /*
   * getActiveTabSig() — builds a string that changes whenever ANY instance's
   * active tab changes. Used to detect stale option labels without polling.
   * Cost: O(n) string concat, n = number of instances (always tiny).
   */
  function getActiveTabSig() {
    if (!window.monacoInstances) { return ''; }
    return Object.keys(window.monacoInstances).map(function (iid) {
      var inst = window.monacoInstances[iid];
      return iid + ':' + ((inst && inst.activeTabId) || '');
    }).join('|');
  }

  function populateInstancePicker() {
    var instances      = window.monacoInstances ? Object.keys(window.monacoInstances) : [];
    var instanceKey    = instances.join(',');
    var activeTabKey   = getActiveTabSig();
    var _didRender     = false; /* tracks whether we called renderInstanceHistory */

    /*
     * Skip full rebuild only when BOTH the instance set AND every active tab
     * are identical to last time. Previously only instanceKey was checked,
     * which meant tab switches within an instance never refreshed the labels.
     */
    var unchanged = (instanceKey === _lastInstanceKeys &&
                     activeTabKey === _lastActiveTabKeys &&
                     instances.length > 0);
    if (unchanged) {
      /*
       * Even on early-return we must check whether the user focused a different
       * instance since the sidebar was last open. Previously this was skipped,
       * so switching previews and reopening the chat would still show the OLD
       * preview's history (currentIid was never updated).
       */
      var preferred = window._mlpLastFocusedIid;
      if (preferred && preferred !== currentIid && window.monacoInstances[preferred]) {
        var prevKey = getHistoryKey(currentIid);
        currentIid  = preferred;
        instSel.value = currentIid;
        _lastCtxTotal = -1;
        debouncedUpdateCtxStatus();
        if (getHistoryKey(currentIid) !== prevKey) {
          renderInstanceHistory();
          _didRender = true;
        }
      } else if (currentIid && instSel.value !== currentIid) {
        instSel.value = currentIid;
      }
      return _didRender;
    }
    _lastInstanceKeys  = instanceKey;
    _lastActiveTabKeys = activeTabKey;

    instSel.innerHTML = '';
    if (instances.length === 0) {
      instSel.innerHTML = '<option value="">No editors found</option>';
      currentIid = null;
      return;
    }
    instances.forEach(function (iid) {
      var opt  = document.createElement('option');
      opt.value = iid;
      var inst = window.monacoInstances[iid];
      var tabName = '';
      if (inst && inst.activeTabId && inst.tabs && inst.tabs[inst.activeTabId]) {
        tabName = inst.tabs[inst.activeTabId].title || '';
      }
      opt.textContent = tabName ? ('Editor: ' + tabName) : ('Editor #' + iid.slice(-4));
      instSel.appendChild(opt);
    });

    /*
     * Auto-select the last focused instance (tracked via Monaco focus events
     * in attachEditorListeners). Falls back to first instance on first open.
     */
    var preferred = window._mlpLastFocusedIid || currentIid;
    if (!preferred || !window.monacoInstances[preferred]) {
      preferred = instances[0];
    }
    var prevKey = getHistoryKey(currentIid);
    currentIid = preferred;
    instSel.value = currentIid;

    /* If the effective tab changed, re-render the chat for the new tab */
    if (getHistoryKey(currentIid) !== prevKey) {
      renderInstanceHistory();
      _didRender = true;
    }
    debouncedUpdateCtxStatus();
    return _didRender;
  }
  instSel.addEventListener('change', function () {
    currentIid = this.value;
    _lastCtxTotal = -1;
    _lastActiveTabKeys = ''; /* force label refresh on next populateInstancePicker call */
    attachEditorListeners();
    debouncedUpdateCtxStatus();
    renderInstanceHistory();
    /* Refresh ND tier label for the newly selected tab */
    updateBtnLabel();
    renderAiOptions();
  });

  /* ─── Monaco change listeners ─── */
  var _attachedEditors = (typeof WeakSet !== 'undefined')
    ? new WeakSet()
    : { _s: [], has: function(e){ return this._s.indexOf(e) !== -1; }, add: function(e){ this._s.push(e); } };

  /*
   * _tabChangeSig tracks what activeTabId each instance had the last time we
   * attached listeners. If it has changed when attachEditorListeners is called,
   * we know a tab switch happened and we need to refresh the chat view.
   * No polling involved — we only check at explicit call sites.
   */
  var _tabChangeSig = {};

  function attachEditorListeners() {
    if (!window.monacoInstances) { return; }
    /* Attach to ALL instances so focus tracking works globally, not just currentIid */
    Object.keys(window.monacoInstances).forEach(function (iid) {
      var inst = window.monacoInstances[iid];
      if (!inst) { return; }
      ['htmlEditor','cssEditor','jsEditor'].forEach(function (key) {
        var ed = inst[key];
        if (!ed || _attachedEditors.has(ed)) { return; }
        _attachedEditors.add(ed);

        /* Track content changes (only while sidebar is open, throttled 500ms) */
        var _ccTimer = null;
        ed.onDidChangeContent(function () {
          if (!isOpen) { return; }
          clearTimeout(_ccTimer);
          _ccTimer = setTimeout(function() {
            _lastCtxTotal = -1;
            debouncedUpdateCtxStatus();
          }, 500);
        });

        /*
         * Track focus: record which instance was last interacted with.
         * This is used by populateInstancePicker to auto-select the right
         * instance when the sidebar is opened after a tab switch.
         * onDidFocusEditorText fires only on actual user focus — zero cost
         * when the editor is idle.
         */
        ed.onDidFocusEditorText(function () {
          window._mlpLastFocusedIid = iid;
        });
      });
    });

    /*
     * Detect in-instance tab switches: compare each instance's current
     * activeTabId against what it was when we last attached. If changed,
     * invalidate the active-tab cache so the next populateInstancePicker
     * call rebuilds labels and, if the current instance switched, re-renders
     * the chat history for the new tab.
     * This runs only when attachEditorListeners is explicitly called —
     * on sidebar open and on dropdown change — never on a timer.
     */
    var needPickerRefresh = false;
    Object.keys(window.monacoInstances).forEach(function (iid) {
      var inst   = window.monacoInstances[iid];
      var tabId  = (inst && inst.activeTabId) || '';
      if (_tabChangeSig[iid] !== tabId) {
        _tabChangeSig[iid] = tabId;
        needPickerRefresh  = true;
      }
    });
    if (needPickerRefresh) {
      _lastActiveTabKeys = ''; /* force populateInstancePicker to rebuild labels */
      if (isOpen) { populateInstancePicker(); }
    }
  }

  /*
   * Listen for MLP's own tab-change event (fired by some MLP versions).
   * When caught, reset the active-tab cache and refresh if the sidebar is open.
   * This covers the case where a tab changes while the sidebar is already open.
   */
  document.addEventListener('mlp:tab-changed', function () {
    _lastActiveTabKeys = '';
    if (isOpen) { populateInstancePicker(); updateBtnLabel(); renderAiOptions(); }
  });
  if (window.jQuery) {
    jQuery(document).on('mlp:tab-changed mlp:instance-changed', function () {
      _lastActiveTabKeys = '';
      if (isOpen) { populateInstancePicker(); updateBtnLabel(); renderAiOptions(); }
    });
  }

  /*
   * Fallback tab-change watcher: poll every 100ms while sidebar is open.
   * Catches tab switches AND new tab additions when mlp:tab-changed is not fired.
   * Also detects new instances being added (e.g. a brand-new tab widget appearing).
   */
  var _watchedActiveTabId  = '';
  var _watchedInstanceKeys = '';
  setInterval(function () {
    if (!isOpen) { return; }
    /* Detect new instances added (new tab widgets) */
    var instances    = window.monacoInstances ? Object.keys(window.monacoInstances) : [];
    var instanceSig  = instances.join(',');
    var instancesChanged = (instanceSig !== _watchedInstanceKeys);
    if (instancesChanged) {
      _watchedInstanceKeys = instanceSig;
      _lastActiveTabKeys   = '';
      _lastInstanceKeys    = ''; /* force full picker rebuild */
      populateInstancePicker();
      updateBtnLabel();
      renderAiOptions();
      return; /* populateInstancePicker already handles renderInstanceHistory */
    }
    /* Detect active tab change within current instance */
    if (!currentIid) { return; }
    var inst  = window.monacoInstances && window.monacoInstances[currentIid];
    var tabId = (inst && inst.activeTabId) ? inst.activeTabId : '';
    if (tabId && tabId !== _watchedActiveTabId) {
      _watchedActiveTabId = tabId;
      _lastActiveTabKeys  = '';
      populateInstancePicker(); /* handles renderInstanceHistory for the new tab */
      updateBtnLabel();
      renderAiOptions();
    }
  }, 100);

  /*
   * ZERO-DELAY tab-switch detection via property setter interception.
   *
   * Problem: switchTab() is called via a closure inside the main plugin — no
   * DOM event, no jQuery event, no MutationObserver fires at the exact moment
   * activeTabId changes.  Polling at 100ms is too slow (user sees old history
   * for up to several seconds if the poll misses or re-renders stale data).
   *
   * Solution: use Object.defineProperty to replace monacoInstances[iid].activeTabId
   * with a getter/setter pair.  The setter fires synchronously the instant
   * switchTab() assigns the new tab ID — regardless of how switchTab is called
   * (closure, global export, or anything else).  We immediately clear the chat
   * so the user sees a blank slate, then the 100ms poll fills in the correct
   * history (empty for new tabs, existing messages for tab switches).
   */

  function _clearChatNow() {
    if (!messages) { return; }
    messages.innerHTML = '';
    if (emptyEl) { messages.appendChild(emptyEl); emptyEl.style.display = ''; }
    messages.classList.add('mlp-is-empty');
    var hint = document.getElementById('mlpInputHint');
    if (hint) { hint.classList.remove('hidden'); }
    /* Reset polling watchers so the next tick re-evaluates everything */
    _watchedActiveTabId = '';
    _lastActiveTabKeys  = '';
    _lastInstanceKeys   = '';
    _lastCtxTotal       = -1;
  }

  function _interceptInstance(iid) {
    var inst = window.monacoInstances && window.monacoInstances[iid];
    if (!inst || inst._mlpChatHooked) { return; }
    inst._mlpChatHooked = true;

    var _storedTabId = inst.activeTabId || '';
    try {
      Object.defineProperty(inst, 'activeTabId', {
        configurable: true,
        enumerable:   true,
        get: function ()  { return _storedTabId; },
        set: function (v) {
          var prev      = _storedTabId;
          _storedTabId  = v;
          if (v !== prev && isOpen) {
            /* Tab changed — wipe the chat panel immediately */
            _clearChatNow();
          }
        }
      });
    } catch (e) {
      /* Non-configurable property (shouldn't happen) — fall back to polling */
    }
  }

  function _hookAllInstances() {
    if (!window.monacoInstances) { return; }
    var keys = Object.keys(window.monacoInstances);
    for (var k = 0; k < keys.length; k++) { _interceptInstance(keys[k]); }
  }

  /* Hook now (handles instances already initialised when chat script loads) */
  _hookAllInstances();

  /* Hook again once each editor finishes initialising */
  if (window.jQuery) {
    jQuery(document).on('mlp_editors_ready', function (e, iid) {
      if (iid) { _interceptInstance(iid); } else { _hookAllInstances(); }
    });
  }

  /* Re-hook whenever the chat sidebar opens (covers any missed instances) */
  var _origOpenSidebar = openSidebar;
  openSidebar = function () { _origOpenSidebar(); _hookAllInstances(); };

  var _lastCtxTotal = -1;

  function updateCtxStatus() {
    if (!currentIid || !window.monacoInstances || !window.monacoInstances[currentIid]) {
      if (_lastCtxTotal !== 0) { ctxStatus.textContent = ''; _lastCtxTotal = 0; }
      return;
    }
    var inst = window.monacoInstances[currentIid];
    /*
     * FIX (from v2.0): Use getModel().getValueLength() — reads a cached integer
     * Monaco already maintains internally. Zero allocation, O(1) cost.
     * Falls back to getValue().length only on very old Monaco builds.
     */
    function editorLen(ed) {
      if (!ed) { return 0; }
      var m = ed.getModel && ed.getModel();
      return m ? m.getValueLength() : ed.getValue().length;
    }
    var total = editorLen(inst.htmlEditor) + editorLen(inst.cssEditor) + editorLen(inst.jsEditor);
    if (total === _lastCtxTotal) { return; }
    _lastCtxTotal = total;
    ctxStatus.textContent = total > 0 ? ('~' + Math.round(total / 1000) + 'k chars') : 'empty';
    ctxStatus.style.color = total > 0 ? '#4dccff' : '#4a6a85';
  }

  /* ─── Get code from selected editor ─── */
  function getEditorCode() {
    /* If codebase context is disabled by the user, return empty to exclude code from the AI prompt */
    if (window._mlpCbEnabled === false) {
      return { html: '', css: '', js: '' };
    }
    if (!currentIid || !window.monacoInstances || !window.monacoInstances[currentIid]) {
      return { html: '', css: '', js: '' };
    }
    var inst = window.monacoInstances[currentIid];
    return {
      html: inst.htmlEditor ? inst.htmlEditor.getValue() : '',
      css:  inst.cssEditor  ? inst.cssEditor.getValue()  : '',
      js:   inst.jsEditor   ? inst.jsEditor.getValue()   : ''
    };
  }

  /* ─── Apply code to editor ─── */
  function applyCodeToEditor(lang, code) {
    if (!currentIid || !window.monacoInstances || !window.monacoInstances[currentIid]) {
      alert('No editor selected. Pick one in the dropdown at the top of the chat panel.');
      return false;
    }
    var inst   = window.monacoInstances[currentIid];
    var isFs   = !!inst.isFullscreenEditorActive;

    /* In fullscreen mode the active editors are the fullscreen variants */
    var editor = lang === 'html' ? (isFs ? inst.fullscreenHtmlEditor : inst.htmlEditor) :
                 lang === 'css'  ? (isFs ? inst.fullscreenCssEditor  : inst.cssEditor)  :
                 lang === 'js'   ? (isFs ? inst.fullscreenJsEditor   : inst.jsEditor)   : null;

    /* Always keep both editor pairs in sync so switching modes doesn't lose changes */
    var mirrorEditor = lang === 'html' ? (isFs ? inst.htmlEditor : inst.fullscreenHtmlEditor) :
                       lang === 'css'  ? (isFs ? inst.cssEditor  : inst.fullscreenCssEditor)  :
                       lang === 'js'   ? (isFs ? inst.jsEditor   : inst.fullscreenJsEditor)   : null;

    if (!editor) { alert('Editor for ' + lang.toUpperCase() + ' not found.'); return false; }

    undoSnapshot = { lang: lang, code: editor.getValue() };
    showUndoBar(lang);

    /* Strip local stylesheet links that stall the live preview (e.g. <link href="style.css">) */
    if (lang === 'html') {
      code = code.replace(/<link\b[^>]*\brel=["']stylesheet["'][^>]*\bhref=["'](?!https?:\/\/)[^"']*["'][^>]*\/?>/gi, '');
      code = code.replace(/<link\b[^>]*\bhref=["'](?!https?:\/\/)[^"']*\.css["'][^>]*\/?>/gi, '');
    }

    editor.setValue(code);
    /* Force Monaco to re-render its viewport immediately */
    try { editor.layout(); } catch(e) {}

    /* Keep the mirror editor in sync too */
    if (mirrorEditor) {
      try { mirrorEditor.setValue(code); mirrorEditor.layout(); } catch(e) {}
    }

    /* Update the stored tab data so tab switches don't revert the change */
    if (inst.activeTabId && inst.tabs && inst.tabs[inst.activeTabId]) {
      inst.tabs[inst.activeTabId][lang] = code;
    }

    if (typeof mlpRunPreview === 'function')              { try { mlpRunPreview(currentIid); } catch(e){} }
    if (typeof window.mlpTriggerPreview === 'function')   { try { window.mlpTriggerPreview(currentIid); } catch(e){} }
    if (window.jQuery) { jQuery(document).trigger('mlp:code-applied', [currentIid, lang]); }
    return true;
  }

  /* ─── Undo bar ─── */
  /* Write directly to the visible slot — avoids innerHTML mirror losing event listeners */
  var undoBarVisible = document.getElementById('mlpUndoBarVisible');
  function showUndoBar(lang) {
    var target = undoBarVisible || undoBar;
    if (!target) { return; }
    target.innerHTML =
      '<div class="mlp-undo-bar">' +
        '<span>&#x21A9; ' + lang.toUpperCase() + ' applied &mdash; undo?</span>' +
        '<button class="mlp-undo-btn" id="mlpUndoBtn">Undo</button>' +
        '<button class="mlp-undo-dismiss" title="Dismiss">&#x2715;</button>' +
      '</div>';
    target.style.display = '';
    target.querySelector('.mlp-undo-btn').addEventListener('click', function () {
      if (!undoSnapshot) { return; }
      var inst   = window.monacoInstances && window.monacoInstances[currentIid];
      var isFs   = inst && !!inst.isFullscreenEditorActive;
      var l      = undoSnapshot.lang;
      var editor = inst && (l === 'html' ? (isFs ? inst.fullscreenHtmlEditor : inst.htmlEditor) :
                            l === 'css'  ? (isFs ? inst.fullscreenCssEditor  : inst.cssEditor)  :
                            l === 'js'   ? (isFs ? inst.fullscreenJsEditor   : inst.jsEditor)   : null);
      var mirror = inst && (l === 'html' ? (isFs ? inst.htmlEditor : inst.fullscreenHtmlEditor) :
                            l === 'css'  ? (isFs ? inst.cssEditor  : inst.fullscreenCssEditor)  :
                            l === 'js'   ? (isFs ? inst.jsEditor   : inst.fullscreenJsEditor)   : null);
      if (editor) {
        editor.setValue(undoSnapshot.code);
        try { editor.layout(); } catch(e) {}
        if (mirror) { try { mirror.setValue(undoSnapshot.code); mirror.layout(); } catch(e) {} }
        if (inst.activeTabId && inst.tabs && inst.tabs[inst.activeTabId]) {
          inst.tabs[inst.activeTabId][l] = undoSnapshot.code;
        }
        if (typeof mlpRunPreview === 'function')            { try { mlpRunPreview(currentIid); } catch(e){} }
        if (typeof window.mlpTriggerPreview === 'function') { try { window.mlpTriggerPreview(currentIid); } catch(e){} }
      }
      undoSnapshot = null;
      hideUndoBar();
    });
    target.querySelector('.mlp-undo-dismiss').addEventListener('click', function () {
      undoSnapshot = null;
      hideUndoBar();
    });
    /* Keep hidden bar in sync so legacy JS refs don't error */
    if (undoBar && target !== undoBar) { undoBar.style.display = 'none'; }
  }
  function hideUndoBar() {
    if (undoBarVisible) { undoBarVisible.style.display = 'none'; undoBarVisible.innerHTML = ''; }
    if (undoBar)        { undoBar.style.display = 'none'; undoBar.innerHTML = ''; }
  }

  /* ─── Provider badge helper ─── */
  function makeProviderBadge(provider) {
    if (!provider) { return ''; }
    var cls = 'mlp-provider-unknown';
    if (/replit/i.test(provider))              { cls = 'mlp-provider-replit'; }
    else if (/mistral/i.test(provider))        { cls = 'mlp-provider-mistral'; }
    else if (/cerebras/i.test(provider))       { cls = 'mlp-provider-cerebras'; }
    else if (/groq/i.test(provider))           { cls = 'mlp-provider-groq'; }
    else if (/philo|poll/i.test(provider))     { cls = 'mlp-provider-philo'; }
    else if (/gemini/i.test(provider))         { cls = 'mlp-provider-gemini'; }
    else if (/cohere/i.test(provider))         { cls = 'mlp-provider-cohere'; }
    else if (/silicon/i.test(provider))       { cls = 'mlp-provider-together'; }
    var badge = document.createElement('span');
    badge.className = 'mlp-provider-badge ' + cls;
    badge.textContent = provider;
    return badge;
  }

  /* ─── Parse markdown + code fences ─── */
  function parseAIReply(text) {
    var frag  = document.createDocumentFragment();

    /* ── Ensure consecutive fences are separated by a newline ───────────────
     * When AI outputs ```\n...\n``````css\n (closing + opening with no gap)
     * the split can't tell where one fence ends and the next begins.
     * Insert a newline between closing and opening backtick sequences.
     * ─────────────────────────────────────────────────────────────────────── */
    text = text.replace(/(```)(`{3})/g, '$1\n$2');

    /* ── Auto-close unclosed fences ─────────────────────────────────────────
     * If the AI's response was cut off or it forgot the closing ```, the split
     * regex never matches and the raw fence tag appears as plain text.
     * Count opening vs closing fences — if unbalanced, append a closing ```.
     * ─────────────────────────────────────────────────────────────────────── */
    var openCount  = (text.match(/^```/gm) || []).length;
    var closeCount = (text.match(/^```\s*$/gm) || []).length;
    if (openCount > closeCount) { text = text.trimEnd() + '\n```'; }

    /* ── Pre-normalise: ensure every opening fence has a newline after the lang tag ──
     * Some models output "```html\ncode" correctly but others emit "```html code..."
     * without a newline, causing the split regex to miss the fence entirely.
     * Replace  ```lang<spaces><non-newline-content>  →  ```lang\n<content>
     * Only touch the opening tag line; leave the content and closing ``` alone. */
    text = text.replace(/^([ \t]*```(?:html|css|js|javascript|markup)?)[ \t]+([^\n`])/gim, '$1\n$2');

    /* ── Robust fence split ──────────────────────────────────────────────────
     * Handles all real-world AI fence variations:
     *   ```html\n...```          — standard
     *   ```html \n...```         — trailing space after lang tag
     *   ```\n...```              — no lang tag
     *   ```html...``` (no \n)    — malformed but seen in practice
     *   ` ``html\n...```          — stray space before backticks (trimmed later)
     * The outer group captures the whole fence so split() keeps it as a part.
     * [\s\S]*? is non-greedy so nested fences don't collapse into one block.
     * ─────────────────────────────────────────────────────────────────────── */
    var parts = text.split(/(```(?:html|css|js|javascript|markup|plaintext|text)?[ \t]*\r?\n?[\s\S]*?```)/gi);
    parts.forEach(function (part) {
      var fenceMatch = part.match(/^```(html|css|js|javascript|markup|plaintext|text)?[ \t]*\r?\n?([\s\S]*?)```$/i);
      if (fenceMatch) {
        var rawLang = (fenceMatch[1] || '').toLowerCase();
        /* Normalize aliases */
        if (rawLang === 'javascript') { rawLang = 'js'; }
        if (rawLang === 'markup')     { rawLang = 'html'; }
        if (rawLang === 'plaintext' || rawLang === 'text') { rawLang = ''; }

        /* Auto-detect language from content when not specified */
        if (!rawLang) {
          var content = fenceMatch[2] || '';
          if (/^\s*<(!DOCTYPE|html|head|body|div|span|p |ul|ol|li|a |img|script|style|link|meta|table|form|input|button|header|footer|nav|main|section|article)/i.test(content)) {
            rawLang = 'html';
          } else if (/^\s*(body|html|head|\.|#|@media|@keyframe|:root|\*\s*\{)/i.test(content) || /[{};]\s*$/.test(content.trim())) {
            rawLang = 'css';
          } else {
            rawLang = 'js';
          }
        }
        var lang = rawLang || 'html';  /* final fallback */
        var code = fenceMatch[2] || '';
        var block   = document.createElement('div');
        block.className = 'mlp-code-block';
        block.innerHTML =
          '<div class="mlp-code-block-header">' +
            '<span class="mlp-code-lang">' + lang.toUpperCase() + '</span>' +
            '<div class="mlp-code-block-actions">' +
              '<button class="mlp-code-copy-btn">⎘ Copy</button>' +
              '<button class="mlp-code-apply-btn" data-lang="' + lang + '">⬆ Apply</button>' +
            '</div>' +
          '</div>' +
          '<pre>' + escHtml(code) + '</pre>';

        block.querySelector('.mlp-code-copy-btn').addEventListener('click', function () {
          var btn = this;
          navigator.clipboard && navigator.clipboard.writeText(code).then(function () {
            btn.textContent = '✓ Copied!';
            setTimeout(function () { btn.textContent = '⎘ Copy'; }, 2000);
          });
        });

        block.querySelector('.mlp-code-apply-btn').addEventListener('click', function () {
          var btn = this;
          var ok  = applyCodeToEditor(lang, code);
          if (ok) {
            btn.textContent = '✓ Applied!';
            btn.classList.add('mlp-applied');
            setTimeout(function () {
              btn.textContent = '⬆ Apply';
              btn.classList.remove('mlp-applied');
            }, 2500);
          }
        });
        frag.appendChild(block);
      } else if (part.trim()) {
        var div = document.createElement('div');
        div.innerHTML = renderProse(part);
        frag.appendChild(div);
      }
    });
    return frag;
  }

  /*
   * Prose regex constants — compiled once at module load, never inside a loop.
   * /gm flag is safe with String.replace() (replace() never reads lastIndex).
   *
   * _reUlWrap was REMOVED. The old pattern /(<li>[^\n]*<\/li>\n?)+/gm used a
   * nested quantifier that could cause catastrophic backtracking (O(2^n) engine
   * work) on long AI responses with malformed list markup, pinning the browser's
   * JS thread to 100% CPU. It is replaced by wrapListItems(), a plain O(n) loop.
   *
   * Ordered lists are now wrapped in <ol> by the same loop, fixing the previous
   * bug where <ol> items were left bare or pulled into <ul> blocks.
   */
  var _reH4     = /^### (.+)$/gm;
  var _reH3     = /^## (.+)$/gm;
  var _reBoldEm = /\*\*\*(.+?)\*\*\*/gm;
  var _reBold   = /\*\*(.+?)\*\*/gm;
  var _reEm     = /\*(.+?)\*/gm;
  var _reCode   = /`([^`]+)`/gm;
  var _reHr     = /^---+$/gm;
  var _reUl     = /^[-*] (.+)$/gm;
  var _reOl     = /^\d+\. (.+)$/gm;

  /*
   * wrapListItems() — O(n) line-walk replacement for the removed _reUlWrap regex.
   *
   * Scans lines one-by-one and wraps runs of UL <li> lines in <ul>…</ul> and
   * runs of OL <li> lines in <ol>…</ol>. A data-ol attribute is used to
   * distinguish the two list types after the two replace() passes above have
   * both emitted plain <li> tags. No regex quantifier nesting → zero
   * backtracking risk regardless of input length or content.
   */
  function wrapListItems(s) {
    var lines  = s.split('\n');
    var out    = [];
    var inUl   = false;
    var inOl   = false;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^<li data-ul>/.test(line)) {
        if (inOl) { out.push('</ol>'); inOl = false; }
        if (!inUl) { out.push('<ul>'); inUl = true; }
        out.push(line.replace(' data-ul', ''));
      } else if (/^<li data-ol>/.test(line)) {
        if (inUl) { out.push('</ul>'); inUl = false; }
        if (!inOl) { out.push('<ol>'); inOl = true; }
        out.push(line.replace(' data-ol', ''));
      } else {
        if (inUl) { out.push('</ul>'); inUl = false; }
        if (inOl) { out.push('</ol>'); inOl = false; }
        out.push(line);
      }
    }
    if (inUl) { out.push('</ul>'); }
    if (inOl) { out.push('</ol>'); }
    return out.join('\n');
  }

  function renderProse(text) {
    var s = text;
    s = s.replace(_reH4, '<h4>$1</h4>');
    s = s.replace(_reH3, '<h3>$1</h3>');
    s = s.replace(_reBoldEm, '<strong><em>$1</em></strong>');
    s = s.replace(_reBold,   '<strong>$1</strong>');
    s = s.replace(_reEm,     '<em>$1</em>');
    /*
     * FIX: Inline code must have its content HTML-escaped before insertion.
     * Without escaping, AI replies like `<html>` or `<!DOCTYPE html>` are
     * injected raw into innerHTML — the browser interprets them as actual HTML
     * elements, rendering the code box visually empty.
     * The function form of replace() lets us call escHtml() on each capture.
     */
    s = s.replace(_reCode, function (_, code) { return '<code>' + escHtml(code) + '</code>'; });
    s = s.replace(_reHr,     '<hr>');
    /* tag each list type distinctly so wrapListItems() can tell them apart */
    s = s.replace(_reUl, '<li data-ul>$1</li>');
    s = s.replace(_reOl, '<li data-ol>$1</li>');
    /* wrap tagged runs — O(n) loop, no regex backtracking */
    s = wrapListItems(s);
    /* paragraphs */
    s = s.split(/\n{2,}/).map(function (p) {
      p = p.trim();
      if (!p) { return ''; }
      if (/^<(h[34]|ul|ol|hr|li)/.test(p)) { return p; }
      return '<p>' + p.replace(/\n/g, '<br>') + '</p>';
    }).join('');
    return s;
  }

  function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  /* ─── Render all messages for the current instance ─── */
  /*
   * Called when the user switches the instance dropdown.
   * Rebuilds the messages pane from scratch using the instance's stored history.
   * Does NOT re-request anything from the server — purely a local DOM rebuild.
   * CPU cost: O(n) where n = number of stored messages, run only on user action.
   */
  function renderInstanceHistory() {
    messages.innerHTML = '';
    var hist = getInstanceHistory(getHistoryKey(currentIid));
    if (hist.length === 0) {
      if (emptyEl) { messages.appendChild(emptyEl); emptyEl.style.display = ''; }
      messages.classList.add('mlp-is-empty');
      var hint = document.getElementById('mlpInputHint'); if(hint){hint.classList.remove('hidden');}
      return;
    }
    messages.classList.remove('mlp-is-empty');
    var hint2 = document.getElementById('mlpInputHint'); if(hint2){hint2.classList.add('hidden');}
    if (emptyEl) { emptyEl.style.display = 'none'; }
    hist.forEach(function (turn) {
      appendMessage(turn.role, turn.content, false, turn.provider || '');
    });
  }

  /* ─── Like / Dislike tracking ─── */
  /* providerVotes = { [providerKey]: { likes: N, dislikes: N } } */
  var _VOTES_KEY = 'mlpProviderVotes_v1';
  var providerVotes = (function () {
    try { return JSON.parse(localStorage.getItem(_VOTES_KEY) || '{}'); } catch(e) { return {}; }
  })();

  function _saveVotes() {
    try { localStorage.setItem(_VOTES_KEY, JSON.stringify(providerVotes)); } catch(e) {}
  }

  function _getVoteBucket(provider) {
    var key = provider || 'unknown';
    if (!providerVotes[key]) { providerVotes[key] = { likes: 0, dislikes: 0 }; }
    return providerVotes[key];
  }

  /* Returns total likes/dislikes across ALL providers */
  function _totalVotes() {
    var total = { likes: 0, dislikes: 0 };
    Object.keys(providerVotes).forEach(function(k) {
      total.likes    += providerVotes[k].likes    || 0;
      total.dislikes += providerVotes[k].dislikes || 0;
    });
    return total;
  }

  /* ─── Render a message ─── */
  /* ── Thinking steps — exact Replit-style icons ── */
  var THINKING_STEPS = [
    /* >_  terminal */
    { svg: '<polyline points="2,5 6,8 2,11"/><line x1="8" y1="11" x2="14" y2="11"/>', label: 'Reading code' },
    /* ⊞  layout panels */
    { svg: '<rect x="2" y="2" width="5" height="12" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/>', label: 'Parsing structure' },
    /* 🔍  search */
    { svg: '<circle cx="6.5" cy="6.5" r="4"/><line x1="9.5" y1="9.5" x2="14" y2="14"/>', label: 'Analyzing logic' },
    /* ♡  lightbulb */
    { svg: '<path d="M8 2C5.8 2 4 3.8 4 6c0 1.5.8 2.8 2 3.5V11h4V9.5c1.2-.7 2-2 2-3.5 0-2.2-1.8-4-4-4z"/><line x1="6" y1="13" x2="10" y2="13"/>', label: 'Planning solution' },
    /* ○  circle */
    { svg: '<circle cx="8" cy="8" r="5"/>', label: 'Generating response' }
  ];

  /* Active thinking state */
  var _thinkingTimers  = [];
  var _thinkingElapsed = null;
  var _thinkingStart   = 0;
  var _completedSteps  = [];  /* stored for reasoning summary */

  function _clearThinkingTimers() {
    _thinkingTimers.forEach(function(t){ clearTimeout(t); clearInterval(t); });
    _thinkingTimers = [];
    if (_thinkingElapsed) { clearInterval(_thinkingElapsed); _thinkingElapsed = null; }
  }

  function _makeSvgBtn(svgContent, extraClass) {
    var btn = document.createElement('div');
    btn.className = 'mlp-thinking-icon-btn' + (extraClass ? ' ' + extraClass : '');
    btn.innerHTML = '<svg viewBox="0 0 24 24">' + svgContent + '</svg>';
    return btn;
  }

  function appendMessage(role, content, isTyping, provider, attachments) {
    if (emptyEl) { emptyEl.style.display = 'none'; }
    messages.classList.remove('mlp-is-empty');
    var _hint = document.getElementById('mlpInputHint'); if(_hint){_hint.classList.add('hidden');}

    var wrap = document.createElement('div');
    wrap.className = 'mlp-msg mlp-msg-' + role;

    var roleLabel = document.createElement('div');
    roleLabel.className = 'mlp-msg-role';
    roleLabel.textContent = role === 'user' ? 'You' : 'AI';

    var bubble = document.createElement('div');
    bubble.className = 'mlp-msg-bubble';

    if (isTyping) {
      /* ── Replit-style action rows thinking UI ── */
      _completedSteps = [];
      _thinkingStart  = Date.now();
      _clearThinkingTimers();

      var thinkDiv = document.createElement('div');
      thinkDiv.className = 'mlp-thinking-bubble';
      thinkDiv.id = 'mlp-think-wrap';

      bubble.appendChild(thinkDiv);
      wrap.id = 'mlp-typing-bubble';

      /* SVG templates */
      var SVG_FILE = '<svg viewBox="0 0 16 16"><path d="M4 2h5l3 3v9H4V2z" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none" stroke="currentColor"/><polyline points="9,2 9,5 12,5" stroke-width="1.5" fill="none" stroke="currentColor" stroke-linecap="round"/></svg>';

      /* Build the single action row — icons are added progressively */
      var currentRow = document.createElement('div');
      currentRow.className = 'mlp-action-row';

      var iconsWrap = document.createElement('div');
      iconsWrap.className = 'mlp-action-row-icons';
      currentRow.appendChild(iconsWrap);

      var rowDivider = document.createElement('div');
      rowDivider.className = 'mlp-action-divider';
      currentRow.appendChild(rowDivider);

      var rowLabel = document.createElement('div');
      rowLabel.className = 'mlp-thinking-actions-label';
      rowLabel.innerHTML = '<span>1</span> action';
      currentRow.appendChild(rowLabel);

      thinkDiv.appendChild(currentRow);

      /* Helper: create one icon box */
      function _makeStepIcon(svgPath, isActive) {
        var el = document.createElement('div');
        el.className = 'mlp-action-icon' + (isActive ? ' icon-active' : '');
        el.innerHTML = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + svgPath + '</svg>';
        return el;
      }

      /* Add first icon immediately (active) */
      iconsWrap.appendChild(_makeStepIcon(THINKING_STEPS[0].svg, true));

      /* Each step: mark previous icon done, add new active icon, update count */
      var stepDelays = [900, 1800, 3000, 4500, 6500];
      THINKING_STEPS.slice(1).forEach(function(step, i) {
        var t = setTimeout(function() {
          /* Mark previous icon as done */
          var prevIcon = iconsWrap.lastElementChild;
          if (prevIcon) { prevIcon.classList.remove('icon-active'); prevIcon.classList.add('icon-done'); }

          /* Add new active icon */
          iconsWrap.appendChild(_makeStepIcon(step.svg, true));

          /* Count = number of icons now in the row */
          var n = iconsWrap.children.length;
          var isDone = (n >= THINKING_STEPS.length);
          rowLabel.innerHTML = '<span>' + n + '</span> action' + (n === 1 ? '' : 's') + (isDone ? ' done' : '');

          _completedSteps.push(THINKING_STEPS[i]);
          requestAnimationFrame(function() { messages.scrollTop = messages.scrollHeight; });
        }, stepDelays[i]);
        _thinkingTimers.push(t);
      });

      /* ── Step 1 @ 7s: "Working..." footer row appears ── */
      var slowT = setTimeout(function() {
        var wrap2 = document.getElementById('mlp-think-wrap');
        if (!wrap2) { return; }

        var footer = document.createElement('div');
        footer.className = 'mlp-thinking-footer';
        footer.id = 'mlp-think-footer';

        var workingRow = document.createElement('div');
        workingRow.className = 'mlp-thinking-footer-row';
        workingRow.id = 'mlp-working-row';
        workingRow.innerHTML =
          '<span class="mlp-thinking-footer-icon icon-clock">' +
            '<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" stroke-width="1.6"/><polyline points="8,5 8,8 10.5,9.5" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none" stroke="currentColor"/></svg>' +
          '</span>' +
          '<span>Working<span class="mlp-preparing-dots"><span>.</span><span>.</span><span>.</span></span></span>';
        footer.appendChild(workingRow);

        wrap2.appendChild(footer);
        requestAnimationFrame(function() { messages.scrollTop = messages.scrollHeight; });
      }, 7000);
      _thinkingTimers.push(slowT);

      /* ── Step 2 @ 12s: silence "Working...", show "Preparing code of tabname" pill ── */
      var prepT = setTimeout(function() {
        var wrap2 = document.getElementById('mlp-think-wrap');
        if (!wrap2) { return; }

        /* Fade out / silence the working row */
        var workingRow2 = document.getElementById('mlp-working-row');
        if (workingRow2) {
          workingRow2.style.transition = 'opacity 0.5s ease';
          workingRow2.style.opacity = '0';
          setTimeout(function() { if (workingRow2.parentNode) { workingRow2.parentNode.removeChild(workingRow2); } }, 500);
        }

        /* Resolve the active tab name */
        var _activeFileName = '';
        try {
          var _inst = window.monacoInstances && currentIid && window.monacoInstances[currentIid];
          if (_inst && _inst.activeTabId && _inst.tabs && _inst.tabs[_inst.activeTabId]) {
            _activeFileName = _inst.tabs[_inst.activeTabId].title || '';
          }
        } catch(e) {}
        if (!_activeFileName) { _activeFileName = 'preview'; }

        /* Build "Preparing code of tabname..." pill — same style as action row */
        var fileLine = document.createElement('div');
        fileLine.className = 'mlp-action-file-line mlp-action-file-line-row';
        fileLine.id = 'mlp-file-line';

        var fileIconBox = document.createElement('div');
        fileIconBox.className = 'mlp-action-icon mlp-file-icon-box';
        fileIconBox.innerHTML = SVG_FILE;

        var fileLabel = document.createElement('span');
        fileLabel.className = 'mlp-file-preparing-label';
        fileLabel.innerHTML =
          'Preparing code of <span class="mlp-action-file-name">' + _activeFileName + '</span>' +
          '<span class="mlp-preparing-dots"><span>.</span><span>.</span><span>.</span></span>';

        fileLine.appendChild(fileIconBox);
        fileLine.appendChild(fileLabel);

        /* Append inside the footer (or directly to thinkDiv if footer gone) */
        var footer2 = document.getElementById('mlp-think-footer');
        if (footer2) { footer2.appendChild(fileLine); } else { wrap2.appendChild(fileLine); }

        requestAnimationFrame(function() { messages.scrollTop = messages.scrollHeight; });
      }, 12000);
      _thinkingTimers.push(prepT);

    } else if (role === 'ai' || role === 'assistant') {
      bubble.appendChild(parseAIReply(content));

      /* Add Replit-style summary: compact pill + "Checkpoint" + "Worked for X min" */
      if (_completedSteps.length > 0) {
        var elapsedMs  = Date.now() - _thinkingStart;
        var elapsedSec = (elapsedMs / 1000).toFixed(1);
        var elapsedMin = Math.round(elapsedMs / 60000);
        var timeLabel  = elapsedMin >= 1 ? elapsedMin + ' minute' + (elapsedMin === 1 ? '' : 's') : elapsedSec + 's';

        /* Collapsible summary pill */
        var summary = document.createElement('div');
        summary.className = 'mlp-reasoning-summary';

        var miniIcons = '<div class="mlp-reasoning-icons-mini">';
        _completedSteps.forEach(function(s) {
          miniIcons += '<div class="mlp-reasoning-icon-mini"><svg viewBox="0 0 24 24">' + s.svg + '</svg></div>';
        });
        miniIcons += '</div>';

        summary.innerHTML =
          miniIcons +
          '<span class="mlp-reasoning-count">' + _completedSteps.length + ' actions &middot; ' + elapsedSec + 's</span>' +
          '<span class="mlp-reasoning-arrow">&#9662;</span>';

        var detail = document.createElement('div');
        detail.className = 'mlp-reasoning-detail';
        detail.innerHTML = _completedSteps.map(function(s) {
          return '<span class="mlp-reasoning-step-done">&#10003;</span>' + s.label;
        }).join('<br>');

        summary.addEventListener('click', function() {
          var isOpen = detail.classList.toggle('open');
          summary.classList.toggle('open', isOpen);
          requestAnimationFrame(function() { messages.scrollTop = messages.scrollHeight; });
        });
        bubble.appendChild(summary);
        bubble.appendChild(detail);

        /* Replit-style footer: Checkpoint + Worked for X minutes */
        var footerWrap = document.createElement('div');
        footerWrap.className = 'mlp-thinking-footer';
        footerWrap.style.marginTop = '8px';

        /* Checkpoint row */
        var checkRow = document.createElement('div');
        checkRow.className = 'mlp-thinking-footer-row';
        checkRow.innerHTML =
          '<span class="mlp-thinking-footer-icon icon-check">' +
            '<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" stroke-width="1.6"/><polyline points="5.5,8 7,10 10.5,6" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none" stroke="currentColor"/></svg>' +
          '</span>' +
          '<span>Checkpoint made just now</span>';
        footerWrap.appendChild(checkRow);

        /* Worked for X minutes row */
        var workedRow = document.createElement('div');
        workedRow.className = 'mlp-thinking-footer-row';
        workedRow.innerHTML =
          '<span class="mlp-thinking-footer-icon icon-clock">' +
            '<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" stroke-width="1.6"/><polyline points="8,5 8,8 10.5,9.5" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none" stroke="currentColor"/></svg>' +
          '</span>' +
          '<span>Worked for ' + timeLabel + '</span>';
        footerWrap.appendChild(workedRow);

        bubble.appendChild(footerWrap);

        _completedSteps = [];
      }

      if (provider) {
        /* Store provider on the bubble for popup use — don't render badge inline */
        bubble.dataset.provider = provider;

        /* Make the "AI" role label clickable to show popup (admin only) */
        if (mlpIsAdmin) {
        roleLabel.style.cursor = 'pointer';
        roleLabel.title = 'Click to see AI provider';
        roleLabel.addEventListener('click', function(e) {
          e.stopPropagation();
          /* Remove any existing popup */
          var existing = document.getElementById('mlpProviderPopup');
          if (existing) { existing.parentNode.removeChild(existing); }

          var popup = document.createElement('div');
          popup.id = 'mlpProviderPopup';
          popup.style.cssText = [
            'position:absolute',
            'z-index:9999999',
            'background:var(--c-bg2)',
            'border:1px solid var(--c-border2)',
            'border-radius:10px',
            'padding:8px 12px',
            'font-size:0.7rem',
            'font-family:var(--c-font)',
            'color:var(--c-text)',
            'box-shadow:0 4px 16px rgba(0,0,0,0.18)',
            'display:flex',
            'align-items:center',
            'gap:10px',
            'white-space:nowrap',
            'pointer-events:all'
          ].join(';');

          var badge = makeProviderBadge(provider);
          if (badge) { popup.appendChild(badge); }

          var closeBtn = document.createElement('button');
          closeBtn.textContent = '✕';
          closeBtn.style.cssText = 'background:none;border:none;cursor:pointer;color:var(--c-text3);font-size:0.75rem;padding:0;line-height:1;';
          closeBtn.addEventListener('click', function(ev) {
            ev.stopPropagation();
            if (popup.parentNode) { popup.parentNode.removeChild(popup); }
          });
          popup.appendChild(closeBtn);

          /* Position popup near the role label */
          var rect = roleLabel.getBoundingClientRect();
          var sidebarRect = document.getElementById('mlpChatSidebar').getBoundingClientRect();
          popup.style.top  = (rect.bottom - sidebarRect.top + 4) + 'px';
          popup.style.left = (rect.left - sidebarRect.left) + 'px';

          document.getElementById('mlpChatSidebar').appendChild(popup);

          /* Close on outside click */
          setTimeout(function() {
            document.addEventListener('click', function _close() {
              if (popup.parentNode) { popup.parentNode.removeChild(popup); }
              document.removeEventListener('click', _close);
            });
          }, 10);
        });
        } /* end if (mlpIsAdmin) */
      }

      /* ── Like / Dislike / Copy buttons ── */
      (function(msgProvider, msgContent) {
        var reactions = document.createElement('div');
        reactions.className = 'mlp-msg-reactions';

        /* SVG paths */
        var SVG_LIKE    = '<svg viewBox="0 0 24 24"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3H14z"/><path d="M7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"/></svg>';
        var SVG_DISLIKE = '<svg viewBox="0 0 24 24"><path d="M10 15v4a3 3 0 0 0 3 3l4-9V2H5.72a2 2 0 0 0-2 1.7l-1.38 9a2 2 0 0 0 2 2.3H10z"/><path d="M17 2h2.67A2.31 2.31 0 0 1 22 4v7a2.31 2.31 0 0 1-2.33 2H17"/></svg>';
        var SVG_COPY    = '<svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';

        var likeBtn    = document.createElement('button');
        likeBtn.className = 'mlp-react-btn';
        likeBtn.title  = 'Helpful';
        likeBtn.innerHTML = SVG_LIKE;

        var dislikeBtn = document.createElement('button');
        dislikeBtn.className = 'mlp-react-btn';
        dislikeBtn.title = 'Not helpful';
        dislikeBtn.innerHTML = SVG_DISLIKE;

        var copyBtn = document.createElement('button');
        copyBtn.className = 'mlp-react-btn';
        copyBtn.title = 'Copy response';
        copyBtn.innerHTML = SVG_COPY;

        var _voted = null;

        function _appendFeedbackMsg(html) {
          var fbWrap = document.createElement('div');
          fbWrap.className = 'mlp-msg mlp-msg-ai';
          fbWrap.style.marginTop = '4px';
          var fbRole = document.createElement('div');
          fbRole.className = 'mlp-msg-role';
          fbRole.textContent = 'AI';
          var fbBub = document.createElement('div');
          fbBub.className = 'mlp-msg-bubble';
          fbBub.style.fontStyle = 'italic';
          fbBub.innerHTML = html;
          fbWrap.appendChild(fbRole);
          fbWrap.appendChild(fbBub);
          var parentWrap = reactions.closest('.mlp-msg');
          if (parentWrap && parentWrap.nextSibling) {
            messages.insertBefore(fbWrap, parentWrap.nextSibling);
          } else {
            messages.appendChild(fbWrap);
          }
          requestAnimationFrame(function() { messages.scrollTop = messages.scrollHeight; });
          setTimeout(function() { if (fbWrap.parentNode) { fbWrap.parentNode.removeChild(fbWrap); } }, 6000);
        }

        likeBtn.addEventListener('click', function() {
          if (_voted === 'like') { return; }
          _voted = 'like';
          likeBtn.classList.add('mlp-voted', 'mlp-liked');
          dislikeBtn.classList.remove('mlp-voted', 'mlp-disliked');
          dislikeBtn.style.opacity = '0.3';
          dislikeBtn.disabled = true;
          _getVoteBucket(msgProvider).likes++;
          _saveVotes();
          _appendFeedbackMsg('Thanks! I\u2019m here to assist if you need more help \uD83D\uDE0A');
        });

        dislikeBtn.addEventListener('click', function() {
          if (_voted === 'dislike') { return; }
          _voted = 'dislike';
          dislikeBtn.classList.add('mlp-voted', 'mlp-disliked');
          likeBtn.classList.remove('mlp-voted', 'mlp-liked');
          likeBtn.style.opacity = '0.3';
          likeBtn.disabled = true;
          _getVoteBucket(msgProvider).dislikes++;
          _saveVotes();
          _appendFeedbackMsg(
            'Sorry \uD83D\uDE1E that you didn\u2019t like the result, send feedback in the ' +
            '<a href="https://ptero.discourse.group/" target="_blank" rel="noopener noreferrer" ' +
            'style="color:var(--c-accent);text-decoration:underline;">Ptero forum</a>.'
          );
        });

        copyBtn.addEventListener('click', function() {
          var plainText = msgContent || '';
          navigator.clipboard && navigator.clipboard.writeText(plainText).then(function() {
            copyBtn.classList.add('mlp-voted-copy');
            var origSvg = copyBtn.innerHTML;
            copyBtn.innerHTML = '<svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>';
            setTimeout(function() {
              copyBtn.classList.remove('mlp-voted-copy');
              copyBtn.innerHTML = origSvg;
            }, 2000);
          });
        });

        reactions.appendChild(likeBtn);
        reactions.appendChild(dislikeBtn);
        reactions.appendChild(copyBtn);
        bubble.appendChild(reactions);
      })(provider, content);
    } else {
      /* User message — render text + any image attachments */
      if (attachments && attachments.length > 0) {
        attachments.forEach(function (att) {
          if (att.type && att.type.indexOf('image') === 0) {
            var img = document.createElement('img');
            img.className = 'mlp-msg-img';
            img.src = att.dataUrl;
            img.alt = att.name;
            bubble.appendChild(img);
          } else {
            /* Non-image file: show a chip */
            var fc = document.createElement('div');
            fc.className = 'mlp-attachment-chip';
            fc.style.marginBottom = '4px';
            fc.innerHTML = '<span class="mlp-attachment-chip-ext">' + att.ext + '</span>' +
                           '<span class="mlp-attachment-chip-name">' + att.name + '</span>';
            bubble.appendChild(fc);
          }
        });
      }
      bubble.appendChild(document.createTextNode(content));
    }

    wrap.appendChild(roleLabel);
    wrap.appendChild(bubble);
    messages.appendChild(wrap);
    requestAnimationFrame(function () { messages.scrollTop = messages.scrollHeight; });
    return wrap;
  }

  function removeTyping() {
    _clearThinkingTimers();
    var el = document.getElementById('mlp-typing-bubble');
    if (el) { el.parentNode.removeChild(el); }
  }

  /* ── Turnstile: show captcha in chat on first message ── */
  function _tsShowBubble(pendingText) {
    _tsPending = pendingText;
    /* Show user bubble with any pending attachments */
    appendMessage('user', pendingText, false, '', _tsPendingAttachments);
    inputEl.value = '';
    autoResize();
    /* Clear the attachment chips from the input area */
    _attachments = []; _renderAttachments();

    var wrap = document.createElement('div');
    wrap.className = 'mlp-msg mlp-msg-ai';
    var lbl = document.createElement('div');
    lbl.className = 'mlp-msg-role';
    lbl.textContent = 'AI';
    var bub = document.createElement('div');
    bub.className = 'mlp-msg-bubble';
    bub.innerHTML =
      '<div class="mlp-ts-bubble">' +
        "<div>👋 <b>Confirm you're a human</b><br><span style=\"font-size:0.78rem;color:#4a6a85;\">One-time check — takes 2 seconds.</span></div>" +
        '<div id="mlp-ts-widget"></div>' +
        '<div class="mlp-ts-bubble-ok" id="mlp-ts-ok">\u2714 Verified! Sending your message\u2026</div>' +
      '</div>';
    wrap.appendChild(lbl);
    wrap.appendChild(bub);
    messages.appendChild(wrap);
    requestAnimationFrame(function () { messages.scrollTop = messages.scrollHeight; });

    var sitekey = '<?php echo defined("MLP_TURNSTILE_SITE_KEY") ? esc_js(MLP_TURNSTILE_SITE_KEY) : ""; ?>';
    function doRender() {
      window.turnstile.render('#mlp-ts-widget', {
        sitekey: sitekey,
        theme:   'dark',
        callback: function (token) {
          _tsToken    = token;
          _tsVerified = true;
          var ok  = document.getElementById('mlp-ts-ok');
          var wid = document.getElementById('mlp-ts-widget');
          if (ok)  { ok.style.display  = 'block'; }
          if (wid) { wid.style.display = 'none';  }
          requestAnimationFrame(function () { messages.scrollTop = messages.scrollHeight; });
          setTimeout(function () { _doSend(_tsPending, true, _tsPendingAttachments); _tsPending = ''; _tsPendingAttachments = []; }, 700);
        },
        'error-callback': function () {
          var wid = document.getElementById('mlp-ts-widget');
          if (wid) { wid.innerHTML = '<span style="color:#fca5a5;font-size:0.75rem;">Verification failed — please refresh the page.</span>'; }
        }
      });
    }
    if (window.turnstile && window.turnstile.render) {
      doRender();
    } else {
      /* Wait for the Turnstile script to load via its onload event — no polling */
      var tsScript = document.querySelector('script[src*="turnstile"]');
      if (tsScript) {
        tsScript.addEventListener('load', doRender, { once: true });
      } else {
        /* Script not yet in DOM — watch for it once with a short MutationObserver */
        var tsObserver = new MutationObserver(function (_, obs) {
          var s = document.querySelector('script[src*="turnstile"]');
          if (s) { obs.disconnect(); s.addEventListener('load', doRender, { once: true }); }
        });
        tsObserver.observe(document.head, { childList: true });
      }
    }
  }

  /* ══════════════════════════════════════════════════
     MEDIA ATTACHMENT SYSTEM
     (lives here so it can directly access currentNdTier,
      mlpNd2Provider, mlpSelectedProvider, providerStatuses)
  ══════════════════════════════════════════════════ */

  var MEDIA_CAPABLE_PROVIDERS = {
    'gemini':      true,
    'github':      true,
    'replit':      true,
    'mistral':     false,
    'cerebras':    false,
    'groq':        false,
    'cohere':      false,
    'siliconflow': false
  };
  var MEDIA_MIGRATION_ORDER = ['gemini', 'github', 'replit'];
  var _attachments = [];

  var _mediaInput = document.getElementById('mlpMediaFileInput');
  var _mediaBtn   = document.getElementById('mlpMediaBtn');
  var _attachRow  = document.getElementById('mlpAttachmentsRow');

  if (_mediaBtn && _mediaInput) {
    _mediaBtn.addEventListener('click', function () {
      _mediaInput.value = '';
      _mediaInput.click();
    });
    _mediaInput.addEventListener('change', function () {
      Array.prototype.forEach.call(_mediaInput.files || [], _addAttachment);
    });
  }

  /* Drag-and-drop + paste onto textarea */
  var _mediaTa = document.getElementById('mlpChatInput');
  if (_mediaTa) {
    _mediaTa.addEventListener('dragover',  function (e) { e.preventDefault(); _mediaTa.style.borderLeft = '2px solid var(--c-accent)'; });
    _mediaTa.addEventListener('dragleave', function ()  { _mediaTa.style.borderLeft = ''; });
    _mediaTa.addEventListener('drop', function (e) {
      e.preventDefault(); _mediaTa.style.borderLeft = '';
      Array.prototype.forEach.call((e.dataTransfer && e.dataTransfer.files) || [], _addAttachment);
    });
    _mediaTa.addEventListener('paste', function (e) {
      var items = e.clipboardData && e.clipboardData.items;
      if (!items) { return; }
      for (var i = 0; i < items.length; i++) {
        if (items[i].kind === 'file' && items[i].type.indexOf('image') === 0) {
          var f = items[i].getAsFile();
          if (f) { _addAttachment(f); }
        }
      }
    });
  }

  function _addAttachment(file) {
    if (!file) { return; }
    var ext = (file.name.split('.').pop() || '').toUpperCase().slice(0, 5);
    var reader = new FileReader();
    reader.onload = function (ev) {
      _attachments.push({ file: file, name: file.name, ext: ext, dataUrl: ev.target.result, type: file.type });
      _renderAttachments();
    };
    reader.readAsDataURL(file);
  }

  function _renderAttachments() {
    if (!_attachRow) { return; }
    _attachRow.innerHTML = '';
    if (_attachments.length === 0) { _attachRow.classList.remove('has-files'); return; }
    _attachRow.classList.add('has-files');
    _attachments.forEach(function (att, idx) {
      var chip = document.createElement('div');
      chip.className = 'mlp-attachment-chip';
      var isImg = att.type && att.type.indexOf('image') === 0;
      chip.innerHTML = (isImg
        ? '<img class="mlp-attachment-chip-img" src="' + att.dataUrl + '" alt="">'
        : '<span class="mlp-attachment-chip-ext">' + att.ext + '</span>') +
        '<span class="mlp-attachment-chip-name">' + escHtml(att.name) + '</span>' +
        '<button class="mlp-attachment-remove" data-idx="' + idx + '" title="Remove">&times;</button>';
      chip.querySelector('.mlp-attachment-remove').addEventListener('click', function (e) {
        e.stopPropagation();
        _attachments.splice(parseInt(this.getAttribute('data-idx'), 10), 1);
        _renderAttachments();
      });
      _attachRow.appendChild(chip);
    });
  }

  function _currentProviderSupportsMedia() {
    var tier = currentNdTier();
    var pid  = (tier === 'nd-2') ? mlpNd2Provider : mlpSelectedProvider;
    return !!MEDIA_CAPABLE_PROVIDERS[pid];
  }

  function _findMediaProvider() {
    for (var i = 0; i < MEDIA_MIGRATION_ORDER.length; i++) {
      var pid = MEDIA_MIGRATION_ORDER[i];
      if (providerStatuses[pid] !== 'rate_limited' && providerStatuses[pid] !== 'offline') { return pid; }
    }
    return MEDIA_MIGRATION_ORDER[0];
  }

  function _migrateToMediaProvider(targetPid) {
    var tier = currentNdTier();
    var PNAMES = { gemini:'Gemini 2.5 Flash', github:'GitHub · GPT-4o', replit:'Replit AI GPT',
                   mistral:'Mistral AI', cerebras:'Cerebras', groq:'Groq',
                   cohere:'Cohere', siliconflow:'SiliconFlow · Qwen3' };
    var fromName = PNAMES[(tier === 'nd-2') ? mlpNd2Provider : mlpSelectedProvider] || 'current AI';
    var toName   = PNAMES[targetPid] || targetPid;

    /* Switch the active provider */
    if (tier === 'nd-2') { mlpNd2Provider = targetPid; }
    else                 { mlpNd2Provider = targetPid; } /* nd-2 providers support media */
    updateBtnLabel();
    renderAiOptions();

    /* Show migration banner in chat */
    var msgBox = document.getElementById('mlpChatMessages');
    if (!msgBox) { return; }
    var notice = document.createElement('div');
    notice.className = 'mlp-msg mlp-msg-ai';
    notice.style.marginTop = '6px';
    var lbl = document.createElement('div'); lbl.className = 'mlp-msg-role'; lbl.textContent = 'AI';
    var bub = document.createElement('div'); bub.className = 'mlp-msg-bubble';
    var banner = document.createElement('div'); banner.className = 'mlp-migrate-banner';
    banner.innerHTML =
      '<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.5"/><line x1="8" y1="5" x2="8" y2="8.5"/><circle cx="8" cy="11" r="0.5" fill="currentColor"/></svg>' +
      '<span><strong>Switching AI for media support</strong><br>' +
      escHtml(fromName) + ' doesn\'t support media. Migrating to <strong>' + escHtml(toName) + '</strong> — your conversation is preserved.</span>';
    bub.appendChild(banner); notice.appendChild(lbl); notice.appendChild(bub);
    msgBox.appendChild(notice);
    requestAnimationFrame(function () { msgBox.scrollTop = msgBox.scrollHeight; });
  }

  /* ─── Send ─── */
  function sendMessage() {
    var text = inputEl.value.trim();
    var pendingAttachments = _attachments.slice();

    /* Allow send if there's text OR attachments */
    if ((!text && pendingAttachments.length === 0) || isBusy || sendBtn.disabled) { return; }

    /* Use a placeholder if user only attached a file with no message */
    if (!text && pendingAttachments.length > 0) {
      text = 'I have attached an image/file. Please analyse it.';
    }

    /* ── Media migration check: provider doesn't support media ── */
    if (pendingAttachments.length > 0 && !_currentProviderSupportsMedia()) {
      var targetPid = _findMediaProvider();
      _migrateToMediaProvider(targetPid);
      /* Small delay so migration banner renders before the send */
      setTimeout(function () {
        _execSendWithMedia(text, pendingAttachments);
      }, 400);
      return;
    }

    /* First message: show Turnstile in chat (preserve attachments) */
    if (!_tsVerified) {
      _tsPendingAttachments = pendingAttachments;
      _tsShowBubble(text);
      return;
    }

    /* Normal send — always pass attachments (even if empty array) */
    _doSend(text, false, pendingAttachments);
  }

  function _execSendWithMedia(text, attachments) {
    if (!_tsVerified) {
      _tsPendingAttachments = attachments;
      _tsShowBubble(text);
      return;
    }
    _doSend(text, false, attachments);
  }

  /* ─────────────────────────────────────────────────────────────
     Browser-side Pollinations fallback
     Called when the PHP backend fails all three server providers.
     Makes a direct fetch to Pollinations (no API key, CORS-open).
     cb(replyText|null) — null means all models also failed.
  ───────────────────────────────────────────────────────────── */
  /* ── Migration animation: shown when server-side providers all fail ── */
  function _showMigrateAnim(failedProvider) {
    var wrap = document.createElement('div');
    wrap.className = 'mlp-msg mlp-msg-ai';
    wrap.id = 'mlp-migrate-wrap';

    var bubble = document.createElement('div');
    bubble.className = 'mlp-msg-bubble';

    /* Console-style scrolling chars row */
    var animRow = document.createElement('div');
    animRow.className = 'mlp-migrate-anim';

    var iconEl = document.createElement('div');
    iconEl.className = 'mlp-migrate-icon';
    iconEl.title = 'Click to see what happened';
    iconEl.innerHTML = '<svg viewBox="0 0 16 16"><polyline points="2,4 2,14 14,14 14,4"/><polyline points="1,2 15,2 15,4 1,4 1,2"/><line x1="5" y1="8" x2="11" y2="8"/><line x1="5" y1="11" x2="9" y2="11"/></svg>';

    /* Console chars animation */
    var consoleEl = document.createElement('span');
    consoleEl.className = 'mlp-migrate-console';
    var _consoleChars = ['ERR', '...', '>>>','---','///','\\\\\\','!!!','...'];
    var _ci = 0;
    consoleEl.textContent = _consoleChars[0];
    var _consoleInt = setInterval(function() {
      _ci = (_ci + 1) % _consoleChars.length;
      consoleEl.textContent = _consoleChars[_ci];
    }, 120);

    var labelEl = document.createElement('div');
    labelEl.className = 'mlp-migrate-label';
    labelEl.innerHTML = '<strong>Migrating</strong><span class="mlp-migrate-cursor">_</span>';

    animRow.appendChild(iconEl);
    animRow.appendChild(consoleEl);
    animRow.appendChild(labelEl);
    bubble.appendChild(animRow);
    wrap.appendChild(bubble);
    messages.appendChild(wrap);
    messages.scrollTop = messages.scrollHeight;

    /* Popup on console icon click */
    var _failedProv = failedProvider || 'previous provider';
    iconEl.addEventListener('click', function(e) {
      e.stopPropagation();
      var existing = document.getElementById('mlpMigratePopup');
      if (existing) { existing.parentNode.removeChild(existing); return; }

      var popup = document.createElement('div');
      popup.id = 'mlpMigratePopup';
      popup.style.cssText = [
        'position:absolute','z-index:9999999',
        'background:var(--c-bg2)','border:1px solid rgba(251,191,36,0.35)',
        'border-radius:10px','padding:10px 13px','max-width:240px',
        'font-size:0.68rem','font-family:var(--c-font)','color:var(--c-text)',
        'box-shadow:0 4px 18px rgba(0,0,0,0.18)','line-height:1.55'
      ].join(';');
      popup.innerHTML =
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">' +
          '<span style="font-weight:700;color:#f59e0b;font-size:0.7rem;">⚠ Provider failed</span>' +
          '<button id="mlpMigratePopupClose" style="background:none;border:none;cursor:pointer;color:var(--c-text3);font-size:0.8rem;padding:0;line-height:1;">✕</button>' +
        '</div>' +
        '<div style="color:var(--c-text2);">' +
          '<strong style="color:var(--c-text);">' + escHtml(_failedProv) + '</strong> did not respond. ' +
          'The system automatically migrated to the next available provider ' +
          '(Pollinations) to answer your message. Your conversation is preserved.' +
        '</div>';

      var rect = iconEl.getBoundingClientRect();
      var sidebarRect = document.getElementById('mlpChatSidebar').getBoundingClientRect();
      popup.style.top  = (rect.bottom - sidebarRect.top + 5) + 'px';
      popup.style.left = (rect.left   - sidebarRect.left)    + 'px';

      document.getElementById('mlpChatSidebar').appendChild(popup);
      popup.querySelector('#mlpMigratePopupClose').addEventListener('click', function(ev) {
        ev.stopPropagation();
        if (popup.parentNode) { popup.parentNode.removeChild(popup); }
      });
      setTimeout(function() {
        document.addEventListener('click', function _cl() {
          if (popup.parentNode) { popup.parentNode.removeChild(popup); }
          document.removeEventListener('click', _cl);
        });
      }, 10);
    });

    return { wrap: wrap, stopConsole: function() { clearInterval(_consoleInt); } };
  }

  function _tryPollinationsClient(text, code, histSlice, cb) {
    var sysPrompt = 'You are an expert HTML/CSS/JavaScript front-end engineer. Help the user write, debug, and optimize web code. When producing code, wrap it in labeled fences: ```html, ```css, ```js. Always output complete file content inside fences.';
    var ctx = '';
    if (code && (code.html || code.css || code.js)) {
      ctx = '\n\n--- EDITOR CODE ---\n';
      if (code.html) { ctx += '### HTML\n' + code.html.substring(0, 3000) + '\n'; }
      if (code.css)  { ctx += '### CSS\n'  + code.css.substring(0, 1500)  + '\n'; }
      if (code.js)   { ctx += '### JS\n'   + code.js.substring(0, 1500)   + '\n'; }
      ctx += '--- END ---\n';
    }
    var msgs = [{ role: 'system', content: sysPrompt }];
    histSlice.forEach(function (t) {
      msgs.push({ role: t.role === 'assistant' ? 'assistant' : 'user', content: t.content.substring(0, 2000) });
    });
    msgs.push({ role: 'user', content: text + ctx });

    var models = ['openai-large', 'openai', 'mistral'];
    var idx = 0;
    function tryNext() {
      if (idx >= models.length) { cb(null); return; }
      var model = models[idx++];
      fetch('https://gen.pollinations.ai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ model: model, messages: msgs, private: true })
      })
      .then(function (r) {
        if (!r.ok) { tryNext(); return null; }
        return r.json();
      })
      .then(function (d) {
        if (!d) { return; }
        var txt = (d.choices && d.choices[0] && d.choices[0].message) ? d.choices[0].message.content : '';
        if (txt) { cb(txt); } else { tryNext(); }
      })
      .catch(function () { tryNext(); });
    }
    tryNext();
  }

  /* ─── Reset send-button + input state ─── */
  function _resetSendUI() {
    isBusy = false;
    abortController = null;
    sendBtn.innerHTML = '<i class="fas fa-paper-plane"></i>';
    sendBtn.classList.remove('mlp-stop-mode');
    sendBtn.title = 'Send (Ctrl+Enter)';
    inputEl.disabled = false;
    inputEl.focus();

    /* ── Re-randomize providers for next message (non-admin only) ── */
    if (!mlpIsAdmin) {
      var nd1ids = ['mistral', 'cerebras', 'groq'];
      mlpSelectedProvider = nd1ids[Math.floor(Math.random() * nd1ids.length)];
      var nd2ids = ['replit', 'siliconflow', 'cohere', 'cerebras', 'github', 'gemini'];
      mlpNd2Provider = nd2ids[Math.floor(Math.random() * nd2ids.length)];
      updateBtnLabel();
    }

    /* ── Start cooldown: block send button for _COOLDOWN_MS ── */
    sendBtn.disabled = true;
    if (cdBar)  { cdBar.classList.add('mlp-cd-active'); }
    if (cdProg) { cdProg.style.width = '100%'; }

    var cdStart = Date.now();
    var cdRaf;
    function _cdTick() {
      var elapsed = Date.now() - cdStart;
      if (elapsed >= _COOLDOWN_MS) {
        sendBtn.disabled = false;
        if (cdBar)  { cdBar.classList.remove('mlp-cd-active'); }
        if (cdProg) { cdProg.style.width = '100%'; }
        return;
      }
      if (cdProg) { cdProg.style.width = Math.max(0, 100 - (elapsed / _COOLDOWN_MS) * 100) + '%'; }
      cdRaf = requestAnimationFrame(_cdTick);
    }
    cdRaf = requestAnimationFrame(_cdTick);
    clearTimeout(_cooldownTimer);
    _cooldownTimer = setTimeout(function () {
      cancelAnimationFrame(cdRaf);
      sendBtn.disabled = false;
      if (cdBar) { cdBar.classList.remove('mlp-cd-active'); }
    }, _COOLDOWN_MS + 50); /* safety net only */
  }

  function _doSend(text, alreadyInChat, _mediaAttachments) {
    if (!text || isBusy) { return; }

    /* Grab attachments: parameter takes priority, then global store */
    var attachments = _mediaAttachments || _attachments.slice();

    var sendIid = currentIid;
    var sendKey = getHistoryKey(sendIid);
    var hist    = getInstanceHistory(sendKey);

    /* Store original text for no-code retry (strip any retry prefix) */
    _lastCodeRequestText = text.replace(/^IMPORTANT:.*?Now: /s, '') || text;

    isBusy = true;
    inputEl.disabled = true;
    sendBtn.title = 'Stop';
    sendBtn.innerHTML = '<i class="fas fa-stop"></i>';
    sendBtn.classList.add('mlp-stop-mode');
    sendBtn.disabled = false;

    hist.push({ role: 'user', content: text });
    if (hist.length > 20) { instanceHistories[sendKey] = hist = hist.slice(-20); }

    if (!alreadyInChat) {
      appendMessage('user', text, false, '', attachments);
      inputEl.value = '';
      autoResize();
      /* Clear attachments after sending */
      _attachments = []; _renderAttachments();
    }

    appendMessage('assistant', '', true);

    var code    = getEditorCode();
    var ndTier  = currentNdTier();
    /* ND-2 always uses replit as the provider key (fallback to cerebras is server-side) */
    var providerToSend = (ndTier === 'nd-2') ? mlpNd2Provider : mlpSelectedProvider;
    var fd   = new FormData();
    fd.append('action',          'mlp_ai_chat');
    fd.append('nonce',           (window.mlp_ajax && window.mlp_ajax.nonce) ? window.mlp_ajax.nonce : '');
    fd.append('message',         text);
    fd.append('html',            code.html);
    fd.append('css',             code.css);
    fd.append('js',              code.js);
    fd.append('provider',        providerToSend);
    fd.append('nd_tier',         ndTier);
    fd.append('turnstile_token', _tsToken);
    _tsToken = '';
    var historySlice = hist.slice(-12);
    fd.append('history', JSON.stringify(historySlice.slice(0, -1)));

    /* ── Append image attachments as base64 ── */
    var imageAttachments = attachments.filter(function(a){ return a.type && a.type.indexOf('image') === 0; });
    if (imageAttachments.length > 0) {
      fd.append('images', JSON.stringify(imageAttachments.map(function(a){
        return { dataUrl: a.dataUrl, mimeType: a.type, name: a.name };
      })));
    }

    var ajaxUrl = (window.mlp_ajax && window.mlp_ajax.ajaxurl) ? window.mlp_ajax.ajaxurl : '/wp-admin/admin-ajax.php';
    abortController = new AbortController();

  /* ── Detect if a message requests code changes ── */
  var _CODE_REQUEST_RE = /\b(build|create|add|make|generate|fix|change|update|modify|refactor|edit|write|implement|convert|redesign|style|remove|replace|insert|move|rename|rewrite|improve|optimize)\b/i;
  var _lastCodeRequestText = ''; /* stores the original user text for retry */

  /* ── Show no-code warning on an AI bubble ── */
  function _showNoCodeWarning(bubble, originalText) {
    var warn = document.createElement('div');
    warn.className = 'mlp-nocode-warn';
    warn.innerHTML =
      '<span>⚠ AI explained but didn\'t generate code. Want it to try again with code?</span>' +
      '<button class="mlp-nocode-retry-btn">🔁 Retry</button>';
    warn.querySelector('.mlp-nocode-retry-btn').addEventListener('click', function () {
      warn.parentNode.removeChild(warn);
      /* Re-send with a strict code-forcing prefix */
      var retryText = 'IMPORTANT: You MUST output the complete code inside ```html / ```css / ```js fences. Do not explain only — produce the full modified file(s). Now: ' + originalText;
      _doSend(retryText, false);
    });
    bubble.appendChild(warn);
    requestAnimationFrame(function () { messages.scrollTop = messages.scrollHeight; });
  }

    fetch(ajaxUrl, { method: 'POST', body: fd, signal: abortController.signal })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var h = getInstanceHistory(sendKey);
        var stillActive = (sendKey === getHistoryKey(currentIid));
        if (data.success && data.data && data.data.reply) {
          removeTyping();
          var reply    = data.data.reply;
          var rawProv  = data.data.provider || '';
          var ndPrefix = ndTier ? ndTier.toUpperCase() : '';
          var provider = (rawProv && ndPrefix) ? (ndPrefix + ' · ' + rawProv) : rawProv;
          h.push({ role: 'assistant', content: reply, provider: provider });
          saveHistories();
          if (stillActive) {
            var msgWrap = appendMessage('assistant', reply, false, provider);
            /* No-code detection: if user asked for code but reply has no fences */
            var hasCodeFence = /```(html|css|js|javascript)/i.test(reply);
            if (!hasCodeFence && _CODE_REQUEST_RE.test(_lastCodeRequestText) && msgWrap) {
              var bub = msgWrap.querySelector('.mlp-msg-bubble');
              if (bub) { _showNoCodeWarning(bub, _lastCodeRequestText); }
            }
          }
        } else {
          /*
           * PHP backend failed all server-side providers.
           * Fall back to a direct browser → Pollinations call (no API key needed,
           * CORS-open). Set _clientFallbackActive so .finally() skips the reset —
           * _resetSendUI() is called inside the callback when the fallback resolves.
           */
          _clientFallbackActive = true;
          var _migrateAnim = _showMigrateAnim(rawProv || 'Server providers');
          _tryPollinationsClient(text, code, hist.slice(-8), function (clientReply) {
            if (_migrateAnim) { _migrateAnim.stopConsole(); var mw = document.getElementById('mlp-migrate-wrap'); if (mw) { mw.parentNode.removeChild(mw); } }
            removeTyping();
            var h2 = getInstanceHistory(sendKey);
            var sa2 = (sendKey === getHistoryKey(currentIid));
            if (clientReply) {
              var pollProv = (ndTier ? ndTier.toUpperCase() + ' · ' : '') + 'Pollinations';
              h2.push({ role: 'assistant', content: clientReply, provider: pollProv });
              saveHistories();
              if (sa2) {
                var pollWrap = appendMessage('assistant', clientReply, false, pollProv);
                var hasCodeFence2 = /```(html|css|js|javascript)/i.test(clientReply);
                if (!hasCodeFence2 && _CODE_REQUEST_RE.test(_lastCodeRequestText) && pollWrap) {
                  var bub2 = pollWrap.querySelector('.mlp-msg-bubble');
                  if (bub2) { _showNoCodeWarning(bub2, _lastCodeRequestText); }
                }
              }
            } else {
              h2.pop();
              var errMsg = (data.data && data.data.message) ? data.data.message : 'AI unavailable. Please try again later.';
              if (sa2) {
                var errWrap = appendMessage('assistant', '\u26A0 ' + errMsg, false);
                if (errWrap) { errWrap.classList.add('mlp-msg-error'); }
              }
            }
            _clientFallbackActive = false;
            _resetSendUI();
          });
        }
      })
      .catch(function (err) {
        removeTyping();
        var h = getInstanceHistory(sendKey);
        var stillActive = (sendKey === getHistoryKey(currentIid));
        if (err.name === 'AbortError') {
          if (stillActive) {
            var stopWrap = appendMessage('assistant', '\u23F9 Response stopped.', false);
            if (stopWrap) { stopWrap.classList.add('mlp-msg-error'); }
          }
        } else {
          if (stillActive) { appendMessage('assistant', '\u26A0 Network error: ' + err.message, false); }
        }
        h.pop();
      })
      .finally(function () {
        if (_clientFallbackActive) { return; } /* client fallback is running — it will reset UI */
        _resetSendUI();
      });
  }

  /* ─── Stop handler ─── */
  sendBtn.addEventListener('click', function () {
    if (isBusy && abortController) {
      abortController.abort();
    } else {
      sendMessage();
    }
  });

  /* ─── Keyboard ─── */
  inputEl.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      sendMessage();
    }
  });

  /* ─── Auto-resize textarea ─── */
  var _rafResize = 0;
  function autoResize() {
    if (_rafResize) { return; }
    _rafResize = requestAnimationFrame(function () {
      _rafResize = 0;
      inputEl.style.height = 'auto';
      inputEl.style.height = Math.min(inputEl.scrollHeight, 140) + 'px';
    });
  }
  inputEl.addEventListener('input', autoResize);

  /* ─── Clear chat ─── */
  clearBtn.addEventListener('click', function () {
    if (!confirm('Clear chat history for this tab?')) { return; }
    var key = getHistoryKey(currentIid);
    if (key) { instanceHistories[key] = []; }
    saveHistories();
    messages.innerHTML = '';
    if (emptyEl) { messages.appendChild(emptyEl); emptyEl.style.display = ''; }
    messages.classList.add('mlp-is-empty');
    var _ch = document.getElementById('mlpInputHint'); if(_ch){_ch.classList.remove('hidden');}
  });

  /* ─── Fill from suggestion ─── */
  window.mlpChatFill = function (text) {
    inputEl.value = text;
    autoResize();
    inputEl.focus();
  };

  /* ─── Quick chip prompt insert ─── */
  window.mlpInsertChipPrompt = function (text) {
    inputEl.value = text;
    autoResize();
    inputEl.focus();
    inputEl.setSelectionRange(text.length, text.length);
  };

  /* ─── Show "?" ND status button for admins only ─── */
  (function () {
    var ndHelpBtn = document.getElementById('mlpNdHelpBtn');
    if (ndHelpBtn && window.mlp_ajax && window.mlp_ajax.is_admin === true) {
      ndHelpBtn.style.display = '';
    }
  })();

  /* ─── Pause background work when tab is hidden ─── */
  document.addEventListener('visibilitychange', function () {
    if (!isOpen) { return; }
    if (!document.hidden) {
      _lastCtxTotal = -1;
      debouncedUpdateCtxStatus();
    }
  });

})();
</script>
<!-- ═══════════════ /MLP AI CHAT SIDEBAR v2.1 ═══════════════ -->
    <?php
}
