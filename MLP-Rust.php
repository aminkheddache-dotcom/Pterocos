<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class MLP_Rust {
    public static function init() {
        add_action( 'wp_head',   [ __CLASS__, 'output_styles'  ], 99 );
        add_action( 'wp_footer', [ __CLASS__, 'output_editor'  ],  5 );
    }

    public static function output_styles() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) {
            return;
        }
        ?>
<style id="mlp-rust-styles">
/* ── Rust CSS variables ─────────────────────────────────────── */
#mlp-rust-overlay {
    --rs-orange:      #e8632a;
    --rs-orange-dim:  #b84e1f;
    --rs-orange-glow: rgba(232,99,42,.38);
    --rs-surface:     #1a1008;
    --rs-bg:          #0f0a05;
    --rs-border:      #2e1f0d;
    --rs-text:        #f0e8e0;
    --rs-muted:       #8a6e58;
    --rs-output-bg:   #0a0705;
    --rs-green:       #3dba6b;
    --rs-red:         #f87171;
    --rs-blue:        #60a5fa;
}

/* ── Overlay ─────────────────────────────────────────────────── */
#mlp-rust-overlay {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 99999;
    background: var(--rs-bg);
    flex-direction: column;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    overflow: hidden;
}
#mlp-rust-overlay.mlp-rs-active { display: flex; }

/* ── Topbar ──────────────────────────────────────────────────── */
#mlp-rs-topbar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 14px;
    height: 46px;
    background: var(--rs-surface);
    border-bottom: 1px solid var(--rs-border);
    flex-shrink: 0;
    overflow: hidden;
}
#mlp-rs-back {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 11px;
    background: transparent;
    border: 1px solid var(--rs-border);
    border-radius: 6px;
    color: var(--rs-muted);
    font-size: .75rem;
    font-weight: 600;
    cursor: pointer;
    font-family: inherit;
    transition: border-color .15s, color .15s;
    white-space: nowrap;
    flex-shrink: 0;
}
#mlp-rs-back:hover { border-color: var(--rs-orange); color: var(--rs-orange); }

#mlp-rs-title {
    flex: 1;
    font-size: .83rem;
    font-weight: 700;
    color: var(--rs-text);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 8px;
}
#mlp-rs-title .rs-lang-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    background: rgba(232,99,42,.18);
    color: var(--rs-orange);
    border-radius: 4px;
    font-size: .62rem;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    border: 1px solid rgba(232,99,42,.28);
    flex-shrink: 0;
}

/* ── Buttons ─────────────────────────────────────────────────── */
.mlp-rs-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    border-radius: 6px;
    font-family: inherit;
    font-size: .75rem;
    font-weight: 700;
    cursor: pointer;
    border: 1px solid transparent;
    white-space: nowrap;
    transition: opacity .15s, background .15s, border-color .15s, color .15s;
    flex-shrink: 0;
}
.mlp-rs-btn:disabled { opacity: .5; cursor: not-allowed; }

#mlp-rs-run {
    background: linear-gradient(135deg, #e8632a, #b84e1f);
    color: #fff;
    border-color: transparent;
    box-shadow: 0 1px 8px rgba(232,99,42,.35);
}
#mlp-rs-run:hover:not(:disabled) { opacity: .88; }

#mlp-rs-check {
    background: transparent;
    border-color: var(--rs-border);
    color: var(--rs-muted);
}
#mlp-rs-check:hover:not(:disabled) { border-color: var(--rs-orange); color: var(--rs-orange); }

#mlp-rs-save {
    background: transparent;
    border-color: var(--rs-border);
    color: var(--rs-muted);
}
#mlp-rs-save:hover:not(:disabled) { border-color: var(--rs-orange); color: var(--rs-orange); }

#mlp-rs-export {
    background: transparent;
    border-color: var(--rs-border);
    color: var(--rs-muted);
}
#mlp-rs-export:hover:not(:disabled) { border-color: var(--rs-blue); color: var(--rs-blue); }

#mlp-rs-format {
    background: transparent;
    border-color: var(--rs-border);
    color: var(--rs-muted);
}
#mlp-rs-format:hover:not(:disabled) { border-color: var(--rs-orange); color: var(--rs-orange); }

#mlp-rs-copy-code {
    background: transparent;
    border-color: var(--rs-border);
    color: var(--rs-muted);
}
#mlp-rs-copy-code:hover:not(:disabled) { border-color: var(--rs-green); color: var(--rs-green); }


#mlp-rs-fullscreen-btn {
    background: transparent;
    border-color: var(--rs-border);
    color: var(--rs-muted);
    padding: 5px 9px;
    border: 1px solid var(--rs-border);
    border-radius: 6px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    transition: border-color .15s, color .15s;
    flex-shrink: 0;
}
#mlp-rs-fullscreen-btn:hover { border-color: var(--rs-blue); color: var(--rs-blue); }

/* ── Floating AI Chat FAB ────────────────────────────────────── */
#mlp-rs-chat-fab {
    position: fixed;
    bottom: 28px;
    right: 16px;
    z-index: 999993;
    height: 38px;
    padding: 0 14px 0 11px;
    border-radius: 8px;
    background: linear-gradient(135deg, #e8632a, #b84e1f);
    border: none;
    color: #fff;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: .75rem;
    font-weight: 700;
    letter-spacing: .02em;
    white-space: nowrap;
    box-shadow: 0 4px 18px rgba(232,99,42,.45), 0 1px 4px rgba(0,0,0,.4);
    transition: opacity .18s, transform .18s, box-shadow .18s;
}
#mlp-rs-chat-fab:hover { opacity: .9; transform: translateY(-2px); box-shadow: 0 6px 22px rgba(232,99,42,.55); }
#mlp-rs-chat-fab.mlp-rs-fab-hidden { opacity: 0; pointer-events: none; transform: translateY(6px); }

/* ── Tabbar ──────────────────────────────────────────────────── */
#mlp-rs-tabbar {
    display: flex;
    align-items: center;
    padding: 0 14px;
    height: 36px;
    background: var(--rs-surface);
    border-bottom: 1px solid var(--rs-border);
    flex-shrink: 0;
    overflow: hidden;
}
.mlp-rs-tab {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 0 14px;
    height: 100%;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--rs-muted);
    font-family: inherit;
    font-size: .73rem;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    transition: color .12s, border-color .12s;
}
.mlp-rs-tab.mlp-rs-tab-active { color: var(--rs-text); border-bottom-color: var(--rs-orange); }

/* ── Fullscreen overrides ────────────────────────────────────── */
#mlp-rust-overlay.mlp-rs-fullscreen #mlp-rs-topbar,
#mlp-rust-overlay.mlp-rs-fullscreen #mlp-rs-tabbar,
#mlp-rust-overlay.mlp-rs-fullscreen #mlp-rs-statusbar { display: none !important; }
#mlp-rust-overlay.mlp-rs-fullscreen #mlp-rs-output-wrap { display: none !important; }
#mlp-rust-overlay.mlp-rs-fullscreen #mlp-rs-resizer { display: none !important; }

/* ── Main split ──────────────────────────────────────────────── */
#mlp-rs-main {
    flex: 1;
    display: flex;
    flex-direction: row;
    overflow: hidden;
    min-height: 0;
}
#mlp-rs-editor-wrap {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    position: relative;
}
#mlp-rs-editor { flex: 1; min-height: 0; width: 100%; }

/* ── Resizer ─────────────────────────────────────────────────── */
#mlp-rs-resizer {
    width: 5px;
    background: var(--rs-border);
    cursor: col-resize;
    flex-shrink: 0;
    transition: background .15s;
    position: relative;
    z-index: 2;
}
#mlp-rs-resizer:hover,
#mlp-rs-resizer.mlp-rs-dragging { background: var(--rs-orange); }

/* ── Output panel ────────────────────────────────────────────── */
#mlp-rs-output-wrap {
    width: 38%;
    min-width: 220px;
    max-width: 70%;
    display: flex;
    flex-direction: column;
    background: var(--rs-output-bg);
    border-left: 1px solid var(--rs-border);
    overflow: hidden;
}
#mlp-rs-output-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 12px;
    height: 34px;
    background: var(--rs-surface);
    border-bottom: 1px solid var(--rs-border);
    flex-shrink: 0;
}
#mlp-rs-output-title {
    flex: 1;
    font-size: .68rem;
    font-weight: 700;
    color: var(--rs-muted);
    text-transform: uppercase;
    letter-spacing: .07em;
}
#mlp-rs-clear-btn {
    background: none;
    border: none;
    color: var(--rs-muted);
    font-size: .68rem;
    cursor: pointer;
    font-family: inherit;
    padding: 3px 7px;
    border-radius: 4px;
    transition: color .15s, background .15s;
}
#mlp-rs-clear-btn:hover { color: var(--rs-red); background: rgba(248,113,113,.1); }
#mlp-rs-output {
    flex: 1;
    overflow-y: auto;
    padding: 10px 12px;
    font-size: .78rem;
    line-height: 1.7;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    color: #d4d4d4;
    white-space: pre-wrap;
    word-break: break-word;
    background: var(--rs-output-bg);
}
#mlp-rs-output::-webkit-scrollbar { width: 5px; }
#mlp-rs-output::-webkit-scrollbar-thumb { background: var(--rs-border); border-radius: 3px; }
.mlp-rs-out-line   { display: block; padding: 0; }
.mlp-rs-out-err    { color: var(--rs-red); }
.mlp-rs-out-warn   { color: #fbbf24; }
.mlp-rs-out-info   { color: #4a7fa8; font-style: italic; font-size: .72rem; }
.mlp-rs-out-ok     { color: var(--rs-green); font-size: .72rem; }
.mlp-rs-out-note   { color: #7aa2c8; font-size: .72rem; }
.mlp-rs-out-timing { color: var(--rs-muted); font-size: .7rem; font-style: italic; }
.mlp-rs-out-sep {
    display: block;
    color: var(--rs-muted);
    font-size: .68rem;
    letter-spacing: .04em;
    margin: 4px 0 6px;
    white-space: nowrap;
    overflow: hidden;
}
.mlp-rs-out-sep::after {
    content: '';
    display: inline-block;
    width: 100%;
    border-top: 1px solid var(--rs-border);
    vertical-align: middle;
    margin-left: 6px;
}
.mlp-rs-out-badge-ok  { color: var(--rs-green); font-weight: 700; font-size: .73rem; }
.mlp-rs-out-badge-err { color: var(--rs-red);   font-weight: 700; font-size: .73rem; }
.mlp-rs-out-badge-warn { color: #fbbf24;         font-weight: 700; font-size: .73rem; }

/* ── Stdin input panel ───────────────────────────────────────── */
#mlp-rs-stdin-wrap {
    flex-shrink: 0;
    border-top: 1px solid var(--rs-border);
    background: var(--rs-surface);
}
#mlp-rs-stdin-header {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 0 10px;
    height: 26px;
    border-bottom: 1px solid var(--rs-border);
    cursor: pointer;
    user-select: none;
}
#mlp-rs-stdin-label {
    flex: 1;
    font-size: .63rem;
    font-weight: 700;
    color: var(--rs-muted);
    text-transform: uppercase;
    letter-spacing: .07em;
}
#mlp-rs-stdin-chevron {
    color: var(--rs-muted);
    transition: transform .15s;
}
#mlp-rs-stdin-header.mlp-rs-stdin-open #mlp-rs-stdin-chevron { transform: rotate(180deg); }
#mlp-rs-stdin-body {
    display: none;
    padding: 6px 10px 8px;
}
#mlp-rs-stdin-body.mlp-rs-stdin-open { display: block; }
#mlp-rs-stdin {
    width: 100%;
    min-height: 52px;
    max-height: 110px;
    padding: 5px 8px;
    background: rgba(0,0,0,.35);
    border: 1px solid var(--rs-border);
    border-radius: 4px;
    color: var(--rs-text);
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: .75rem;
    line-height: 1.5;
    resize: vertical;
    transition: border-color .15s;
    box-sizing: border-box;
}
#mlp-rs-stdin:focus { outline: none; border-color: var(--rs-orange); }
#mlp-rs-stdin::placeholder { color: var(--rs-muted); opacity: .7; }
#mlp-rs-stdin-actions {
    display: flex;
    justify-content: flex-start;
    margin-top: 6px;
}
#mlp-rs-stdin-run {
    background: linear-gradient(135deg, #e8632a, #b84e1f);
    color: #fff;
    border-color: transparent;
    box-shadow: 0 1px 6px rgba(232,99,42,.3);
    font-size: .72rem;
    padding: 4px 12px;
}
#mlp-rs-stdin-run:hover:not(:disabled) { opacity: .88; }
#mlp-rs-stdin-hint {
    margin-top: 4px;
    font-size: .62rem;
    color: var(--rs-muted);
}

/* ── Status bar ──────────────────────────────────────────────── */
#mlp-rs-statusbar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 14px;
    height: 24px;
    background: var(--rs-surface);
    border-top: 1px solid var(--rs-border);
    flex-shrink: 0;
    font-size: .62rem;
    color: var(--rs-muted);
    overflow: hidden;
}
#mlp-rs-status-lang { display: inline-flex; align-items: center; gap: 4px; color: var(--rs-orange); font-weight: 600; }
#mlp-rs-status-msg  { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
#mlp-rs-status-pos  { white-space: nowrap; }
#mlp-rs-status-save { white-space: nowrap; font-style: italic; }

/* ── Toast ───────────────────────────────────────────────────── */
#mlp-rs-toast {
    position: fixed;
    bottom: 28px;
    right: 28px;
    z-index: 999999;
    background: #1d1309;
    border: 1.5px solid #3d2814;
    border-radius: 8px;
    padding: 11px 18px;
    font-size: .8rem;
    font-weight: 700;
    color: #f0e8e0;
    box-shadow: 0 8px 32px rgba(0,0,0,.7), 0 2px 8px rgba(0,0,0,.5);
    opacity: 0;
    transform: translateY(10px) scale(.97);
    transition: opacity .2s, transform .2s;
    pointer-events: none;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    letter-spacing: .01em;
    white-space: nowrap;
}
#mlp-rs-toast.mlp-rs-show { opacity: 1; transform: translateY(0) scale(1); }
#mlp-rs-toast.mlp-rs-err  { border-color: #f87171; color: #fca5a5; }
#mlp-rs-toast.mlp-rs-succ { border-color: #3dba6b; color: #86efac; }

/* Save flash on status bar */
@keyframes mlp-rs-save-flash {
    0%   { color: var(--rs-green); font-weight: 700; }
    60%  { color: var(--rs-green); font-weight: 700; }
    100% { color: var(--rs-muted); font-weight: 400; }
}
#mlp-rs-status-save.mlp-rs-saved-flash { animation: mlp-rs-save-flash 1.8s ease-out forwards; }

/* ── Run spinner ─────────────────────────────────────────────── */
@keyframes mlp-rs-spin { to { transform: rotate(360deg); } }
.mlp-rs-spinner {
    width: 12px;
    height: 12px;
    border: 2px solid rgba(255,255,255,.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: mlp-rs-spin .7s linear infinite;
    display: inline-block;
    flex-shrink: 0;
}

/* ── Mobile layout ───────────────────────────────────────────── */
@media (max-width: 680px) {
    #mlp-rs-main { flex-direction: column; }
    #mlp-rs-output-wrap { width: 100%; max-width: 100%; min-width: 0; border-left: none; border-top: 1px solid var(--rs-border); height: 38%; }
    #mlp-rs-resizer { display: none; }
}

/* ── AI Chat Sidebar ─────────────────────────────────────────── */
#mlp-rs-chat-sidebar {
    position: fixed;
    top: 56px;
    right: 12px;
    bottom: 20px;
    width: 360px;
    max-width: calc(96vw - 12px);
    z-index: 999991;
    background: #120d07;
    border: 1px solid #3d2814;
    border-radius: 10px;
    display: flex;
    flex-direction: column;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    transform: translateX(400px);
    transition: transform 0.25s cubic-bezier(0.4,0,0.2,1);
    box-shadow: -4px 12px 40px rgba(0,0,0,.75), 0 0 0 1px rgba(232,99,42,.18);
    overflow: hidden;
}
#mlp-rs-chat-sidebar.mlp-rs-chat-open { transform: translateX(0); }

#mlp-rs-chat-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    background: #1d1309;
    border-bottom: 1px solid #3d2814;
    flex-shrink: 0;
}
#mlp-rs-chat-title {
    font-size: .83rem;
    font-weight: 700;
    color: #f0e8e0;
    display: flex;
    align-items: center;
    gap: 7px;
}
#mlp-rs-chat-title svg { color: #e8632a; }
#mlp-rs-chat-close {
    background: none;
    border: none;
    color: #8a6e58;
    cursor: pointer;
    padding: 4px;
    display: flex;
    align-items: center;
    transition: color .15s;
}
#mlp-rs-chat-close:hover { color: #f0e8e0; }

#mlp-rs-chat-messages {
    flex: 1;
    overflow-y: auto;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    background: #120d07;
}
#mlp-rs-chat-messages::-webkit-scrollbar { width: 5px; }
#mlp-rs-chat-messages::-webkit-scrollbar-thumb { background: #3d2814; border-radius: 3px; }

.mlp-rs-chat-msg {
    padding: 9px 11px;
    border-radius: 6px;
    font-size: .76rem;
    line-height: 1.55;
    max-width: 95%;
    word-wrap: break-word;
}
.mlp-rs-chat-msg.user {
    background: #2d1a08;
    color: #fed7aa;
    align-self: flex-end;
    margin-left: auto;
    border: 1px solid #5a3218;
}
.mlp-rs-chat-msg.assistant {
    background: #1a1208;
    color: #e8ddd4;
    align-self: flex-start;
    border: 1px solid #2e1f0d;
}
.mlp-rs-chat-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: #6a5040;
    font-size: .73rem;
    text-align: center;
    padding: 20px;
    line-height: 1.6;
}

#mlp-rs-chat-input-area {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px;
    background: #1d1309;
    border-top: 1px solid #3d2814;
    flex-shrink: 0;
}
#mlp-rs-chat-input {
    width: 100%;
    padding: 9px 10px;
    background: #0d0802;
    border: 1px solid #4a2e14;
    border-radius: 5px;
    color: #f0e8e0;
    font-family: inherit;
    font-size: .76rem;
    resize: none;
    min-height: 60px;
    max-height: 100px;
    transition: border-color .15s;
    box-sizing: border-box;
}
#mlp-rs-chat-input::placeholder { color: #5a4030; }
#mlp-rs-chat-input:focus { outline: none; border-color: #e8632a; box-shadow: 0 0 0 2px rgba(232,99,42,.18); }
#mlp-rs-chat-send {
    align-self: flex-end;
    padding: 6px 16px;
    background: #e8632a;
    color: #fff;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: .74rem;
    font-weight: 700;
    font-family: inherit;
    transition: background .15s, opacity .15s;
    letter-spacing: .02em;
}
#mlp-rs-chat-send:hover:not(:disabled) { background: #c75222; }
#mlp-rs-chat-send:disabled { background: #5a3010; color: #8a6040; cursor: not-allowed; }

/* ── Chat markdown ───────────────────────────────────────────── */
.mlp-rs-chat-msg.assistant .mlp-rs-md-h2 {
    display: block; font-size: .85rem; font-weight: 700; color: #fdba74;
    margin: 8px 0 3px; padding-bottom: 3px; border-bottom: 1px solid #2e1f0d;
}
.mlp-rs-chat-msg.assistant .mlp-rs-md-h3 {
    display: block; font-size: .78rem; font-weight: 700; color: #fb923c;
    margin: 6px 0 2px;
}
.mlp-rs-chat-msg.assistant .mlp-rs-md-code {
    font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
    font-size: .72rem; background: rgba(0,0,0,.35); border: 1px solid #2a2a2a;
    border-radius: 3px; padding: 0 4px; color: #fbbf24;
}
.mlp-rs-chat-msg.assistant strong { color: var(--rs-text); font-weight: 700; }
.mlp-rs-chat-msg.assistant em { color: #d1d5db; font-style: italic; }

/* ── Code blocks inside chat ─────────────────────────────────── */
.mlp-rs-chat-code-wrap { margin: 6px 0 0; border-radius: 6px; overflow: hidden; border: 1px solid #2a2a2a; background: #0d0a07; max-width: 100%; }
.mlp-rs-chat-code-header { display: flex; align-items: center; justify-content: space-between; padding: 4px 10px; background: #1a1410; border-bottom: 1px solid #2a2a2a; }
.mlp-rs-chat-code-lang { font-size: .62rem; font-weight: 700; color: var(--rs-orange); letter-spacing: .06em; text-transform: uppercase; }
.mlp-rs-chat-code-actions { display: flex; gap: 5px; }
.mlp-rs-chat-code-apply,
.mlp-rs-chat-code-copy {
    display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px;
    border-radius: 4px; font-family: inherit; font-size: .65rem; font-weight: 700;
    cursor: pointer; border: 1px solid transparent; transition: opacity .15s, background .15s;
}
.mlp-rs-chat-code-apply { background: var(--rs-orange); color: #fff; }
.mlp-rs-chat-code-apply:hover { opacity: .85; }
.mlp-rs-chat-code-apply.mlp-rs-applied { background: #1d4ed8; }
.mlp-rs-chat-code-copy { background: transparent; border-color: #3a3a3a; color: #888; }
.mlp-rs-chat-code-copy:hover { color: #d4d4d4; border-color: #555; }
.mlp-rs-chat-code-pre { margin:0; padding:10px 12px; overflow-x:auto; font-family:'JetBrains Mono','Fira Code','Consolas',monospace; font-size:.73rem; line-height:1.6; color:#d4d4d4; white-space:pre; background:transparent; }
.mlp-rs-chat-undo-btn { display:inline-flex; align-items:center; gap:4px; margin-top:4px; padding:2px 8px; background:transparent; border:1px solid #3a3a3a; border-radius:4px; color:#f59e0b; font-family:inherit; font-size:.65rem; font-weight:700; cursor:pointer; transition:opacity .15s; }
.mlp-rs-chat-undo-btn:hover { opacity:.8; }

/* ── Thinking bubble ─────────────────────────────────────────── */
.mlp-rs-thinking-bubble { display:flex; align-items:center; gap:10px; padding:10px 14px; background:#1a1410; border-radius:6px; border:1px solid rgba(232,99,42,.15); align-self:flex-start; max-width:95%; }
.mlp-rs-thinking-label { font-size:.68rem; color:#6b7280; font-style:italic; white-space:nowrap; }
@keyframes mlp-rs-dot-wave { 0%,100%{transform:translateY(0);opacity:.35;} 50%{transform:translateY(-6px);opacity:1;} }
@keyframes mlp-rs-dot-glow { 0%,100%{filter:drop-shadow(0 0 0px #e8632a);} 50%{filter:drop-shadow(0 0 5px #e8632a);} }
.mlp-rs-think-dot { animation: mlp-rs-dot-wave 1.3s ease-in-out infinite, mlp-rs-dot-glow 1.3s ease-in-out infinite; }
.mlp-rs-think-dot:nth-child(2) { animation-delay:.22s; }
.mlp-rs-think-dot:nth-child(3) { animation-delay:.44s; }
@keyframes mlp-rs-ring-pulse { 0%,100%{opacity:.18;r:14;} 50%{opacity:.45;r:16;} }
.mlp-rs-think-ring { animation:mlp-rs-ring-pulse 1.3s ease-in-out infinite; transform-origin:center; }

#mlp-rs-chat-overlay {
    position:fixed; inset:0; background:rgba(0,0,0,.3); z-index:999990;
    opacity:0; pointer-events:none; transition:opacity 0.25s cubic-bezier(0.4,0,0.2,1);
}
#mlp-rs-chat-overlay.mlp-rs-chat-open { opacity:1; pointer-events:auto; }

/* Hide HTML/CSS/JS chat when Rust editor is open */
html.mlp-rs-editor-active #mlpChatToggle,
html.mlp-rs-editor-active #mlpChatSidebar { display: none !important; }
/* Hide Python chat when Rust editor is open */
html.mlp-rs-editor-active #mlp-py-chat-fab,
html.mlp-rs-editor-active #mlp-py-chat-sidebar,
html.mlp-rs-editor-active #mlp-py-chat-overlay { display: none !important; }

/* ── Interactive Terminal Modal ──────────────────────────────── */
#mlp-rs-term-modal {
    position: absolute;
    inset: 0;
    z-index: 10;
    background: #080604;
    display: none;
    flex-direction: column;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
}
#mlp-rs-term-modal.mlp-rs-term-active { display: flex; }
#mlp-rs-term-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 14px;
    height: 36px;
    background: #1a1008;
    border-bottom: 1px solid #2e1f0d;
    flex-shrink: 0;
}
#mlp-rs-term-bar-title {
    flex: 1;
    font-size: .73rem;
    font-weight: 700;
    color: #6a8e6a;
    text-transform: uppercase;
    letter-spacing: .07em;
    display: flex;
    align-items: center;
    gap: 7px;
}
#mlp-rs-term-bar-title::before {
    content: '';
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #3dba6b;
    box-shadow: 0 0 6px #3dba6b;
    animation: mlp-rs-term-pulse 2s ease-in-out infinite;
}
@keyframes mlp-rs-term-pulse { 0%,100%{box-shadow:0 0 4px #3dba6b;} 50%{box-shadow:0 0 10px #3dba6b;} }
#mlp-rs-term-close {
    background: none;
    border: 1px solid #2e1f0d;
    color: #8a6e58;
    border-radius: 5px;
    padding: 3px 9px;
    font-family: inherit;
    font-size: .72rem;
    cursor: pointer;
    transition: border-color .15s, color .15s;
    flex-shrink: 0;
}
#mlp-rs-term-close:hover { border-color: #f87171; color: #f87171; }
#mlp-rs-term-body {
    flex: 1;
    overflow-y: auto;
    padding: 14px 18px 10px;
    display: flex;
    flex-direction: column;
}
#mlp-rs-term-body::-webkit-scrollbar { width: 5px; }
#mlp-rs-term-body::-webkit-scrollbar-thumb { background: #2e1f0d; border-radius: 3px; }
.mlp-rs-term-out {
    font-size: .82rem;
    line-height: 1.65;
    color: #d4d4d4;
    white-space: pre-wrap;
    word-break: break-word;
    min-height: 1.3em;
}
.mlp-rs-term-out.err  { color: #f87171; }
.mlp-rs-term-out.info { color: #60a5fa; font-style: italic; font-size: .73rem; }
.mlp-rs-term-out.ok   { color: #3dba6b; font-weight: 700; }
.mlp-rs-term-sep {
    font-size: .66rem;
    color: #3d2814;
    letter-spacing: .06em;
    margin: 10px 0 8px;
    border-top: 1px solid #1a0f07;
    padding-top: 8px;
    text-transform: uppercase;
}
.mlp-rs-term-prompt-row {
    display: flex;
    align-items: baseline;
    min-height: 1.65em;
}
.mlp-rs-term-prompt-label {
    font-size: .82rem;
    color: #d4d4d4;
    white-space: pre;
    flex-shrink: 0;
}
.mlp-rs-term-input {
    flex: 1;
    min-width: 60px;
    background: transparent;
    border: none;
    border-bottom: 1px dashed #3d2814;
    color: #3dba6b;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: .82rem;
    padding: 0 3px 1px;
    outline: none;
    caret-color: #3dba6b;
    transition: border-color .15s;
}
.mlp-rs-term-input:focus { border-bottom-color: #3dba6b; border-bottom-style: solid; }
.mlp-rs-term-input::placeholder { color: #2a1a0a; font-style: italic; }
#mlp-rs-term-footer {
    padding: 10px 16px 12px;
    border-top: 1px solid #1a0f07;
    display: none;
    align-items: center;
    gap: 12px;
    flex-shrink: 0;
    background: #0a0704;
}
#mlp-rs-term-runbtn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 18px;
    background: linear-gradient(135deg, #e8632a, #b84e1f);
    color: #fff;
    border: none;
    border-radius: 6px;
    font-family: inherit;
    font-size: .78rem;
    font-weight: 700;
    cursor: pointer;
    transition: opacity .15s;
    box-shadow: 0 1px 8px rgba(232,99,42,.35);
    flex-shrink: 0;
}
#mlp-rs-term-runbtn:hover:not(:disabled) { opacity: .88; }
#mlp-rs-term-runbtn:disabled { opacity: .45; cursor: not-allowed; }
#mlp-rs-term-hint {
    font-size: .67rem;
    color: #4a3020;
    font-style: italic;
    flex: 1;
}
#mlp-rs-term-result {
    margin-top: 10px;
    display: none;
}
/* Terminal button in topbar */
#mlp-rs-terminal-btn {
    background: transparent;
    border-color: var(--rs-border);
    color: var(--rs-muted);
}
#mlp-rs-terminal-btn:hover:not(:disabled) { border-color: #3dba6b; color: #3dba6b; }

/* ── Project card accent ─────────────────────────────────────── */
#mlp-projects-overlay .mlp-pcard-rust .mlp-pcard-thumb {
    background: linear-gradient(135deg, #1a0e05 0%, #2e1404 100%);
    border-bottom: 2px solid var(--rs-orange, #e8632a);
}
</style>
        <?php
    }

    public static function output_editor() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) {
            return;
        }
        ?>
<!-- Rust Editor Overlay -->
<div id="mlp-rust-overlay" role="dialog" aria-modal="true" aria-label="Rust Editor">
  <!-- Topbar -->
  <div id="mlp-rs-topbar">
    <button id="mlp-rs-back" type="button" aria-label="Back to projects">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      Projects
    </button>
    <div id="mlp-rs-title">
      <span id="mlp-rs-name">Untitled</span>
      <span class="rs-lang-badge">
        <svg width="10" height="10" viewBox="0 0 106 106" fill="none"><circle cx="53" cy="53" r="53" fill="#e8632a"/><rect x="33" y="33" width="18" height="40" rx="4" fill="#fff"/><rect x="33" y="43" width="40" height="8" rx="2" fill="#fff"/><circle cx="71" cy="67" r="8" fill="#fff" stroke="#e8632a" stroke-width="4"/></svg>
        Rust
      </span>
    </div>
    <button id="mlp-rs-fullscreen-btn" type="button" title="Toggle fullscreen (Ctrl+Shift+F)">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
    </button>
    <button id="mlp-rs-run" class="mlp-rs-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
      Run
    </button>
    <button id="mlp-rs-check" class="mlp-rs-btn" type="button" title="Check (cargo check equivalent — type-check only, no output)">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
      Check
    </button>
    <button id="mlp-rs-save" class="mlp-rs-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
      Save
    </button>
    <button id="mlp-rs-export" class="mlp-rs-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Export .rs
    </button>
    <button id="mlp-rs-terminal-btn" class="mlp-rs-btn" type="button" title="Interactive terminal — answer prompts one by one">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
      Terminal
    </button>
  </div>

  <!-- Tabbar -->
  <div id="mlp-rs-tabbar">
    <button class="mlp-rs-tab mlp-rs-tab-active" data-tab="main" type="button">
      <span style="width:7px;height:7px;border-radius:50%;background:#e8632a;display:inline-block;"></span>
      main.rs
    </button>
    <button id="mlp-rs-format" class="mlp-rs-btn" type="button" title="Format code (rustfmt)" style="margin-left:8px;">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="21" y1="6" x2="3" y2="6"/><line x1="15" y1="12" x2="3" y2="12"/><line x1="17" y1="18" x2="3" y2="18"/></svg>
      Format
    </button>
    <button id="mlp-rs-copy-code" class="mlp-rs-btn" type="button" title="Copy code to clipboard" style="margin-left:6px;">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      Copy
    </button>
  </div>

  <!-- Main split: editor + output -->
  <div id="mlp-rs-main">
    <div id="mlp-rs-editor-wrap">
      <div id="mlp-rs-editor"></div>
    </div>
    <div id="mlp-rs-resizer" role="separator" aria-orientation="vertical" aria-label="Resize panels"></div>
    <div id="mlp-rs-output-wrap">
      <div id="mlp-rs-output-header">
        <div id="mlp-rs-output-title">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline;margin-right:4px;vertical-align:middle;"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          Output
        </div>
        <button id="mlp-rs-clear-btn" type="button" title="Clear output">Clear</button>
      </div>
      <div id="mlp-rs-output" aria-live="polite" aria-label="Rust output"></div>
      <!-- Stdin panel -->
      <div id="mlp-rs-stdin-wrap">
        <div id="mlp-rs-stdin-header" role="button" tabindex="0" aria-expanded="false" title="Provide program input (stdin) before running">
          <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;color:var(--rs-muted)"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>
          <span id="mlp-rs-stdin-label">Stdin (program input)</span>
          <svg id="mlp-rs-stdin-chevron" width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
        </div>
        <div id="mlp-rs-stdin-body">
          <textarea id="mlp-rs-stdin" placeholder="Type program input here (one value per line)…" spellcheck="false" autocomplete="off"></textarea>
          <div id="mlp-rs-stdin-actions">
            <button id="mlp-rs-stdin-run" class="mlp-rs-btn" type="button">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
              Run
            </button>
          </div>
          <div id="mlp-rs-stdin-hint">Sent as stdin when you click Run. Use for programs that call <code style="color:var(--rs-orange);font-size:.6rem;">read_line()</code> or <code style="color:var(--rs-orange);font-size:.6rem;">stdin()</code>.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Interactive Terminal Modal -->
  <div id="mlp-rs-term-modal" role="dialog" aria-modal="true" aria-label="Interactive Terminal">
    <div id="mlp-rs-term-bar">
      <div id="mlp-rs-term-bar-title">Terminal — Interactive Input</div>
      <button id="mlp-rs-term-close" type="button" title="Close terminal">✕ Close</button>
    </div>
    <div id="mlp-rs-term-body"></div>
    <div id="mlp-rs-term-result"></div>
    <div id="mlp-rs-term-footer">
      <button id="mlp-rs-term-runbtn" type="button">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
        Run Program
      </button>
      <span id="mlp-rs-term-hint">Enter answers above, then click Run Program</span>
    </div>
  </div>

  <!-- Status bar -->
  <div id="mlp-rs-statusbar">
    <span id="mlp-rs-status-lang">
      <svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>
      Rust (stable)
    </span>
    <span id="mlp-rs-status-msg"></span>
    <span id="mlp-rs-status-pos">Ln 1, Col 1</span>
    <span id="mlp-rs-status-save"></span>
  </div>
</div>

<!-- Rust AI Chat Sidebar -->
<div id="mlp-rs-chat-overlay"></div>
<div id="mlp-rs-chat-sidebar">
  <div id="mlp-rs-chat-header">
    <div id="mlp-rs-chat-title">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      Rust AI Assistant
    </div>
    <button id="mlp-rs-chat-close" type="button" title="Close chat">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>
  <div id="mlp-rs-chat-messages">
    <div class="mlp-rs-chat-empty">Ask the Rust AI assistant about your code — ownership, lifetimes, traits, performance, and more.</div>
  </div>
  <div id="mlp-rs-chat-input-area">
    <textarea id="mlp-rs-chat-input" placeholder="Ask about your Rust code..." rows="2"></textarea>
    <button id="mlp-rs-chat-send" type="button">Send</button>
  </div>
</div>

<!-- Toast -->
<div id="mlp-rs-toast"></div>

<!-- Floating AI Chat Button -->
<button id="mlp-rs-chat-fab" class="mlp-rs-fab-hidden" type="button" title="Open Rust AI Chat" aria-label="Open Rust AI Chat">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
  Rust AI
</button>

<script>
(function(){
'use strict';

/* ── Helpers ─────────────────────────────────────────────────── */
function $id(id) { return document.getElementById(id); }

var MLP_RS_LS  = 'mlp_projects';
var MLP_TS_SITEKEY = <?php echo json_encode( defined( 'MLP_TURNSTILE_SITE_KEY' ) ? MLP_TURNSTILE_SITE_KEY : '' ); ?>;

var rsEditor     = null;
var monacoReady  = false;
var _activeId    = null;
var _unsaved     = false;
var running      = false;
var _rustChannel = 'stable';

/* ── LocalStorage helpers ────────────────────────────────────── */
function getProjects() {
    try { return JSON.parse(localStorage.getItem(MLP_RS_LS)) || []; } catch(e) { return []; }
}
function getProject(id) {
    return getProjects().find(function(p){ return p.id === id; }) || null;
}
function updateProject(id, data) {
    var all = getProjects();
    var idx = all.findIndex(function(p){ return p.id === id; });
    if (idx === -1) return;
    all[idx] = Object.assign({}, all[idx], data);
    localStorage.setItem(MLP_RS_LS, JSON.stringify(all));
}

/* ── Output helpers ──────────────────────────────────────────── */
function appendOutput(text, cls) {
    var outEl = $id('mlp-rs-output');
    if (!outEl) return;
    var span = document.createElement('span');
    span.className = 'mlp-rs-out-line' + (cls ? ' ' + cls : '');
    span.textContent = text;
    outEl.appendChild(span);
    outEl.scrollTop = outEl.scrollHeight;
}
function clearOutput() {
    var outEl = $id('mlp-rs-output');
    if (outEl) outEl.innerHTML = '';
}
function setStatus(msg) {
    var el = $id('mlp-rs-status-msg');
    if (el) el.textContent = msg;
}
function setSave(msg) {
    var el = $id('mlp-rs-status-save');
    if (el) el.textContent = msg;
}

/* ── Toast ───────────────────────────────────────────────────── */
var _rsToastTimer = null;
function rsToast(msg, type, ms) {
    var el = $id('mlp-rs-toast');
    if (!el) return;
    el.textContent = msg;
    el.className = 'mlp-rs-show' + (type === 'err' ? ' mlp-rs-err' : type === 'succ' ? ' mlp-rs-succ' : '');
    clearTimeout(_rsToastTimer);
    _rsToastTimer = setTimeout(function(){ el.className = ''; }, ms || 2200);
}

/* ── Format via Rust Playground ──────────────────────────────── */
function formatCode() {
    if (running) return;
    var code = rsEditor ? rsEditor.getValue() : '';
    if (!code.trim()) { rsToast('Nothing to format', '', 1500); return; }
    var formatBtn = $id('mlp-rs-format');
    if (formatBtn) { formatBtn.disabled = true; formatBtn.textContent = 'Formatting…'; }
    fetch('https://play.rust-lang.org/format', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ channel: _rustChannel || 'stable', edition: '2021', code: code })
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
        if (data.code && !data.error) {
            var prev = rsEditor.getValue();
            if (data.code !== prev) {
                rsEditor.setValue(data.code);
                rsEditor.setScrollPosition({ scrollTop: rsEditor.getScrollTop() });
                _unsaved = true; setSave('● Unsaved');
                rsToast('Code formatted', 'succ', 1800);
            } else {
                rsToast('Already formatted', '', 1800);
            }
        } else {
            rsToast('Format failed: ' + (data.error || 'unknown error'), 'err', 2500);
        }
    })
    .catch(function() { rsToast('Network error — could not reach play.rust-lang.org', 'err', 2500); })
    .finally(function() {
        if (formatBtn) {
            formatBtn.disabled = false;
            formatBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="21" y1="6" x2="3" y2="6"/><line x1="15" y1="12" x2="3" y2="12"/><line x1="17" y1="18" x2="3" y2="18"/></svg> Format';
        }
    });
}

/* ── Copy code to clipboard ──────────────────────────────────── */
function copyCode() {
    var code = rsEditor ? rsEditor.getValue() : '';
    if (!code.trim()) { rsToast('Nothing to copy', '', 1500); return; }
    var copyBtn = $id('mlp-rs-copy-code');
    navigator.clipboard.writeText(code).then(function() {
        rsToast('Code copied to clipboard', 'succ', 1800);
        if (copyBtn) {
            copyBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Copied!';
            setTimeout(function() {
                copyBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy';
            }, 2000);
        }
    }).catch(function() { rsToast('Copy failed — clipboard unavailable', 'err', 2200); });
}

/* ── Detect stdin usage in code ──────────────────────────────── */
function _hasStdinUsage(code) {
    return /read_line\s*\(|io::stdin|std::io::stdin|BufRead|\.lines\(\)|stdin\(\)/.test(code);
}

/* ── Inject stdin shim into Rust code ────────────────────────────
 *
 *  The Rust Playground API silently ignores the `stdin` field.
 *  To work around this we embed the stdin data as a static string
 *  in the code and replace io::stdin() calls with a shim that
 *  reads from it.  This lets programs like flashcard games work
 *  correctly with pre-supplied answers.
 * ─────────────────────────────────────────────────────────────── */
function _injectStdinShim(code, stdinVal) {
    /* Escape the stdin string for embedding in a Rust raw string.
       We use a raw string r#"..."# so we don't need to escape most chars. */
    var safeData = stdinVal.replace(/#/g, '__HASH__'); /* avoid breaking r#"..."# */

    var shim = [
        '/* ── MLP stdin shim ── */',
        'mod __mlp_stdin {',
        '    use std::sync::atomic::{AtomicUsize, Ordering};',
        '    const DATA: &str = concat!(' + JSON.stringify(stdinVal) + ', "\\n");',
        '    static POS: AtomicUsize = AtomicUsize::new(0);',
        '    pub fn read_line(buf: &mut String) -> std::io::Result<usize> {',
        '        let pos = POS.load(Ordering::Relaxed);',
        '        let remaining = &DATA[pos..];',
        '        if remaining.is_empty() { return Ok(0); }',
        '        let end = remaining.find(\'\\n\').map(|i| i + 1).unwrap_or(remaining.len());',
        '        buf.push_str(&remaining[..end]);',
        '        POS.store(pos + end, Ordering::Relaxed);',
        '        Ok(end)',
        '    }',
        '    pub fn read_to_string(buf: &mut String) -> std::io::Result<usize> {',
        '        let pos = POS.load(Ordering::Relaxed);',
        '        let remaining = &DATA[pos..];',
        '        buf.push_str(remaining);',
        '        POS.store(DATA.len(), Ordering::Relaxed);',
        '        Ok(remaining.len())',
        '    }',
        '}',
        'macro_rules! __mlp_read_line {',
        '    ($buf:expr) => { __mlp_stdin::read_line($buf) };',
        '}',
        '/* ── end MLP stdin shim ── */',
        '',
    ].join('\n');

    /* Replace io::stdin().read_line(X)  →  __mlp_stdin::read_line(X)
       Replace io::stdin().read_to_string(X) → __mlp_stdin::read_to_string(X)
       This covers the most common patterns. */
    var transformed = code
        .replace(/\bio::stdin\s*\(\)\s*\.\s*read_to_string\s*\(/g, '__mlp_stdin::read_to_string(')
        .replace(/\bio::stdin\s*\(\)\s*\.\s*read_line\s*\(/g,      '__mlp_stdin::read_line(')
        .replace(/\bstd::io::stdin\s*\(\)\s*\.\s*read_to_string\s*\(/g, '__mlp_stdin::read_to_string(')
        .replace(/\bstd::io::stdin\s*\(\)\s*\.\s*read_line\s*\(/g,      '__mlp_stdin::read_line(');

    return shim + transformed;
}

/* ── Run via Rust Playground API (client-side fetch) ─────────── */
function runCode() {
    if (running) return;
    var code = rsEditor ? rsEditor.getValue() : '';
    if (!code.trim()) { rsToast('Nothing to run', '', 1500); return; }

    var edition = '2021';
    var channel = _rustChannel || 'stable';

    var stdinEl  = $id('mlp-rs-stdin');
    var stdinVal = stdinEl ? stdinEl.value : '';

    /* If stdin data is provided and the code reads from stdin,
       embed the data directly into the code via the shim.
       The Rust Playground API does not reliably pass `stdin` to
       the compiled binary, so this is the correct workaround. */
    var finalCode = (stdinVal.trim() && _hasStdinUsage(code))
        ? _injectStdinShim(code, stdinVal)
        : code;

    /* Track whether we need to prompt for stdin after showing output */
    var _needsStdinHint = _hasStdinUsage(code) && !stdinVal.trim();

    running = true;
    setRunBtnState(true);
    clearOutput();
    appendOutput('▶ Run  ' + new Date().toLocaleTimeString() + '  ' + channel, 'mlp-rs-out-sep');
    if (stdinVal.trim() && _hasStdinUsage(code)) {
        appendOutput('stdin: ' + stdinVal.trim().split('\n').length + ' line(s) embedded', 'mlp-rs-out-info');
    }
    setStatus('Compiling…');

    var t0 = Date.now();

    fetch('https://play.rust-lang.org/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            channel:   channel,
            mode:      'debug',
            edition:   edition,
            code:      finalCode,
            crateType: 'bin',
            tests:     false,
            stdin:     stdinVal
        })
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
        var ms = Date.now() - t0;
        var ansiRe = /\x1b\[[0-9;?]*[A-Za-z]/g;
        var out    = (data.stdout || '').replace(ansiRe, '').trimEnd();
        var stderr = (data.stderr || '').replace(ansiRe, '').trimEnd();
        var errMsg = data.error || '';
        var ok     = !errMsg && !/(?:^|\n)error(\[E\d+\])?[:\[]/.test(stderr);

        /* ── 640K / stdout-overflow ── */
        if (!ok && /640K|Generated \d+ bytes|copy child stdout|stdio task failed/i.test(errMsg)) {
            appendOutput('output limit hit', 'mlp-rs-out-sep');
            appendOutput('Program produced too much output — likely looping on empty stdin.', 'mlp-rs-out-warn');
            appendOutput('Fill the Stdin panel ↓ with your answers and run again.', 'mlp-rs-out-info');
            if (_hasStdinUsage(code)) {
                var sh2 = $id('mlp-rs-stdin-header'), sb2 = $id('mlp-rs-stdin-body');
                if (sb2 && !sb2.classList.contains('mlp-rs-stdin-open')) {
                    sb2.classList.add('mlp-rs-stdin-open');
                    if (sh2) { sh2.classList.add('mlp-rs-stdin-open'); sh2.setAttribute('aria-expanded','true'); }
                }
                var se2 = $id('mlp-rs-stdin'); if (se2) setTimeout(function(){ se2.focus(); }, 80);
            }
            appendOutput('', '');
            appendOutput('✗  Run failed · ' + ms + 'ms', 'mlp-rs-out-badge-err');
            setStatus('Output limit — check stdin');
            return;
        }

        if (out)    appendOutput(out, '');
        if (stderr) _renderRustDiagnostics(stderr);

        if (ok) {
            if (!out && !stderr) appendOutput('(no output)', 'mlp-rs-out-timing');

            /* If stdin was empty but the program reads input, open the panel
               so the user can see the prompts above and fill in answers */
            if (_needsStdinHint) {
                appendOutput('', '');
                appendOutput('↑ Program printed its questions above.', 'mlp-rs-out-info');
                appendOutput('Fill in the Stdin panel ↓ with your answers, then Run again.', 'mlp-rs-out-info');
                var _sh = $id('mlp-rs-stdin-header'), _sb = $id('mlp-rs-stdin-body');
                if (_sb && !_sb.classList.contains('mlp-rs-stdin-open')) {
                    _sb.classList.add('mlp-rs-stdin-open');
                    if (_sh) { _sh.classList.add('mlp-rs-stdin-open'); _sh.setAttribute('aria-expanded','true'); }
                }
                if (stdinEl) setTimeout(function(){ stdinEl.focus(); }, 80);
            }

            appendOutput('', '');
            appendOutput('✓  Done · ' + ms + 'ms', 'mlp-rs-out-badge-ok');
            setStatus('Done · ' + ms + 'ms');
        } else {
            if (!out && !stderr) appendOutput(errMsg || 'Unknown error', 'mlp-rs-out-err');
            appendOutput('', '');
            appendOutput('✗  Build failed · ' + ms + 'ms', 'mlp-rs-out-badge-err');
            setStatus('Build failed');
        }
    })
    .catch(function(err) {
        appendOutput('Network error — could not reach play.rust-lang.org\n' + (err && err.message ? err.message : String(err)), 'mlp-rs-out-err');
        setStatus('Network error');
    })
    .finally(function() {
        running = false;
        setRunBtnState(false);
    });
}

/* ── Check-only (no execution) ───────────────────────────────── */
function checkCode() {
    if (running) return;
    var code = rsEditor ? rsEditor.getValue() : '';
    if (!code.trim()) { rsToast('Nothing to check', '', 1500); return; }

    var edition = '2021';
    var channel = _rustChannel || 'stable';

    running = true;
    setRunBtnState(true);
    clearOutput();
    appendOutput('✔ Check  ' + new Date().toLocaleTimeString() + '  ' + channel, 'mlp-rs-out-sep');
    setStatus('Checking…');

    var t0 = Date.now();

    fetch('https://play.rust-lang.org/compile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            channel:   channel,
            mode:      'debug',
            edition:   edition,
            code:      code,
            crateType: 'bin',
            tests:     false,
            target:    'mir'
        })
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
        var ms     = Date.now() - t0;
        var ansiRe = /\x1b\[[0-9;?]*[A-Za-z]/g;
        var stderr = (data.stderr || '').replace(ansiRe, '').trimEnd();
        var ok     = !data.error && !/(?:^|\n)error(\[E\d+\])?[:\[]/.test(stderr);
        var hasWarn = /(?:^|\n)warning(\[|:)/.test(stderr);

        if (stderr) _renderRustDiagnostics(stderr);
        appendOutput('', '');
        if (ok) {
            if (!hasWarn) appendOutput('No errors or warnings.', 'mlp-rs-out-timing');
            appendOutput('✓  Check passed · ' + ms + 'ms', 'mlp-rs-out-badge-ok');
            setStatus('Check passed · ' + ms + 'ms');
        } else {
            appendOutput('✗  Check failed · ' + ms + 'ms', 'mlp-rs-out-badge-err');
            setStatus('Check failed');
        }
    })
    .catch(function(err) {
        appendOutput('Network error: ' + (err && err.message ? err.message : String(err)), 'mlp-rs-out-err');
        setStatus('Network error');
    })
    .finally(function() {
        running = false;
        setRunBtnState(false);
    });
}

/* ── Rust diagnostics coloriser ──────────────────────────────── */
var _RS_NOISE = /^\s*(Compiling|Finished|Running|Downloading|Downloaded|Updating|Locking|Blocking|Fetching|Resolving|Unpacking)\s/;
var _RS_SUMMARY = /^error: aborting due to|^error: could not compile/;
function _renderRustDiagnostics(stderr) {
    var lines = stderr.split('\n');
    var prevWasBlank = false;
    lines.forEach(function(line) {
        if (_RS_NOISE.test(line))   return;
        if (_RS_SUMMARY.test(line)) return;
        /* collapse multiple blank lines into one */
        if (!line.trim()) {
            if (prevWasBlank) return;
            prevWasBlank = true;
        } else {
            prevWasBlank = false;
        }
        var cls = '';
        if (/^error(\[E\d+\])?[:\[]/.test(line)) {
            cls = 'mlp-rs-out-err';
        } else if (/^\s+[\^~]+/.test(line)) {
            cls = 'mlp-rs-out-err';
        } else if (/^warning(\[|\s*:)/.test(line)) {
            cls = 'mlp-rs-out-warn';
        } else if (/^note\s*:/.test(line) || /^help\s*:/.test(line)) {
            cls = 'mlp-rs-out-note';
        } else if (/^\s+-->\s/.test(line) || /^\s+\|\s/.test(line) || /^\s+=\s/.test(line)) {
            cls = 'mlp-rs-out-info';
        }
        appendOutput(line, cls);
    });
}

function setRunBtnState(isRunning) {
    var runBtn      = $id('mlp-rs-run');
    var stdinRunBtn = $id('mlp-rs-stdin-run');
    var checkBtn    = $id('mlp-rs-check');
    var runningHTML = '<span class="mlp-rs-spinner"></span> Running…';
    var idleHTML    = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run';
    if (runBtn) {
        runBtn.innerHTML = isRunning ? runningHTML : idleHTML;
        runBtn.disabled  = isRunning;
    }
    if (stdinRunBtn) {
        stdinRunBtn.innerHTML = isRunning ? runningHTML : '<svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run';
        stdinRunBtn.disabled  = isRunning;
    }
    if (checkBtn) { checkBtn.disabled = isRunning; }
}

/* ── Save ────────────────────────────────────────────────────── */
function saveProject() {
    if (!_activeId) { rsToast('Nothing to save — open a project first', '', 2000); return; }
    var code = rsEditor ? rsEditor.getValue() : '';
    var now  = Date.now();
    updateProject(_activeId, { rust: code, type: 'rust', updated: now });
    _unsaved = false;
    var timeStr = new Date(now).toLocaleTimeString();
    setSave('✓ Saved ' + timeStr);
    /* flash the status-bar save label */
    var saveEl = $id('mlp-rs-status-save');
    if (saveEl) {
        saveEl.classList.remove('mlp-rs-saved-flash');
        void saveEl.offsetWidth; /* reflow to restart animation */
        saveEl.classList.add('mlp-rs-saved-flash');
    }
    rsToast('✓ Saved — ' + timeStr, 'succ', 2200);
}

/* ── Export ──────────────────────────────────────────────────── */
function exportProject() {
    var code = rsEditor ? rsEditor.getValue() : '';
    var p    = _activeId ? getProject(_activeId) : null;
    var name = (p && p.name) ? p.name.replace(/[^a-z0-9_\-]/gi, '_') : 'rust_project';
    var blob = new Blob([code], { type: 'text/x-rustsrc' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a');
    a.href   = url; a.download = name + '.rs';
    document.body.appendChild(a); a.click();
    setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(url); }, 500);
    rsToast('Exported ' + name + '.rs', 'succ', 2200);
}

/* ── Open / Close overlay ────────────────────────────────────── */
function openRustEditor(projectId) {
    var p = getProject(projectId);
    if (!p || p.type !== 'rust') return;
    _activeId = projectId;
    _unsaved  = false;

    _rustChannel = (p.rustChannel && ['stable','beta','nightly'].indexOf(p.rustChannel) !== -1) ? p.rustChannel : 'stable';

    var nameEl = $id('mlp-rs-name');
    if (nameEl) nameEl.textContent = p.name || 'Untitled';

    /* Update badge and status bar to show active channel */
    var badgeEl = document.querySelector('#mlp-rs-title .rs-lang-badge');
    if (badgeEl) {
        var channelLabel = _rustChannel === 'stable' ? 'Rust' : 'Rust · ' + _rustChannel.charAt(0).toUpperCase() + _rustChannel.slice(1);
        badgeEl.innerHTML = '<svg width="10" height="10" viewBox="0 0 106 106" fill="none"><circle cx="53" cy="53" r="53" fill="#e8632a"/><rect x="33" y="33" width="18" height="40" rx="4" fill="#fff"/><rect x="33" y="43" width="40" height="8" rx="2" fill="#fff"/><circle cx="71" cy="67" r="8" fill="#fff" stroke="#e8632a" stroke-width="4"/></svg> ' + channelLabel;
    }
    var statusLangEl = $id('mlp-rs-status-lang');
    if (statusLangEl) {
        statusLangEl.innerHTML = '<svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg> Rust (' + _rustChannel + ')';
    }

    var overlay = $id('mlp-rust-overlay');
    if (overlay) overlay.classList.add('mlp-rs-active');

    document.documentElement.classList.add('mlp-rs-editor-active');

    setSave(''); setStatus('Ready');
    clearOutput();
    appendOutput('Rust Playground  ·  ▶ Run (Ctrl+Enter)  ·  Ctrl+S to save', 'mlp-rs-out-info');

    if (monacoReady && window.monaco) {
        if (!rsEditor) {
            mountMonaco(p.rust || '');
        } else {
            rsEditor.setValue(p.rust || '');
            rsEditor.setScrollPosition({ scrollTop: 0 });
        }
    } else {
        waitForMonacoThenMount(p.rust || '');
    }

    /* Wire FAB */
    var chatFab = $id('mlp-rs-chat-fab');
    if (chatFab) {
        chatFab.classList.remove('mlp-rs-fab-hidden');
        if (!chatFab._rsWired) {
            chatFab.addEventListener('click', _openRsChat);
            chatFab._rsWired = true;
        }
    }

    /* Wire chat panel controls */
    var chatClose   = $id('mlp-rs-chat-close');
    var chatSend    = $id('mlp-rs-chat-send');
    var chatInput   = $id('mlp-rs-chat-input');
    var chatOverlay = $id('mlp-rs-chat-overlay');

    if (chatClose   && !chatClose._rsWired)   { chatClose.addEventListener('click',  _closeRsChat); chatClose._rsWired = true; }
    if (chatSend    && !chatSend._rsWired)     { chatSend.addEventListener('click',   _sendRsChat);  chatSend._rsWired = true; }
    if (chatOverlay && !chatOverlay._rsWired)  { chatOverlay.addEventListener('click', _closeRsChat); chatOverlay._rsWired = true; }
    if (chatInput   && !chatInput._rsWired) {
        chatInput.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); _sendRsChat(); }
        });
        chatInput._rsWired = true;
    }
}

function closeRustEditor() {
    if (_unsaved) {
        if (!confirm('You have unsaved changes. Leave without saving?')) return;
    }
    var overlay = $id('mlp-rust-overlay');
    if (overlay) overlay.classList.remove('mlp-rs-active');

    _closeRsChat();
    var chatFab = $id('mlp-rs-chat-fab');
    if (chatFab) chatFab.classList.add('mlp-rs-fab-hidden');

    document.documentElement.classList.remove('mlp-rs-editor-active');
    _activeId = null; running = false;

    if (typeof window.mlpProjectsOpen === 'function') {
        window.mlpProjectsOpen();
    } else {
        var projOverlay = document.getElementById('mlp-projects-overlay');
        if (projOverlay) {
            projOverlay.classList.remove('mlp-proj-hidden');
            projOverlay.style.display = '';
            document.body.style.overflow = 'hidden';
        }
    }
}

/* ── Monaco ──────────────────────────────────────────────────── */
function mountMonaco(initialCode) {
    if (!window.monaco) return;
    var container = $id('mlp-rs-editor');
    if (!container) return;
    if (rsEditor) { rsEditor.setValue(initialCode); return; }

    rsEditor = window.monaco.editor.create(container, {
        value:    initialCode,
        language: 'rust',
        theme:    'vs-dark',
        fontSize: 14,
        lineHeight: 22,
        fontFamily: "'JetBrains Mono','Fira Code','Consolas',monospace",
        minimap:  { enabled: false },
        scrollBeyondLastLine: false,
        automaticLayout: true,
        wordWrap: 'off',
        renderLineHighlight: 'line',
        cursorBlinking: 'smooth',
        smoothScrolling: true,
        folding: true,
        renderWhitespace: 'selection',
        bracketPairColorization: { enabled: true },
        suggestOnTriggerCharacters: true,
        quickSuggestions: { other: true, comments: false, strings: false },
        parameterHints: { enabled: true },
        padding: { top: 10, bottom: 10 },
    });

    rsEditor.onDidChangeCursorPosition(function(e) {
        var el = $id('mlp-rs-status-pos');
        if (el) el.textContent = 'Ln ' + e.position.lineNumber + ', Col ' + e.position.column;
    });
    rsEditor.onDidChangeModelContent(function() { _unsaved = true; setSave('● Unsaved'); });

    rsEditor.addCommand(window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.Enter, runCode);
    rsEditor.addCommand(window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.KeyS, function(){ saveProject(); });
}

function waitForMonacoThenMount(code) {
    var tries = 0;
    var timer = setInterval(function() {
        if (window.monaco) { clearInterval(timer); monacoReady = true; mountMonaco(code); return; }
        if (++tries > 60) clearInterval(timer);
    }, 200);
}

/* ── Resizer drag ────────────────────────────────────────────── */
(function() {
    var resizer = $id('mlp-rs-resizer');
    var main    = $id('mlp-rs-main');
    var outWrap = $id('mlp-rs-output-wrap');
    if (!resizer || !main || !outWrap) return;
    var dragging = false, startX = 0, startW = 0;
    resizer.addEventListener('mousedown', function(e) {
        dragging = true; startX = e.clientX;
        startW = outWrap.getBoundingClientRect().width;
        resizer.classList.add('mlp-rs-dragging');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault();
    });
    document.addEventListener('mousemove', function(e) {
        if (!dragging) return;
        var dx = startX - e.clientX;
        var mainW = main.getBoundingClientRect().width;
        var newW = Math.max(220, Math.min(mainW * 0.70, startW + dx));
        outWrap.style.width = newW + 'px';
    });
    document.addEventListener('mouseup', function() {
        if (!dragging) return;
        dragging = false;
        resizer.classList.remove('mlp-rs-dragging');
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        if (rsEditor) rsEditor.layout();
    });
})();

/* ── Fullscreen toggle ───────────────────────────────────────── */
function toggleFullscreen() {
    var overlay = $id('mlp-rust-overlay');
    if (!overlay) return;
    var isFs = overlay.classList.toggle('mlp-rs-fullscreen');
    var btn = $id('mlp-rs-fullscreen-btn');
    if (btn) {
        btn.title = isFs ? 'Exit fullscreen (Ctrl+Shift+F)' : 'Toggle fullscreen (Ctrl+Shift+F)';
        btn.innerHTML = isFs
            ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="10" y1="14" x2="3" y2="21"/><line x1="21" y1="3" x2="14" y2="10"/></svg>'
            : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>';
    }
    if (rsEditor) setTimeout(function(){ rsEditor.layout(); }, 50);
}

/* ── Wire buttons ────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
    var runBtn    = $id('mlp-rs-run');
    var checkBtn  = $id('mlp-rs-check');
    var saveBtn   = $id('mlp-rs-save');
    var exportBtn = $id('mlp-rs-export');
    var fsBtn     = $id('mlp-rs-fullscreen-btn');
    var backBtn   = $id('mlp-rs-back');
    var clearBtn  = $id('mlp-rs-clear-btn');

    var formatBtn   = $id('mlp-rs-format');
    var copyCodeBtn = $id('mlp-rs-copy-code');
    var termBtn     = $id('mlp-rs-terminal-btn');
    var termClose   = $id('mlp-rs-term-close');
    var termRunBtn  = $id('mlp-rs-term-runbtn');

    var stdinRunBtn = $id('mlp-rs-stdin-run');

    if (runBtn)      runBtn.addEventListener('click',      runCode);
    if (stdinRunBtn) stdinRunBtn.addEventListener('click', runCode);
    if (checkBtn)    checkBtn.addEventListener('click',    checkCode);
    if (saveBtn)     saveBtn.addEventListener('click',     saveProject);
    if (exportBtn)   exportBtn.addEventListener('click',   exportProject);
    if (formatBtn)   formatBtn.addEventListener('click',   formatCode);
    if (copyCodeBtn) copyCodeBtn.addEventListener('click', copyCode);
    if (backBtn)     backBtn.addEventListener('click',     closeRustEditor);
    if (clearBtn)    clearBtn.addEventListener('click',    clearOutput);
    if (fsBtn)       fsBtn.addEventListener('click',       toggleFullscreen);
    if (termBtn)     termBtn.addEventListener('click',     openTerminalMode);
    if (termClose)   termClose.addEventListener('click',   _closeTermModal);
    if (termRunBtn)  termRunBtn.addEventListener('click',  _runTerminalProgram);

    /* ── Stdin panel toggle ──────────────────────────────────── */
    var stdinHeader = $id('mlp-rs-stdin-header');
    var stdinBody   = $id('mlp-rs-stdin-body');
    function _toggleStdin() {
        if (!stdinHeader || !stdinBody) return;
        var open = stdinBody.classList.toggle('mlp-rs-stdin-open');
        stdinHeader.classList.toggle('mlp-rs-stdin-open', open);
        stdinHeader.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    if (stdinHeader) {
        stdinHeader.addEventListener('click', _toggleStdin);
        stdinHeader.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); _toggleStdin(); }
        });
    }

    document.addEventListener('keydown', function(e) {
        var overlay = $id('mlp-rust-overlay');
        if (!overlay || !overlay.classList.contains('mlp-rs-active')) return;
        if (e.key === 'Escape') {
            e.preventDefault();
            if (overlay.classList.contains('mlp-rs-fullscreen')) { toggleFullscreen(); }
            else { closeRustEditor(); }
        }
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'F' || e.key === 'f')) {
            e.preventDefault(); toggleFullscreen();
        }
    });
});

/* ══════════════════════════════════════════════════════════════
   ── Interactive Terminal Mode ─────────────────────────────────
   ══════════════════════════════════════════════════════════════ */

var _termCode = '';

function _countStdinCalls(code) {
    var m = code.match(/\.read_line\s*\(|io::stdin\s*\(\)\s*(?:\.\s*lock\s*\(\))?\s*\.\s*read_line|stdin\s*\(\)\s*\.\s*read_line/g);
    return m ? m.length : 0;
}

function _detectPrompts(stdout) {
    var lines = stdout.split('\n');
    return lines.map(function(line) {
        var t = line.trimEnd();
        var isPrompt = t.length > 0 && /[:\?>\u2192\u25b8]\s*$/.test(t);
        return { text: line, isPrompt: isPrompt };
    });
}

function _openTermModal() {
    var modal = $id('mlp-rs-term-modal');
    if (modal) modal.classList.add('mlp-rs-term-active');
}
function _closeTermModal() {
    var modal = $id('mlp-rs-term-modal');
    if (modal) modal.classList.remove('mlp-rs-term-active');
}
function _termAppend(text, cls) {
    var body = $id('mlp-rs-term-body');
    if (!body) return;
    var div = document.createElement('div');
    div.className = 'mlp-rs-term-out' + (cls ? ' ' + cls : '');
    div.textContent = text;
    body.appendChild(div);
    body.scrollTop = body.scrollHeight;
}
function _termClearBody() {
    var body = $id('mlp-rs-term-body');
    if (body) body.innerHTML = '';
    var result = $id('mlp-rs-term-result');
    if (result) { result.style.display = 'none'; result.innerHTML = ''; }
    var footer = $id('mlp-rs-term-footer');
    if (footer) footer.style.display = 'none';
}

function _buildTermInputs(stdout, inputCount) {
    var body = $id('mlp-rs-term-body');
    if (!body) return;

    var analyzed = _detectPrompts(stdout || '');
    var promptLines = analyzed.filter(function(l) { return l.isPrompt; });
    var useMapping  = promptLines.length >= inputCount && inputCount > 0;
    var promptIdx   = 0;

    function makeInput(idx, afterPrompt) {
        var row = document.createElement('div');
        row.className = 'mlp-rs-term-prompt-row';
        if (!afterPrompt) {
            var lbl = document.createElement('span');
            lbl.className = 'mlp-rs-term-prompt-label';
            lbl.textContent = '> ';
            row.appendChild(lbl);
        }
        var inp = document.createElement('input');
        inp.type = 'text';
        inp.className = 'mlp-rs-term-input';
        inp.setAttribute('data-idx', String(idx));
        inp.placeholder = 'type here…';
        inp.autocomplete = 'off';
        inp.spellcheck = false;
        inp.addEventListener('keydown', function(e) {
            if (e.key !== 'Enter') return;
            e.preventDefault();
            var next = body.querySelector('.mlp-rs-term-input[data-idx="' + (idx + 1) + '"]');
            if (next) { next.focus(); }
            else { var rb = $id('mlp-rs-term-runbtn'); if (rb) rb.click(); }
        });
        row.appendChild(inp);
        return row;
    }

    if (useMapping) {
        analyzed.forEach(function(item) {
            if (item.isPrompt && promptIdx < inputCount) {
                var row = document.createElement('div');
                row.className = 'mlp-rs-term-prompt-row';
                var lbl = document.createElement('span');
                lbl.className = 'mlp-rs-term-prompt-label';
                lbl.textContent = item.text;
                row.appendChild(lbl);
                var inp = document.createElement('input');
                inp.type = 'text';
                inp.className = 'mlp-rs-term-input';
                inp.setAttribute('data-idx', String(promptIdx));
                inp.placeholder = 'type here…';
                inp.autocomplete = 'off'; inp.spellcheck = false;
                (function(pIdx) {
                    inp.addEventListener('keydown', function(e) {
                        if (e.key !== 'Enter') return;
                        e.preventDefault();
                        var next = body.querySelector('.mlp-rs-term-input[data-idx="' + (pIdx + 1) + '"]');
                        if (next) { next.focus(); }
                        else { var rb = $id('mlp-rs-term-runbtn'); if (rb) rb.click(); }
                    });
                })(promptIdx);
                row.appendChild(inp);
                body.appendChild(row);
                promptIdx++;
            } else {
                var div = document.createElement('div');
                div.className = 'mlp-rs-term-out';
                div.textContent = item.text;
                body.appendChild(div);
            }
        });
        /* append any remaining inputs that didn't match a prompt */
        while (promptIdx < inputCount) {
            body.appendChild(makeInput(promptIdx, false));
            promptIdx++;
        }
    } else {
        /* Fallback: show all output, then labelled inputs below */
        (stdout || '').split('\n').forEach(function(line) {
            var div = document.createElement('div');
            div.className = 'mlp-rs-term-out';
            div.textContent = line;
            body.appendChild(div);
        });
        if (inputCount > 0) {
            var sep = document.createElement('div');
            sep.className = 'mlp-rs-term-sep';
            sep.textContent = 'Enter your input' + (inputCount > 1 ? 's below' : ' below') + ':';
            body.appendChild(sep);
            for (var i = 0; i < inputCount; i++) {
                body.appendChild(makeInput(i, false));
            }
        }
    }
    body.scrollTop = body.scrollHeight;
}

function openTerminalMode() {
    if (running) return;
    _termCode = rsEditor ? rsEditor.getValue() : '';
    if (!_termCode.trim()) { rsToast('Nothing to run', '', 1500); return; }

    if (!_hasStdinUsage(_termCode)) {
        runCode();
        return;
    }

    var inputCount = Math.max(1, _countStdinCalls(_termCode));
    var channel    = _rustChannel || 'stable';

    _openTermModal();
    _termClearBody();
    _termAppend('$ cargo run', 'info');
    _termAppend('Compiling…', 'info');

    fetch('https://play.rust-lang.org/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            channel: channel, mode: 'debug', edition: '2021',
            code: _termCode, crateType: 'bin', tests: false, stdin: ''
        })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        var ansiRe = /\x1b\[[0-9;?]*[A-Za-z]/g;
        var out    = (data.stdout || '').replace(ansiRe, '').trimEnd();
        var stderr = (data.stderr || '').replace(ansiRe, '').trimEnd();
        var hasErr = /(?:^|\n)error(\[E\d+\])?[:\[]/.test(stderr);

        var body = $id('mlp-rs-term-body');
        if (!body) return;
        body.innerHTML = '';

        if (hasErr) {
            _termAppend('Build failed — fix errors first.', 'err');
            stderr.split('\n').forEach(function(l) { if (l.trim()) _termAppend(l, 'err'); });
            return;
        }

        _termAppend('$ ./program', 'info');
        _buildTermInputs(out, inputCount);

        var footer = $id('mlp-rs-term-footer');
        if (footer) footer.style.display = 'flex';

        var firstInp = body.querySelector('.mlp-rs-term-input[data-idx="0"]');
        if (firstInp) setTimeout(function() { firstInp.focus(); }, 80);
    })
    .catch(function(err) {
        var body = $id('mlp-rs-term-body');
        if (body) body.innerHTML = '';
        _termAppend('Network error: ' + (err && err.message ? err.message : String(err)), 'err');
    });
}

function _runTerminalProgram() {
    var body     = $id('mlp-rs-term-body');
    var resultEl = $id('mlp-rs-term-result');
    var runBtn   = $id('mlp-rs-term-runbtn');

    var inputs = body ? body.querySelectorAll('.mlp-rs-term-input') : [];
    var stdinLines = [];
    inputs.forEach(function(inp) { stdinLines.push(inp.value); });
    var stdinVal = stdinLines.join('\n');

    if (runBtn) {
        runBtn.disabled = true;
        runBtn.innerHTML = '<span class="mlp-rs-spinner"></span> Running…';
    }
    if (resultEl) { resultEl.innerHTML = ''; resultEl.style.display = 'block'; }

    var channel = _rustChannel || 'stable';
    var t0 = Date.now();

    fetch('https://play.rust-lang.org/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            channel: channel, mode: 'debug', edition: '2021',
            code: _termCode, crateType: 'bin', tests: false, stdin: stdinVal
        })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        var ms     = Date.now() - t0;
        var ansiRe = /\x1b\[[0-9;?]*[A-Za-z]/g;
        var out    = (data.stdout || '').replace(ansiRe, '').trimEnd();
        var stderr = (data.stderr || '').replace(ansiRe, '').trimEnd();
        var ok     = !data.error && !/(?:^|\n)error(\[E\d+\])?[:\[]/.test(stderr);

        if (!resultEl) return;
        resultEl.innerHTML = '';
        resultEl.style.display = 'block';

        var sep = document.createElement('div');
        sep.className = 'mlp-rs-term-sep';
        sep.textContent = '── output ──';
        resultEl.appendChild(sep);

        if (out) {
            out.split('\n').forEach(function(line) {
                var d = document.createElement('div');
                d.className = 'mlp-rs-term-out';
                d.textContent = line;
                resultEl.appendChild(d);
            });
        }
        if (stderr) {
            stderr.split('\n').forEach(function(line) {
                if (!line.trim() || /^(Compiling|Finished|Running)/.test(line)) return;
                var d = document.createElement('div');
                d.className = 'mlp-rs-term-out err';
                d.textContent = line;
                resultEl.appendChild(d);
            });
        }
        if (!out && !stderr) {
            var d2 = document.createElement('div');
            d2.className = 'mlp-rs-term-out'; d2.textContent = '(no output)';
            resultEl.appendChild(d2);
        }

        var badge = document.createElement('div');
        badge.style.marginTop = '6px';
        badge.className = 'mlp-rs-term-out ' + (ok ? 'ok' : 'err');
        badge.textContent = (ok ? '✓  Done' : '✗  Failed') + ' · ' + ms + 'ms';
        resultEl.appendChild(badge);

        if (body) body.scrollTop = body.scrollHeight;
    })
    .catch(function(err) {
        if (resultEl) {
            var d = document.createElement('div');
            d.className = 'mlp-rs-term-out err';
            d.textContent = 'Network error: ' + (err && err.message ? err.message : String(err));
            resultEl.appendChild(d);
            resultEl.style.display = 'block';
        }
    })
    .finally(function() {
        if (runBtn) {
            runBtn.disabled = false;
            runBtn.innerHTML = '<svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run again';
        }
    });
}

/* ── Public API ──────────────────────────────────────────────── */
window.mlpOpenRustEditor  = openRustEditor;
window.mlpCloseRustEditor = closeRustEditor;

/* ── Hook into project open ──────────────────────────────────── */
(function hookProjectOpen() {
    var tries = 0;
    var t = setInterval(function() {
        if (typeof window.mlpOpenProjectInEditor === 'function' && !window._mlpRsHooked) {
            var _orig = window.mlpOpenProjectInEditor;
            window.mlpOpenProjectInEditor = function(p) {
                if (p && p.type === 'rust') {
                    var projOverlay = document.getElementById('mlp-projects-overlay');
                    if (projOverlay) projOverlay.style.display = 'none';
                    openRustEditor(p.id);
                } else {
                    _orig(p);
                }
            };
            window._mlpRsHooked = true;
            clearInterval(t);
        }
        if (++tries > 100) clearInterval(t);
    }, 150);
})();

/* ══════════════════════════════════════════════════════════════
   ── Rust AI Chat ─────────────────────────────────────────────
   ══════════════════════════════════════════════════════════════ */
var _rsChatHistories = {};
var _rsChatBusy      = false;
var _rsTsToken       = '';
var _rsTsVerified    = false;
var _rsTsPending     = '';
var _rsTsWidgetId    = null;
var _rsTsWidgetEl    = null;
var _rsUndoStack     = [];
var _rsThinkingEl    = null;

function _getRsChatKey(id) { return 'mlp_rs_chat_' + (id || 'default'); }

function _getRsChatHistory(key) {
    if (!_rsChatHistories[key]) {
        try { _rsChatHistories[key] = JSON.parse(localStorage.getItem(key)) || []; }
        catch(e) { _rsChatHistories[key] = []; }
    }
    return _rsChatHistories[key];
}
function _saveRsChatHistory(key, history) {
    _rsChatHistories[key] = history;
    try { localStorage.setItem(key, JSON.stringify(history)); } catch(e) {}
}

function _openRsChat() {
    var sidebar = $id('mlp-rs-chat-sidebar');
    var overlay = $id('mlp-rs-chat-overlay');
    var fab     = $id('mlp-rs-chat-fab');
    if (sidebar) sidebar.classList.add('mlp-rs-chat-open');
    if (overlay) overlay.classList.add('mlp-rs-chat-open');
    if (fab)     fab.classList.add('mlp-rs-fab-hidden');
    var input = $id('mlp-rs-chat-input');
    if (input) setTimeout(function(){ input.focus(); }, 100);
}
function _closeRsChat() {
    var sidebar = $id('mlp-rs-chat-sidebar');
    var overlay = $id('mlp-rs-chat-overlay');
    var fab     = $id('mlp-rs-chat-fab');
    if (sidebar) sidebar.classList.remove('mlp-rs-chat-open');
    if (overlay) overlay.classList.remove('mlp-rs-chat-open');
    if (fab)     fab.classList.remove('mlp-rs-fab-hidden');
}

function _applyRsCodeToEditor(code, applyBtn) {
    if (!rsEditor) return;
    var prev = rsEditor.getValue();
    _rsUndoStack.push(prev);
    rsEditor.setValue(code);
    rsEditor.setScrollPosition({ scrollTop: 0 });
    _unsaved = true; setSave('● Unsaved');
    if (applyBtn) {
        applyBtn.textContent = '✓ Applied';
        applyBtn.classList.add('mlp-rs-applied');
    }
    if (applyBtn && applyBtn.parentNode && !applyBtn.parentNode.querySelector('.mlp-rs-chat-undo-btn')) {
        var undoBtn = document.createElement('button');
        undoBtn.className = 'mlp-rs-chat-undo-btn'; undoBtn.type = 'button'; undoBtn.innerHTML = '↩ Undo';
        undoBtn.addEventListener('click', function() {
            var prev2 = _rsUndoStack.pop();
            if (prev2 !== undefined) {
                rsEditor.setValue(prev2); rsEditor.setScrollPosition({ scrollTop: 0 });
                _unsaved = true; setSave('● Unsaved');
            }
            if (applyBtn) { applyBtn.textContent = '▶ Apply'; applyBtn.classList.remove('mlp-rs-applied'); }
            undoBtn.parentNode && undoBtn.parentNode.removeChild(undoBtn);
        });
        applyBtn.parentNode.appendChild(undoBtn);
    }
}

function _buildRsCodeBlock(lang, code) {
    var wrap   = document.createElement('div'); wrap.className = 'mlp-rs-chat-code-wrap';
    var header = document.createElement('div'); header.className = 'mlp-rs-chat-code-header';
    var langLabel = document.createElement('span'); langLabel.className = 'mlp-rs-chat-code-lang'; langLabel.textContent = lang || 'rust';
    var actions = document.createElement('div'); actions.className = 'mlp-rs-chat-code-actions';
    var copyBtn = document.createElement('button'); copyBtn.className = 'mlp-rs-chat-code-copy'; copyBtn.type = 'button'; copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', function() {
        navigator.clipboard && navigator.clipboard.writeText(code).then(function(){ copyBtn.textContent = '✓ Copied'; setTimeout(function(){ copyBtn.textContent = 'Copy'; }, 1800); });
    });
    var applyBtn = document.createElement('button'); applyBtn.className = 'mlp-rs-chat-code-apply'; applyBtn.type = 'button'; applyBtn.textContent = '▶ Apply';
    applyBtn.addEventListener('click', function(){ _applyRsCodeToEditor(code, applyBtn); });
    actions.appendChild(copyBtn); actions.appendChild(applyBtn);
    header.appendChild(langLabel); header.appendChild(actions);
    var pre = document.createElement('pre'); pre.className = 'mlp-rs-chat-code-pre'; pre.textContent = code;
    wrap.appendChild(header); wrap.appendChild(pre);
    return wrap;
}

function _showRsThinking() {
    _hideRsThinking();
    var msgs = $id('mlp-rs-chat-messages');
    if (!msgs) return;
    var empty = msgs.querySelector('.mlp-rs-chat-empty');
    if (empty) msgs.innerHTML = '';
    var bubble = document.createElement('div'); bubble.className = 'mlp-rs-thinking-bubble';
    bubble.innerHTML = [
        '<svg width="38" height="16" viewBox="0 0 38 16" fill="none">',
          '<defs><radialGradient id="rs-tg1" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="#fb923c"/><stop offset="100%" stop-color="#e8632a"/></radialGradient></defs>',
          '<circle class="mlp-rs-think-ring" cx="7" cy="8" r="14" fill="#e8632a"/>',
          '<circle class="mlp-rs-think-dot" cx="7"  cy="8" r="3.5" fill="url(#rs-tg1)"/>',
          '<circle class="mlp-rs-think-dot" cx="19" cy="8" r="3.5" fill="url(#rs-tg1)"/>',
          '<circle class="mlp-rs-think-dot" cx="31" cy="8" r="3.5" fill="url(#rs-tg1)"/>',
        '</svg>',
        '<span class="mlp-rs-thinking-label">Rust AI is thinking…</span>'
    ].join('');
    msgs.appendChild(bubble); msgs.scrollTop = msgs.scrollHeight; _rsThinkingEl = bubble;
}
function _hideRsThinking() {
    if (_rsThinkingEl && _rsThinkingEl.parentNode) _rsThinkingEl.parentNode.removeChild(_rsThinkingEl);
    _rsThinkingEl = null;
}

/* ── Markdown renderer ───────────────────────────────────────── */
function _renderRsMdInline(text) {
    var frag = document.createDocumentFragment();
    var re = /(`[^`]+`|\*\*[\s\S]+?\*\*|\*[^*\n]+?\*)/g;
    var last = 0, m;
    while ((m = re.exec(text)) !== null) {
        if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        var token = m[0];
        if (token.startsWith('**')) { var strong = document.createElement('strong'); strong.textContent = token.slice(2,-2); frag.appendChild(strong); }
        else if (token.startsWith('`')) { var code = document.createElement('code'); code.className = 'mlp-rs-md-code'; code.textContent = token.slice(1,-1); frag.appendChild(code); }
        else { var em = document.createElement('em'); em.textContent = token.slice(1,-1); frag.appendChild(em); }
        last = m.index + token.length;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    return frag;
}

function _appendRsChatMsg(role, text) {
    var msgs = $id('mlp-rs-chat-messages');
    if (!msgs) return;
    var empty = msgs.querySelector('.mlp-rs-chat-empty');
    if (empty) msgs.innerHTML = '';
    var bubble = document.createElement('div'); bubble.className = 'mlp-rs-chat-msg ' + role;
    if (role === 'assistant') {
        var parts = text.split(/(```[\w]*\n[\s\S]*?```)/g);
        parts.forEach(function(part) {
            var fenced = part.match(/^```([\w]*)\n([\s\S]*?)```$/);
            if (fenced) {
                bubble.appendChild(_buildRsCodeBlock(fenced[1] || 'rust', fenced[2].replace(/\n$/,'')));
            } else if (part.trim()) {
                var lines = part.split('\n');
                lines.forEach(function(line, i) {
                    if (/^### /.test(line))      { var h = document.createElement('span'); h.className = 'mlp-rs-md-h3'; h.appendChild(_renderRsMdInline(line.slice(4))); bubble.appendChild(h); }
                    else if (/^## /.test(line))  { var h = document.createElement('span'); h.className = 'mlp-rs-md-h2'; h.appendChild(_renderRsMdInline(line.slice(3))); bubble.appendChild(h); }
                    else if (/^# /.test(line))   { var h = document.createElement('span'); h.className = 'mlp-rs-md-h2'; h.appendChild(_renderRsMdInline(line.slice(2))); bubble.appendChild(h); }
                    else if (line) { var span = document.createElement('span'); span.appendChild(_renderRsMdInline(line)); bubble.appendChild(span); }
                    if (i < lines.length - 1) bubble.appendChild(document.createElement('br'));
                });
            }
        });
    } else {
        bubble.textContent = text;
    }
    msgs.appendChild(bubble); msgs.scrollTop = msgs.scrollHeight;
}

function _renderRsTurnstile() {
    if (!MLP_TS_SITEKEY) { _rsTsVerified = true; if (_rsTsPending) { _sendRsChat(); } return; }
    var msgs = $id('mlp-rs-chat-messages');
    if (!msgs || _rsTsWidgetEl) return;
    _rsTsWidgetEl = document.createElement('div'); _rsTsWidgetEl.style.margin = '8px 0';
    msgs.appendChild(_rsTsWidgetEl); msgs.scrollTop = msgs.scrollHeight;
    if (window.turnstile) {
        _rsTsWidgetId = window.turnstile.render(_rsTsWidgetEl, {
            sitekey:  MLP_TS_SITEKEY,
            callback: function(token) {
                _rsTsToken = token; _rsTsVerified = true;
                if (_rsTsWidgetEl && _rsTsWidgetEl.parentNode) _rsTsWidgetEl.parentNode.removeChild(_rsTsWidgetEl);
                _rsTsWidgetEl = null; _rsTsWidgetId = null;
                if (_rsTsPending) { _sendRsChat(); }
            }
        });
    }
}

function _sendRsChat() {
    if (_rsChatBusy) return;
    var input = $id('mlp-rs-chat-input');
    var text  = _rsTsPending || (input && input.value.trim());
    if (!text) return;
    _rsTsPending = '';
    if (input) input.value = '';

    if (!_rsTsVerified) {
        _rsTsPending = text;
        _appendRsChatMsg('user', text);
        _appendRsChatMsg('assistant', 'Please complete the verification to continue.');
        _renderRsTurnstile();
        return;
    }

    var chatKey = _getRsChatKey(_activeId);
    var history = _getRsChatHistory(chatKey);
    history.push({ role: 'user', content: text });
    _saveRsChatHistory(chatKey, history);
    _appendRsChatMsg('user', text);
    _showRsThinking();
    _rsChatBusy = true;
    var sendBtn = $id('mlp-rs-chat-send');
    if (sendBtn) sendBtn.disabled = true;

    var rustCode = rsEditor ? rsEditor.getValue() : '';

    var fd = new FormData();
    fd.append('action',    'mlp_ai_chat_rust');
    fd.append('nonce',     (typeof MLP_NONCE !== 'undefined' ? MLP_NONCE : ''));
    fd.append('message',   text);
    fd.append('rust_code', rustCode);
    fd.append('history',   JSON.stringify(history.slice(-10)));
    if (_rsTsToken) { fd.append('turnstile_token', _rsTsToken); _rsTsToken = ''; }

    var ajaxUrl = (typeof MLP_AJAX_URL !== 'undefined') ? MLP_AJAX_URL : (typeof ajaxurl !== 'undefined' ? ajaxurl : '/wp-admin/admin-ajax.php');

    fetch(ajaxUrl, { method: 'POST', body: fd })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            _hideRsThinking();
            if (data && data.success && data.data && data.data.reply) {
                var reply = data.data.reply;
                history.push({ role: 'assistant', content: reply });
                _saveRsChatHistory(chatKey, history);
                _appendRsChatMsg('assistant', reply);
            } else {
                var errMsg = (data && data.data && data.data.message) ? data.data.message : 'AI request failed. Please try again.';
                _appendRsChatMsg('assistant', '⚠ ' + errMsg);
            }
        })
        .catch(function(err) {
            _hideRsThinking();
            _appendRsChatMsg('assistant', '⚠ Network error: ' + (err && err.message ? err.message : String(err)));
        })
        .finally(function() {
            _rsChatBusy = false;
            if (sendBtn) sendBtn.disabled = false;
            var inp = $id('mlp-rs-chat-input');
            if (inp) setTimeout(function(){ inp.focus(); }, 50);
        });
}

})();
</script>
        <?php
    }
}
