<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 *  Thanks for reading
 */
class MLP_PHP {
    public static function init() {
        add_action( 'wp_head',   [ __CLASS__, 'output_styles' ], 99 );
        add_action( 'wp_footer', [ __CLASS__, 'output_editor' ],  6 );
    }

    /* ── Styles ─────────────────────────────────────────────────────────── */
    public static function output_styles() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) {
            return;
        }
        ?>
<style id="mlp-php-styles">
/* ── PHP Editor Overlay ─────────────────────────────── */
#mlp-php-overlay {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 99999;
    background: var(--mlp-bg, #0e0e0e);
    flex-direction: column;
    font-family: var(--mlp-font, 'JetBrains Mono', 'Fira Code', monospace);
    overflow: hidden;
}
#mlp-php-overlay.mlp-php-active { display: flex; }

/* Topbar */
#mlp-php-topbar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 14px;
    height: 46px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
    overflow-x: auto;
    overflow-y: hidden;
}
#mlp-php-back {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 11px;
    background: transparent;
    border: 1px solid var(--mlp-border, #2a2a2a);
    border-radius: 6px;
    color: var(--mlp-text-muted, #888);
    font-size: .75rem;
    font-weight: 600;
    cursor: pointer;
    font-family: inherit;
    transition: border-color .15s, color .15s;
    white-space: nowrap;
    flex-shrink: 0;
}
#mlp-php-back:hover { border-color: #7c3aed; color: #7c3aed; }
#mlp-php-title {
    flex: 1;
    font-size: .83rem;
    font-weight: 700;
    color: var(--mlp-text, #f0f0f0);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
}
#mlp-php-title span {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 8px;
    background: rgba(124,58,237,.18);
    color: #a78bfa;
    border-radius: 4px;
    font-size: .62rem;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    margin-left: 8px;
}
.mlp-php-btn {
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
.mlp-php-btn:disabled { opacity: .5; cursor: not-allowed; }
#mlp-php-run {
    background: linear-gradient(135deg, #7c3aed, #6d28d9);
    color: #fff;
    border-color: transparent;
    box-shadow: 0 1px 6px rgba(124,58,237,.35);
}
#mlp-php-run:hover:not(:disabled) { opacity: .88; }
#mlp-php-save {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
}
#mlp-php-save:hover:not(:disabled) { border-color: #7c3aed; color: #7c3aed; }
#mlp-php-export {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
}
#mlp-php-export:hover:not(:disabled) { border-color: #a78bfa; color: #a78bfa; }
#mlp-php-fullscreen-btn {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
    padding: 5px 9px;
}
#mlp-php-fullscreen-btn:hover { border-color: #a78bfa; color: #a78bfa; }

/* Floating AI Chat Button */
#mlp-php-chat-fab {
    position: fixed;
    bottom: 28px;
    right: 16px;
    z-index: 999993;
    height: 38px;
    padding: 0 14px 0 11px;
    border-radius: 8px;
    background: linear-gradient(135deg, #7c3aed, #6d28d9);
    border: none;
    color: #fff;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-family: var(--mlp-font, 'JetBrains Mono', 'Fira Code', monospace);
    font-size: .75rem;
    font-weight: 700;
    letter-spacing: .02em;
    white-space: nowrap;
    box-shadow: 0 4px 18px rgba(124,58,237,.45), 0 1px 4px rgba(0,0,0,.4);
    transition: opacity .18s, transform .18s, box-shadow .18s;
}
#mlp-php-chat-fab:hover { opacity: .9; transform: translateY(-2px); box-shadow: 0 6px 22px rgba(124,58,237,.55); }
#mlp-php-chat-fab.mlp-php-fab-hidden { opacity: 0; pointer-events: none; transform: translateY(6px); }

/* Fullscreen */
#mlp-php-overlay.mlp-php-fullscreen #mlp-php-topbar,
#mlp-php-overlay.mlp-php-fullscreen #mlp-php-tabbar,
#mlp-php-overlay.mlp-php-fullscreen #mlp-php-statusbar { display: none !important; }
#mlp-php-overlay.mlp-php-fullscreen #mlp-php-output-wrap { display: none !important; }
#mlp-php-overlay.mlp-php-fullscreen #mlp-php-resizer { display: none !important; }

/* Tab bar */
#mlp-php-tabbar {
    display: flex;
    align-items: center;
    padding: 0 14px;
    height: 36px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
    overflow-x: auto;
}
.mlp-php-tab {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 0 14px;
    height: 100%;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--mlp-text-muted, #888);
    font-family: inherit;
    font-size: .73rem;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    transition: color .12s, border-color .12s;
}
.mlp-php-tab .mlp-php-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.mlp-php-tab.mlp-php-tab-active { color: var(--mlp-text, #f0f0f0); border-bottom-color: #7c3aed; }

/* Main split */
#mlp-php-main {
    flex: 1;
    display: flex;
    flex-direction: row;
    overflow: hidden;
    min-height: 0;
}
#mlp-php-editor-wrap { flex: 1; display: flex; flex-direction: column; min-width: 0; min-height: 0; position: relative; }
#mlp-php-editor { flex: 1; min-height: 0; width: 100%; }

/* Resize handle */
#mlp-php-resizer {
    width: 5px;
    background: var(--mlp-border, #2a2a2a);
    cursor: col-resize;
    flex-shrink: 0;
    transition: background .15s;
    position: relative;
    z-index: 2;
}
#mlp-php-resizer:hover,
#mlp-php-resizer.mlp-php-dragging { background: #7c3aed; }

/* Output panel */
#mlp-php-output-wrap {
    width: 38%;
    min-width: 220px;
    max-width: 70%;
    display: flex;
    flex-direction: column;
    background: #0a0a0a;
    border-left: 1px solid var(--mlp-border, #2a2a2a);
    overflow: hidden;
}
#mlp-php-output-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 12px;
    height: 34px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-php-output-title {
    flex: 1;
    font-size: .68rem;
    font-weight: 700;
    color: var(--mlp-text-muted, #888);
    text-transform: uppercase;
    letter-spacing: .07em;
}
#mlp-php-clear-btn {
    background: none;
    border: none;
    color: var(--mlp-text-muted, #888);
    font-size: .68rem;
    cursor: pointer;
    font-family: inherit;
    padding: 3px 7px;
    border-radius: 4px;
    transition: color .15s, background .15s;
}
#mlp-php-clear-btn:hover { color: #ef4444; background: rgba(239,68,68,.1); }
#mlp-php-output {
    flex: 1;
    overflow-y: auto;
    padding: 10px 12px;
    font-size: .78rem;
    line-height: 1.7;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    color: #d4d4d4;
    white-space: pre-wrap;
    word-break: break-word;
    background: #0a0a0a;
}
#mlp-php-output::-webkit-scrollbar { width: 5px; }
#mlp-php-output::-webkit-scrollbar-thumb { background: var(--mlp-border, #2a2a2a); border-radius: 3px; }
.mlp-php-out-line { display: block; }
.mlp-php-out-err  { color: #f87171; }
.mlp-php-out-info { color: #a78bfa; font-style: italic; font-size: .72rem; }
.mlp-php-out-ok   { color: #34d399; font-size: .72rem; }

/* Preview iframe */
#mlp-php-preview-frame {
    flex: 1;
    width: 100%;
    border: none;
    background: #fff;
    display: none;
}
#mlp-php-output-wrap.mlp-php-mode-preview #mlp-php-output { display: none; }
#mlp-php-output-wrap.mlp-php-mode-preview #mlp-php-preview-frame { display: block; }
.mlp-php-out-tabs { display: flex; gap: 0; margin-right: 6px; }
.mlp-php-out-tab-btn {
    padding: 2px 9px;
    background: transparent;
    border: 1px solid var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
    font-family: inherit;
    font-size: .65rem;
    font-weight: 700;
    cursor: pointer;
    transition: color .12s, border-color .12s, background .12s;
}
.mlp-php-out-tab-btn:first-child { border-radius: 4px 0 0 4px; }
.mlp-php-out-tab-btn:last-child { border-radius: 0 4px 4px 0; border-left: none; }
.mlp-php-out-tab-btn.mlp-php-out-tab-active { background: rgba(124,58,237,.18); color: #a78bfa; border-color: #7c3aed; }

/* Preview fullscreen overlay */
#mlp-php-preview-fs {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 999998;
    background: #111;
    flex-direction: column;
}
#mlp-php-preview-fs.mlp-php-fs-active { display: flex; }

/* Fullscreen toolbar */
#mlp-php-fs-toolbar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 14px;
    height: 44px;
    background: #161616;
    border-bottom: 1px solid #2a2a2a;
    flex-shrink: 0;
}
#mlp-php-preview-fs-back {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    background: transparent;
    border: 1px solid #2a2a2a;
    border-radius: 6px;
    color: #888;
    font-family: var(--mlp-font, 'JetBrains Mono', 'Fira Code', monospace);
    font-size: .73rem;
    font-weight: 700;
    cursor: pointer;
    transition: border-color .15s, color .15s;
    white-space: nowrap;
}
#mlp-php-preview-fs-back:hover { border-color: #7c3aed; color: #a78bfa; }
.mlp-php-fs-device-group {
    display: flex;
    gap: 0;
    margin: 0 auto;
}
.mlp-php-fs-device-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 5px 13px;
    background: transparent;
    border: 1px solid #2a2a2a;
    color: #888;
    font-family: var(--mlp-font, 'JetBrains Mono', 'Fira Code', monospace);
    font-size: .7rem;
    font-weight: 700;
    cursor: pointer;
    transition: color .12s, background .12s, border-color .12s;
    white-space: nowrap;
}
.mlp-php-fs-device-btn:first-child { border-radius: 6px 0 0 6px; }
.mlp-php-fs-device-btn:not(:first-child) { border-left: none; }
.mlp-php-fs-device-btn:last-child { border-radius: 0 6px 6px 0; }
.mlp-php-fs-device-btn:hover { color: #d4d4d4; border-color: #555; }
.mlp-php-fs-device-btn.mlp-php-fs-dev-active { background: rgba(124,58,237,.18); color: #a78bfa; border-color: #7c3aed !important; }

/* Fullscreen viewport area */
#mlp-php-fs-viewport {
    flex: 1;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    min-height: 0;
    overflow: auto;
    background: #111;
    padding: 0;
    transition: padding .25s;
}
#mlp-php-fs-viewport.mlp-php-fs-framed {
    padding: 24px 16px;
    background: #1a1a1a;
}
#mlp-php-fs-frame-wrap {
    width: 100%;
    height: 100%;
    min-height: 0;
    display: flex;
    flex-direction: column;
    box-shadow: none;
    transition: width .25s cubic-bezier(.4,0,.2,1), box-shadow .25s;
    overflow: hidden;
    border-radius: 0;
    background: #fff;
}
#mlp-php-fs-viewport.mlp-php-fs-framed #mlp-php-fs-frame-wrap {
    border-radius: 10px;
    box-shadow: 0 8px 48px rgba(0,0,0,.7), 0 0 0 1px rgba(255,255,255,.07);
    height: auto;
    min-height: calc(100vh - 92px);
}
#mlp-php-preview-fs-frame {
    flex: 1;
    width: 100%;
    border: none;
    min-height: 0;
    display: block;
}
#mlp-php-fs-viewport.mlp-php-fs-framed #mlp-php-preview-fs-frame {
    min-height: calc(100vh - 92px);
}

/* Device label strip */
#mlp-php-fs-device-label {
    display: none;
    align-items: center;
    justify-content: center;
    gap: 6px;
    height: 28px;
    background: #1e1e1e;
    border-bottom: 1px solid #2a2a2a;
    font-family: var(--mlp-font, 'JetBrains Mono', monospace);
    font-size: .62rem;
    color: #555;
    letter-spacing: .07em;
    flex-shrink: 0;
}
#mlp-php-fs-viewport.mlp-php-fs-framed #mlp-php-fs-device-label { display: flex; }

#mlp-php-preview-fs-btn {
    background: none;
    border: none;
    color: var(--mlp-text-muted, #888);
    cursor: pointer;
    padding: 3px 6px;
    display: inline-flex;
    align-items: center;
    border-radius: 4px;
    transition: color .15s, background .15s;
    margin-left: 2px;
}
#mlp-php-preview-fs-btn:hover { color: #a78bfa; background: rgba(124,58,237,.12); }

/* Status bar */
#mlp-php-statusbar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 14px;
    height: 24px;
    background: var(--mlp-surface, #161616);
    border-top: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
    font-size: .62rem;
    color: var(--mlp-text-muted, #888);
    overflow: hidden;
}
#mlp-php-status-lang { display: inline-flex; align-items: center; gap: 4px; color: #a78bfa; font-weight: 600; }
#mlp-php-status-msg  { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
#mlp-php-status-pos  { white-space: nowrap; }
#mlp-php-status-save { white-space: nowrap; font-style: italic; }

/* Toast */
#mlp-php-toast {
    position: fixed;
    bottom: 22px;
    right: 22px;
    z-index: 999999;
    background: var(--mlp-surface, #1e1e1e);
    border: 1px solid var(--mlp-border, #2a2a2a);
    border-radius: 8px;
    padding: 10px 14px;
    font-size: .78rem;
    font-weight: 600;
    color: var(--mlp-text, #f0f0f0);
    box-shadow: 0 6px 24px rgba(0,0,0,.4);
    opacity: 0;
    transform: translateY(8px);
    transition: opacity .22s, transform .22s;
    pointer-events: none;
    font-family: var(--mlp-font, sans-serif);
}
#mlp-php-toast.mlp-php-show { opacity: 1; transform: translateY(0); }
#mlp-php-toast.mlp-php-err  { border-color: #f87171; }
#mlp-php-toast.mlp-php-succ { border-color: #34d399; }

/* Spinner */
@keyframes mlp-php-spin { to { transform: rotate(360deg); } }
.mlp-php-spinner {
    width: 12px; height: 12px;
    border: 2px solid rgba(255,255,255,.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: mlp-php-spin .7s linear infinite;
    display: inline-block;
    flex-shrink: 0;
}

@media (max-width: 680px) {
    #mlp-php-main { flex-direction: column; }
    #mlp-php-output-wrap { width: 100%; max-width: 100%; min-width: 0; border-left: none; border-top: 1px solid var(--mlp-border, #2a2a2a); height: 38%; }
    #mlp-php-resizer { display: none; }
}

/* ── PHP AI Chat Sidebar ────────────────────────────────── */
#mlp-php-chat-sidebar {
    position: fixed;
    top: 56px; right: 12px; bottom: 20px;
    width: 360px;
    max-width: calc(96vw - 12px);
    height: auto;
    z-index: 999991;
    background: var(--mlp-bg, #0e0e0e);
    border: 1px solid var(--mlp-border, #2a2a2a);
    border-radius: 10px;
    display: flex;
    flex-direction: column;
    font-family: var(--mlp-font, 'JetBrains Mono', 'Fira Code', monospace);
    transform: translateX(400px);
    transition: transform 0.25s cubic-bezier(0.4,0,0.2,1);
    box-shadow: -4px 8px 40px rgba(0,0,0,.55), -8px 0 40px rgba(124,58,237,.12);
    overflow: hidden;
}
#mlp-php-chat-sidebar.mlp-php-chat-open { transform: translateX(0); }
#mlp-php-chat-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 14px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-php-chat-title { font-size: .83rem; font-weight: 700; color: var(--mlp-text, #f0f0f0); }
#mlp-php-chat-close { background: none; border: none; color: var(--mlp-text-muted, #888); cursor: pointer; padding: 4px; display: flex; align-items: center; transition: color .15s; }
#mlp-php-chat-close:hover { color: var(--mlp-text, #f0f0f0); }
#mlp-php-chat-messages { flex: 1; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 10px; }
.mlp-php-chat-msg { padding: 8px 10px; border-radius: 6px; font-size: .75rem; line-height: 1.5; max-width: 95%; word-wrap: break-word; }
.mlp-php-chat-msg.user { background: #3b1a8a; color: #c4b5fd; align-self: flex-end; margin-left: auto; }
.mlp-php-chat-msg.assistant { background: #1f2937; color: #d4d4d4; align-self: flex-start; }
.mlp-php-chat-empty { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--mlp-text-muted, #888); font-size: .73rem; text-align: center; padding: 20px; }
#mlp-php-chat-input-area { display: flex; flex-direction: column; gap: 8px; padding: 10px; background: var(--mlp-surface, #161616); border-top: 1px solid var(--mlp-border, #2a2a2a); flex-shrink: 0; }
#mlp-php-chat-input { width: 100%; padding: 8px; background: rgba(0,0,0,.3); border: 1px solid var(--mlp-border, #2a2a2a); border-radius: 4px; color: var(--mlp-text, #f0f0f0); font-family: inherit; font-size: .75rem; resize: none; max-height: 80px; transition: border-color .15s; }
#mlp-php-chat-input:focus { outline: none; border-color: #7c3aed; }
#mlp-php-chat-send { align-self: flex-end; padding: 5px 12px; background: #7c3aed; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: .73rem; font-weight: 600; transition: opacity .15s; }
#mlp-php-chat-send:hover:not(:disabled) { opacity: .88; }
#mlp-php-chat-send:disabled { opacity: .5; cursor: not-allowed; }

/* Code blocks in chat */
.mlp-php-chat-code-wrap { margin: 6px 0 0; border-radius: 6px; overflow: hidden; border: 1px solid #2a2a2a; background: #0d0d0d; max-width: 100%; }
.mlp-php-chat-code-header { display: flex; align-items: center; justify-content: space-between; padding: 4px 10px; background: #1a1a1a; border-bottom: 1px solid #2a2a2a; }
.mlp-php-chat-code-lang { font-size: .62rem; font-weight: 700; color: #a78bfa; letter-spacing: .06em; text-transform: uppercase; }
.mlp-php-chat-code-actions { display: flex; gap: 5px; }
.mlp-php-chat-code-apply, .mlp-php-chat-code-copy { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 4px; font-family: inherit; font-size: .65rem; font-weight: 700; cursor: pointer; border: 1px solid transparent; transition: opacity .15s, background .15s; }
.mlp-php-chat-code-apply { background: #7c3aed; color: #fff; }
.mlp-php-chat-code-apply:hover { opacity: .85; }
.mlp-php-chat-code-apply.mlp-php-applied { background: #1d4ed8; }
.mlp-php-chat-code-copy { background: transparent; border-color: #3a3a3a; color: #888; }
.mlp-php-chat-code-copy:hover { color: #d4d4d4; border-color: #555; }
.mlp-php-chat-code-pre { margin: 0; padding: 10px 12px; overflow-x: auto; font-family: 'JetBrains Mono','Fira Code','Consolas',monospace; font-size: .73rem; line-height: 1.6; color: #d4d4d4; white-space: pre; background: transparent; }
.mlp-php-chat-undo-btn { display: inline-flex; align-items: center; gap: 4px; margin-top: 4px; padding: 2px 8px; background: transparent; border: 1px solid #3a3a3a; border-radius: 4px; color: #f59e0b; font-family: inherit; font-size: .65rem; font-weight: 700; cursor: pointer; transition: opacity .15s; }
.mlp-php-chat-undo-btn:hover { opacity: .8; }

/* Thinking animation */
.mlp-php-thinking-bubble { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: #1f2937; border-radius: 6px; border: 1px solid rgba(167,139,250,.15); align-self: flex-start; max-width: 95%; }
.mlp-php-thinking-label { font-size: .68rem; color: #6b7280; font-style: italic; white-space: nowrap; }
@keyframes mlp-php-dot-wave { 0%, 100% { transform: translateY(0); opacity: .35; } 50% { transform: translateY(-6px); opacity: 1; } }
.mlp-php-think-dot { animation: mlp-php-dot-wave 1.3s ease-in-out infinite; }
.mlp-php-think-dot:nth-child(2) { animation-delay: .22s; }
.mlp-php-think-dot:nth-child(3) { animation-delay: .44s; }

#mlp-php-chat-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.3); z-index: 999990; opacity: 0; pointer-events: none; transition: opacity 0.25s cubic-bezier(0.4,0,0.2,1); }
#mlp-php-chat-overlay.mlp-php-chat-open { opacity: 1; pointer-events: auto; }

html.mlp-php-editor-active #mlpChatToggle,
html.mlp-php-editor-active #mlpChatSidebar { display: none !important; }

/* ── Interactive stdin input row ─────────────────────── */
#mlp-php-input-row {
    display: none;
    align-items: center;
    gap: 6px;
    padding: 6px 10px;
    background: var(--mlp-surface, #161616);
    border-top: 2px solid #7c3aed;
    flex-shrink: 0;
}
#mlp-php-input-row.mlp-php-input-active { display: flex; }
#mlp-php-input-prompt {
    font-size: .75rem;
    color: #a78bfa;
    white-space: pre;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    flex-shrink: 0;
    max-width: 38%;
    overflow: hidden;
    text-overflow: ellipsis;
}
#mlp-php-input-field {
    flex: 1;
    padding: 4px 8px;
    background: rgba(0,0,0,.35);
    border: 1px solid #3a3a3a;
    border-radius: 4px;
    color: #f0f0f0;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: .78rem;
    outline: none;
    min-width: 0;
    caret-color: #a78bfa;
}
#mlp-php-input-field:focus { border-color: #7c3aed; }
#mlp-php-input-send {
    padding: 4px 11px;
    background: #7c3aed;
    border: none;
    border-radius: 4px;
    color: #fff;
    font-family: inherit;
    font-size: .73rem;
    font-weight: 700;
    cursor: pointer;
    white-space: nowrap;
    transition: opacity .15s;
    flex-shrink: 0;
}
#mlp-php-input-send:hover { opacity: .85; }
#mlp-php-input-send:disabled { opacity: .4; cursor: not-allowed; }
@keyframes mlp-php-input-pulse {
    0%, 100% { border-color: #7c3aed; }
    50%       { border-color: #a78bfa; }
}
#mlp-php-input-row.mlp-php-input-active { animation: mlp-php-input-pulse 1.6s ease-in-out infinite; }

/* ── Variables Inspector panel ───────────────────────── */
#mlp-php-vars {
    flex: 1;
    overflow-y: auto;
    padding: 8px 0;
    background: #0a0a0a;
    display: none;
    font-size: .74rem;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
}
#mlp-php-output-wrap.mlp-php-mode-vars #mlp-php-output        { display: none; }
#mlp-php-output-wrap.mlp-php-mode-vars #mlp-php-preview-frame { display: none; }
#mlp-php-output-wrap.mlp-php-mode-vars #mlp-php-vars          { display: block; }
.mlp-var-row {
    display: flex;
    align-items: flex-start;
    padding: 5px 12px;
    border-bottom: 1px solid rgba(42,42,42,.55);
    gap: 10px;
    word-break: break-word;
}
.mlp-var-row:hover { background: rgba(124,58,237,.07); }
.mlp-var-name { color: #a78bfa; font-weight: 700; min-width: 110px; max-width: 160px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.mlp-var-type { color: #555; font-size: .63rem; min-width: 46px; flex-shrink: 0; align-self: flex-start; margin-top: 2px; }
.mlp-var-val  { color: #d4d4d4; flex: 1; white-space: pre-wrap; line-height: 1.5; }
.mlp-var-val-str  { color: #ce9178; }
.mlp-var-val-num  { color: #b5cea8; }
.mlp-var-val-bool { color: #569cd6; }
.mlp-var-val-null { color: #555; font-style: italic; }
.mlp-var-val-arr  { color: #9cdcfe; }
.mlp-var-val-obj  { color: #4ec9b0; }
.mlp-var-empty {
    display: flex; align-items: center; justify-content: center;
    height: 56px; color: #444; font-size: .72rem; font-style: italic;
}
@keyframes mlp-var-highlight {
    0%   { background: rgba(251,191,36,.28); }
    100% { background: transparent; }
}
.mlp-var-row-changed { animation: mlp-var-highlight 2s ease-out forwards; }
.mlp-var-badge-new {
    font-size: .55rem; font-weight: 800; padding: 1px 5px;
    border-radius: 3px; background: #7c3aed; color: #fff;
    letter-spacing: .04em; text-transform: uppercase; flex-shrink: 0; align-self: center;
}
.mlp-var-badge-changed {
    font-size: .55rem; font-weight: 800; padding: 1px 5px;
    border-radius: 3px; background: #f59e0b; color: #111;
    letter-spacing: .04em; text-transform: uppercase; flex-shrink: 0; align-self: center;
}
</style>
        <?php
    }

    /* ── HTML & JavaScript ───────────────────────────────────────────────── */
    public static function output_editor() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) {
            return;
        }

        /* ── Runner URL — Replit server, NOT WordPress AJAX ──────────────
         * Define MLP_PHP_RUNNER_URL in wp-config.php:
         *   define( 'MLP_PHP_RUNNER_URL', 'https://your-slug.replit.app/api/run-php' );
         * Optionally protect with a shared secret (must match MLP_PHP_SECRET env var on Replit):
         *   define( 'MLP_PHP_SECRET', 'your-secret' );
         */
        $runner_url = defined( 'MLP_PHP_RUNNER_URL' ) ? MLP_PHP_RUNNER_URL : '';
        $runner_url = apply_filters( 'mlp_php_runner_url', $runner_url );

        $runner_secret = defined( 'MLP_PHP_SECRET' ) ? MLP_PHP_SECRET : '';
        $runner_secret = apply_filters( 'mlp_php_runner_secret', $runner_secret );

        $turnstile_site_key = defined( 'MLP_TURNSTILE_SITE_KEY' ) ? MLP_TURNSTILE_SITE_KEY : '';
        $turnstile_site_key = apply_filters( 'mlp_php_turnstile_site_key', $turnstile_site_key );
        ?>
<!-- PHP Editor Overlay -->
<div id="mlp-php-overlay" role="dialog" aria-modal="true" aria-label="PHP Editor">
  <div id="mlp-php-topbar">
    <button id="mlp-php-back" type="button" aria-label="Back to projects">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      Projects
    </button>
    <div id="mlp-php-title">
      <span id="mlp-php-name">Untitled</span>
      <span>PHP</span>
    </div>
    <button id="mlp-php-run" class="mlp-php-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
      Run
    </button>
    <button id="mlp-php-save" class="mlp-php-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
      Save
    </button>
    <button id="mlp-php-export" class="mlp-php-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Export .php
    </button>
    <button id="mlp-php-fullscreen-btn" class="mlp-php-btn" type="button" title="Toggle fullscreen (Ctrl+Shift+F)">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
    </button>
  </div>
  <div id="mlp-php-tabbar">
    <button class="mlp-php-tab mlp-php-tab-active" data-tab="php" type="button">
      <span class="mlp-php-dot" style="background:#7c3aed;"></span>
      PHP
    </button>
  </div>
  <div id="mlp-php-main">
    <div id="mlp-php-editor-wrap">
      <div id="mlp-php-editor"></div>
    </div>
    <div id="mlp-php-resizer" role="separator" aria-orientation="vertical" aria-label="Resize panels"></div>
    <div id="mlp-php-output-wrap">
      <div id="mlp-php-output-header">
        <div id="mlp-php-output-title">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline;margin-right:4px;vertical-align:middle;"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          Output
        </div>
        <div class="mlp-php-out-tabs">
          <button class="mlp-php-out-tab-btn mlp-php-out-tab-active" id="mlp-php-tab-output" type="button">Output</button>
          <button class="mlp-php-out-tab-btn" id="mlp-php-tab-preview" type="button">Preview</button>
          <button class="mlp-php-out-tab-btn" id="mlp-php-tab-vars" type="button">𝑥 Variables</button>
        </div>
        <button id="mlp-php-preview-fs-btn" type="button" title="Fullscreen preview">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
        </button>
        <button id="mlp-php-clear-btn" type="button" title="Clear output">Clear</button>
      </div>
      <div id="mlp-php-output" aria-live="polite" aria-label="PHP output"></div>
      <iframe id="mlp-php-preview-frame" sandbox="allow-scripts allow-same-origin allow-forms allow-modals allow-popups allow-pointer-lock" title="HTML Preview"></iframe>
      <div id="mlp-php-vars" aria-label="Variables inspector"></div>
      <div id="mlp-php-input-row" role="group" aria-label="Program input">
        <span id="mlp-php-input-prompt">›</span>
        <input id="mlp-php-input-field" type="text" autocomplete="off" spellcheck="false" placeholder="Type your reply and press Enter…" aria-label="Program input value" />
        <button id="mlp-php-input-send" type="button">↩ Send</button>
      </div>
    </div>
  </div>
  <div id="mlp-php-statusbar">
    <span id="mlp-php-status-lang">
      <svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>
      PHP
    </span>
    <span id="mlp-php-status-msg"></span>
    <span id="mlp-php-status-pos">Ln 1, Col 1</span>
    <span id="mlp-php-status-save"></span>
  </div>
</div>

<!-- PHP AI Chat Sidebar -->
<div id="mlp-php-chat-overlay"></div>
<div id="mlp-php-chat-sidebar">
  <div id="mlp-php-chat-header">
    <div id="mlp-php-chat-title">PHP AI Chat</div>
    <button id="mlp-php-chat-close" type="button" title="Close chat">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>
  <div id="mlp-php-chat-messages">
    <div class="mlp-php-chat-empty">Ask the PHP AI assistant anything about your code</div>
  </div>
  <div id="mlp-php-chat-input-area">
    <div id="mlp-php-turnstile-wrap" style="display:none;margin-bottom:6px;">
      <div id="mlp-php-turnstile-widget"></div>
    </div>
    <textarea id="mlp-php-chat-input" placeholder="Ask about your PHP code…" rows="2"></textarea>
    <button id="mlp-php-chat-send" type="button">Send</button>
  </div>
</div>

<div id="mlp-php-toast"></div>

<!-- Preview fullscreen overlay -->
<div id="mlp-php-preview-fs" role="dialog" aria-modal="true" aria-label="Fullscreen Preview">
  <div id="mlp-php-fs-toolbar">
    <button id="mlp-php-preview-fs-back" type="button" aria-label="Exit fullscreen">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      Back
    </button>
    <div class="mlp-php-fs-device-group">
      <button class="mlp-php-fs-device-btn" data-device="desktop" type="button" title="Desktop">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        Desktop
      </button>
      <button class="mlp-php-fs-device-btn" data-device="tablet" type="button" title="Tablet (768 px)">
        <svg width="11" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2"/><circle cx="12" cy="18" r="1" fill="currentColor" stroke="none"/></svg>
        Tablet
      </button>
      <button class="mlp-php-fs-device-btn" data-device="mobile" type="button" title="Mobile (390 px)">
        <svg width="9" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2"/><circle cx="12" cy="18" r="1" fill="currentColor" stroke="none"/></svg>
        Mobile
      </button>
    </div>
  </div>
  <div id="mlp-php-fs-viewport">
    <div id="mlp-php-fs-frame-wrap">
      <div id="mlp-php-fs-device-label">— Desktop —</div>
      <iframe id="mlp-php-preview-fs-frame" sandbox="allow-scripts allow-same-origin allow-forms allow-modals allow-popups allow-pointer-lock" title="Fullscreen HTML Preview"></iframe>
    </div>
  </div>
</div>

<button id="mlp-php-chat-fab" class="mlp-php-fab-hidden" type="button" aria-label="Open PHP AI Chat">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
  AI Chat
</button>

<script>
(function(){
'use strict';

/* ── Config ─────────────────────────────────────────────────────────────
 * MLP_PHP_RUNNER_URL  — Replit server endpoint for code execution
 * MLP_PHP_SECRET      — optional shared secret (sent as X-MLP-Secret header)
 * Code is stored in localStorage; execution is remote (Replit server).
 * ─────────────────────────────────────────────────────────────────────── */
var MLP_PHP_LS         = 'mlp_projects';
var MLP_PHP_RUNNER_URL = <?php echo json_encode( $runner_url ); ?>;
var MLP_PHP_SECRET            = <?php echo json_encode( $runner_secret ); ?>;
var MLP_PHP_TURNSTILE_KEY     = <?php echo json_encode( $turnstile_site_key ); ?>;
var _phpTurnstileToken        = '';
var _phpTurnstileWidgetId     = null;
var _phpTurnstileRendered     = false;

var _phpPendingMsg  = null;
var _phpLastSentText = '';
var _phpLastSentCode = ''; // stores { text, phpCode, history, chatKey } for auto-retry
function mlpPhpTurnstileCallback(token) {
    _phpTurnstileToken = token;
    // If there is a pending message that was blocked by verification, retry it now
    if (_phpPendingMsg) {
        var pending = _phpPendingMsg;
        _phpPendingMsg = null;
        var wrap = $id('mlp-php-turnstile-wrap');
        if (wrap) wrap.style.display = 'none';
        _phpChatBusy = false;
        // Re-inject the user message into the input and send
        var inp = $id('mlp-php-chat-input');
        if (inp) inp.value = pending.text;
        _sendPhpChat();
    }
}
function mlpPhpTurnstileExpired() {
    _phpTurnstileToken = '';
}
function mlpPhpEnsureTurnstile() {
    if (!MLP_PHP_TURNSTILE_KEY) return; // no site key configured — skip
    var wrap = $id('mlp-php-turnstile-wrap');
    if (!wrap) return;
    wrap.style.display = 'block';
    if (_phpTurnstileRendered) return;
    _phpTurnstileRendered = true;
    if (window.turnstile) {
        _phpTurnstileWidgetId = window.turnstile.render('#mlp-php-turnstile-widget', {
            sitekey:           MLP_PHP_TURNSTILE_KEY,
            callback:          mlpPhpTurnstileCallback,
            'expired-callback': mlpPhpTurnstileExpired,
            theme:             'dark',
            size:              'normal',
        });
    } else {
        // Load script lazily if not yet present
        if (!document.getElementById('cf-turnstile-script')) {
            var s = document.createElement('script');
            s.id  = 'cf-turnstile-script';
            s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=mlpPhpTurnstileOnLoad';
            s.async = true; s.defer = true;
            document.head.appendChild(s);
        }
        window.mlpPhpTurnstileOnLoad = function() {
            if (_phpTurnstileRendered && _phpTurnstileWidgetId === null) {
                _phpTurnstileWidgetId = window.turnstile.render('#mlp-php-turnstile-widget', {
                    sitekey:           MLP_PHP_TURNSTILE_KEY,
                    callback:          mlpPhpTurnstileCallback,
                    'expired-callback': mlpPhpTurnstileExpired,
                    theme:             'dark',
                    size:              'normal',
                });
            }
        };
    }
}

/* ── Helpers ──────────────────────────────────────────────────────────── */
function $id(id) { return document.getElementById(id); }

/* ── Project storage — localStorage ──────────────────────────────────── */
function phpGetProjects() {
    try { return JSON.parse(localStorage.getItem(MLP_PHP_LS)) || []; } catch(e) { return []; }
}
function phpGetProject(id) { return phpGetProjects().find(function(p){ return p && p.id === id; }) || null; }
function phpUpdateProject(id, patch) {
    var arr = phpGetProjects();
    for (var i = 0; i < arr.length; i++) {
        if (arr[i] && arr[i].id === id) { Object.assign(arr[i], patch); break; }
    }
    try { localStorage.setItem(MLP_PHP_LS, JSON.stringify(arr)); } catch(e) {}
}

/* ── Toast ────────────────────────────────────────────────────────────── */
var _phpToastTimer = null;
function phpToast(msg, type, ms) {
    var el = $id('mlp-php-toast'); if (!el) return;
    el.textContent = msg;
    el.className = 'mlp-php-show' + (type === 'err' ? ' mlp-php-err' : type === 'succ' ? ' mlp-php-succ' : '');
    clearTimeout(_phpToastTimer);
    _phpToastTimer = setTimeout(function(){ el.className = ''; }, ms || 2500);
}

/* ── Output panel ─────────────────────────────────────────────────────── */
function phpSetOutputMode(mode) {
    var wrap    = $id('mlp-php-output-wrap');
    var tabOut  = $id('mlp-php-tab-output');
    var tabPrev = $id('mlp-php-tab-preview');
    var tabVars = $id('mlp-php-tab-vars');
    if (!wrap) return;
    wrap.classList.remove('mlp-php-mode-preview', 'mlp-php-mode-vars');
    [tabOut, tabPrev, tabVars].forEach(function(t){ if (t) t.classList.remove('mlp-php-out-tab-active'); });
    if (mode === 'preview') {
        wrap.classList.add('mlp-php-mode-preview');
        if (tabPrev) tabPrev.classList.add('mlp-php-out-tab-active');
    } else if (mode === 'vars') {
        wrap.classList.add('mlp-php-mode-vars');
        if (tabVars) tabVars.classList.add('mlp-php-out-tab-active');
    } else {
        if (tabOut) tabOut.classList.add('mlp-php-out-tab-active');
    }
}
/* Script injected into every preview so form submits and link clicks come back to us */
var _PHP_FORM_INTERCEPT = '<script>(function(){' +
    'function ser(f){var o={};try{new FormData(f).forEach(function(v,k){o[k]=v;});}catch(e){}return o;}' +
    /* intercept form submits */
    'document.addEventListener("submit",function(e){' +
    '  e.preventDefault();e.stopPropagation();' +
    '  var d=ser(e.target);' +
    '  var m=(e.target.method||"get").toUpperCase();' +
    '  if(m==="GET"){' +
    '    try{var u=new URL(e.target.action||location.href);u.searchParams.forEach(function(v,k){d[k]=v;});}catch(x){}' +
    '  }' +
    '  window.parent.postMessage({type:"mlp-php-form",method:m,data:d,action:e.target.action||""},"*");' +
    '});' +
    /* intercept anchor link clicks — treat as GET re-run with query params */
    'document.addEventListener("click",function(e){' +
    '  var a=e.target.closest("a");' +
    '  if(!a)return;' +
    '  var h=a.getAttribute("href")||"";' +
    '  if(!h||h=="#"||h.charAt(0)==="#"||h.indexOf("javascript:")==0)return;' +
    '  e.preventDefault();e.stopPropagation();' +
    '  try{' +
    '    var base=location.href.split("?")[0];' +
    '    var u=new URL(h,base);' +
    '    var d={};u.searchParams.forEach(function(v,k){d[k]=v;});' +
    '    window.parent.postMessage({type:"mlp-php-form",method:"GET",data:d,action:h},"*");' +
    '  }catch(ex){}' +
    '});' +
    '})()\x3c/script>';

function phpWrapHtml(html) {
    var intercepted = html.replace(/<\/head>/i, _PHP_FORM_INTERCEPT + '</head>');
    /* If no </head> found (fragment), wrap whole thing */
    if (intercepted === html) {
        return '<!DOCTYPE html><html><head><meta charset="utf-8">' +
               '<meta name="viewport" content="width=device-width,initial-scale=1">' +
               '<style>body{margin:0;padding:8px;font-family:sans-serif}</style>' +
               _PHP_FORM_INTERCEPT + '</head><body>' + html + '</body></html>';
    }
    /* Full document but no explicit <html> wrap needed — just inject */
    return intercepted;
}

function phpShowPreview(html) {
    var frame = $id('mlp-php-preview-frame'); if (!frame) return;
    var wrapped = phpWrapHtml(html);
    frame.srcdoc = wrapped;
    phpSetOutputMode('preview');
    /* keep fullscreen frame in sync if it is currently open */
    var fs = $id('mlp-php-preview-fs');
    if (fs && fs.classList.contains('mlp-php-fs-active')) {
        var fsFrame = $id('mlp-php-preview-fs-frame');
        if (fsFrame) fsFrame.srcdoc = wrapped;
    }
}
function phpUpdateFsPreview(html) {
    var fsFrame = $id('mlp-php-preview-fs-frame'); if (!fsFrame) return;
    fsFrame.srcdoc = phpWrapHtml(html);
}

/* ── Re-run PHP with simulated POST/GET from an iframe form submit ─────── */
function phpPhpArray(obj) {
    var pairs = Object.keys(obj || {}).map(function(k) {
        var ek = k.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
        var ev = String(obj[k]).replace(/\\/g,'\\\\').replace(/'/g,"\\'");
        return "'" + ek + "'=>'" + ev + "'";
    });
    return 'array(' + pairs.join(',') + ')';
}

function phpHandleFormSubmit(method, formData) {
    if (phpRunning) return; /* ignore if already executing */
    var code = phpEditor ? phpEditor.getValue() : '';
    if (!code.trim()) return;

    /* Prepend a PHP block that overrides the superglobals the user's code reads.
       Open/close tags are split across string concatenations so PHP's tag scanner
       never sees them as real PHP delimiters in the raw output section. */
    var _o = '<' + '?php\n';
    var _c = '\n?' + '>\n';
    var preamble = _o +
        '$_SERVER[\'REQUEST_METHOD\'] = \'' + method + '\';\n';
    if (method === 'POST') {
        preamble += '$_POST = ' + phpPhpArray(formData) + ';\n';
    } else {
        preamble += '$_GET = ' + phpPhpArray(formData) + ';\n';
    }
    preamble += '$_REQUEST = array_merge($_GET ?? [], $_POST ?? []);' + _c;

    var fullCode = phpBuildCodeWithVarsDump(preamble + code);
    phpClearOutput();
    setPhpStatus('Running…');
    var wsUrl = phpDeriveWsUrl();
    if (wsUrl && window.WebSocket) {
        phpRunCodeWs(fullCode, wsUrl);
    } else {
        phpRunCodeFetch(fullCode);
    }
}
function phpClearOutput() {
    var el    = $id('mlp-php-output');        if (el)    el.innerHTML = '';
    var frame = $id('mlp-php-preview-frame'); if (frame) frame.srcdoc = '';
    var vars  = $id('mlp-php-vars');          if (vars)  vars.innerHTML = '';
    phpSetOutputMode('output');
}

/* ── Variables dump helpers ───────────────────────────────────────────── */
var _MLP_VARS_START = '__MLP_VARS_DUMP_START__';
var _MLP_VARS_END   = '__MLP_VARS_DUMP_END__';

function phpBuildCodeWithVarsDump(code) {
    var _o = '<' + '?php\n', _c = '\n?' + '>\n';
    var dump = '\n' + _o +
        'echo "\\n' + _MLP_VARS_START + '\\n";\n' +
        'try {\n' +
        '  $__d = get_defined_vars();\n' +
        '  $__skip = ["__d","__skip","__k","GLOBALS","argv","argc","_SERVER","_ENV","_GET","_POST","_COOKIE","_FILES","_SESSION","_REQUEST","HTTP_RAW_POST_DATA"];\n' +
        '  foreach ($__skip as $__k) unset($__d[$__k]);\n' +
        '  echo json_encode($__d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);\n' +
        '} catch (\\Throwable $__e) { echo "{}"; }\n' +
        'echo "\\n' + _MLP_VARS_END + '\\n";\n' +
        _c;
    return code + dump;
}

function phpExtractVarsDump(raw) {
    if (!raw) return { output: raw || '', vars: null };
    var si = raw.indexOf(_MLP_VARS_START);
    if (si === -1) return { output: raw, vars: null };
    var lineEnd = raw.indexOf('\n', si);
    var ei      = raw.indexOf(_MLP_VARS_END, lineEnd > -1 ? lineEnd : si);
    var jsonStr = (lineEnd !== -1 && ei !== -1) ? raw.substring(lineEnd + 1, ei).trim() : '';
    var tail    = (ei !== -1) ? raw.substring(ei + _MLP_VARS_END.length) : '';
    var cleanOut = (raw.substring(0, si) + tail).replace(/\n{3,}/g, '\n\n').trim();
    var vars = null;
    if (jsonStr) { try { vars = JSON.parse(jsonStr); } catch(e) {} }
    return { output: cleanOut, vars: vars };
}

function phpRenderVars(vars) {
    var panel = $id('mlp-php-vars');
    if (!panel) return;
    panel.innerHTML = '';
    if (!vars || typeof vars !== 'object' || !Object.keys(vars).length) {
        panel.innerHTML = '<div class="mlp-var-empty">No variables defined</div>';
        _phpPrevVars = vars;
        return;
    }
    Object.keys(vars).forEach(function(k) {
        var v   = vars[k];
        var row = document.createElement('div'); row.className = 'mlp-var-row';
        /* change detection */
        var badge = null;
        if (_phpPrevVars !== null) {
            var currStr = JSON.stringify(v);
            if (!Object.prototype.hasOwnProperty.call(_phpPrevVars, k)) {
                row.classList.add('mlp-var-row-changed');
                badge = document.createElement('span'); badge.className = 'mlp-var-badge-new'; badge.textContent = 'new';
            } else if (JSON.stringify(_phpPrevVars[k]) !== currStr) {
                row.classList.add('mlp-var-row-changed');
                badge = document.createElement('span'); badge.className = 'mlp-var-badge-changed'; badge.textContent = '↑';
            }
        }
        var nameEl = document.createElement('span');
        nameEl.className = 'mlp-var-name'; nameEl.textContent = '$' + k; nameEl.title = '$' + k;
        var type = Array.isArray(v) ? 'array' : (v === null ? 'null' : typeof v);
        var typeEl = document.createElement('span');
        typeEl.className = 'mlp-var-type'; typeEl.textContent = type;
        var valEl = document.createElement('span');
        var valCls, valTxt;
        if      (v === null)           { valCls = 'mlp-var-val-null'; valTxt = 'null'; }
        else if (type === 'boolean')   { valCls = 'mlp-var-val-bool'; valTxt = v ? 'true' : 'false'; }
        else if (type === 'number')    { valCls = 'mlp-var-val-num';  valTxt = String(v); }
        else if (type === 'string')    { valCls = 'mlp-var-val-str';  valTxt = '"' + v.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n') + '"'; }
        else if (type === 'array')     { valCls = 'mlp-var-val-arr';  valTxt = JSON.stringify(v, null, 2); }
        else                           { valCls = 'mlp-var-val-obj';  valTxt = JSON.stringify(v, null, 2); }
        valEl.className = 'mlp-var-val ' + valCls;
        valEl.textContent = valTxt;
        row.appendChild(nameEl); row.appendChild(typeEl); row.appendChild(valEl);
        if (badge) row.appendChild(badge);
        panel.appendChild(row);
    });
    _phpPrevVars = vars;
}
function phpAppendOutput(text, cls) {
    var el = $id('mlp-php-output'); if (!el) return;
    var span = document.createElement('span');
    span.className = 'mlp-php-out-line' + (cls ? ' ' + cls : '');
    span.textContent = text;
    el.appendChild(span);
    el.scrollTop = el.scrollHeight;
}
function phpOutputContainsHtml(str) {
    return /<[a-z][\s\S]*>/i.test(str);
}
var _phpFsDevice = 'desktop';
var _phpFsDeviceSizes = { desktop: null, tablet: 768, mobile: 390 };
var _phpFsDeviceLabels = { desktop: '— Desktop —', tablet: '— Tablet  768 px —', mobile: '— Mobile  390 px —' };

function phpFsSetDevice(device) {
    _phpFsDevice = device;
    var wrap     = $id('mlp-php-fs-frame-wrap');
    var viewport = $id('mlp-php-fs-viewport');
    var label    = $id('mlp-php-fs-device-label');
    var w = _phpFsDeviceSizes[device];
    if (wrap) wrap.style.width = w ? w + 'px' : '100%';
    if (viewport) {
        if (w) viewport.classList.add('mlp-php-fs-framed');
        else   viewport.classList.remove('mlp-php-fs-framed');
    }
    if (label) label.textContent = _phpFsDeviceLabels[device] || '';
    document.querySelectorAll('.mlp-php-fs-device-btn').forEach(function(btn) {
        if (btn.getAttribute('data-device') === device) btn.classList.add('mlp-php-fs-dev-active');
        else btn.classList.remove('mlp-php-fs-dev-active');
    });
}
function phpOpenPreviewFs() {
    var src     = $id('mlp-php-preview-frame');
    var fsFrame = $id('mlp-php-preview-fs-frame');
    var fs      = $id('mlp-php-preview-fs');
    if (!fs || !fsFrame) return;
    fsFrame.srcdoc = src ? (src.srcdoc || '') : '';
    phpFsSetDevice(_phpFsDevice);
    fs.classList.add('mlp-php-fs-active');
    document.documentElement.style.overflow = 'hidden';
}
function phpClosePreviewFs() {
    var fs = $id('mlp-php-preview-fs');
    if (!fs) return;
    fs.classList.remove('mlp-php-fs-active');
    document.documentElement.style.overflow = '';
}
function phpFilterOutput(str) {
    if (!str) return str;
    return str.split('\n').filter(function(line) {
        return !/^(Warning|Notice|Deprecated|Strict Standards):\s.+\sin\s\/tmp\/.+\.php\son\s(line\s)?\d+\s*$/i.test(line.trim());
    }).join('\n').replace(/^\n+/, '');
}

/* ── Status bar ───────────────────────────────────────────────────────── */
function setPhpStatus(msg) { var el = $id('mlp-php-status-msg');  if (el) el.textContent = msg || ''; }
function setPhpSave(msg)   { var el = $id('mlp-php-status-save'); if (el) el.textContent = msg || ''; }

/* ── Interactive input row helpers ───────────────────────────────────── */
var _phpWs = null;
var _wsStdoutBuf     = ''; /* accumulates stdout during a WS run to detect HTML output */
var _wsShowingOutput = true; /* becomes false once the internal vars-dump marker is seen */
var _phpPrevVars     = null; /* vars from last run, used to detect changes */

function phpDeriveWsUrl() {
    if (!MLP_PHP_RUNNER_URL) return null;
    return MLP_PHP_RUNNER_URL
        .replace(/^https:\/\//i, 'wss://')
        .replace(/^http:\/\//i,  'ws://')
        .replace(/\/api\/run-php(\?.*)?$/, '/api/run-php-ws');
}

function phpShowInputRow(prompt) {
    var row   = $id('mlp-php-input-row');
    var prEl  = $id('mlp-php-input-prompt');
    var field = $id('mlp-php-input-field');
    if (!row) return;
    if (prEl) prEl.textContent = (prompt && prompt.trim()) ? prompt : '›';
    row.classList.add('mlp-php-input-active');
    if (field) { field.value = ''; setTimeout(function(){ field.focus(); }, 30); }
}

function phpHideInputRow() {
    var row = $id('mlp-php-input-row');
    if (row) row.classList.remove('mlp-php-input-active');
    var field = $id('mlp-php-input-field');
    if (field) field.value = '';
}

function phpSendInput() {
    if (!_phpWs || _phpWs.readyState !== WebSocket.OPEN) return;
    var field = $id('mlp-php-input-field');
    var val   = field ? field.value : '';
    phpHideInputRow();
    phpAppendOutput(val + '\n', '');
    _phpWs.send(JSON.stringify({ type: 'input', data: val + '\n' }));
}

/* ── Run — WebSocket-first, falls back to fetch ──────────────────────── */
var phpRunning = false;

function phpRunCode() {
    /* If already running via WebSocket, act as a Stop button */
    if (phpRunning && _phpWs) {
        try { _phpWs.close(); } catch(e) {}
        _phpWs = null;
        phpRunning = false;
        phpHideInputRow();
        setPhpRunBtnState(false);
        phpAppendOutput('\n⏹ Stopped', 'mlp-php-out-err');
        setPhpStatus('Stopped');
        return;
    }
    if (phpRunning) return;

    var code = phpEditor ? phpEditor.getValue() : '';
    if (!code.trim()) { phpAppendOutput('# (nothing to run)', 'mlp-php-out-info'); return; }

    if (!MLP_PHP_RUNNER_URL) {
        phpClearOutput();
        phpAppendOutput(
            'Runner URL not configured.\n\n' +
            'Add this to your wp-config.php:\n' +
            "  define( 'MLP_PHP_RUNNER_URL', 'https://your-slug.replit.app/api/run-php' );",
            'mlp-php-out-err'
        );
        return;
    }

    var wsUrl = phpDeriveWsUrl();
    var codeToRun = phpBuildCodeWithVarsDump(code);
    if (wsUrl && window.WebSocket) {
        phpRunCodeWs(codeToRun, wsUrl);
    } else {
        phpRunCodeFetch(codeToRun);
    }
}

/* ── WebSocket execution path ─────────────────────────────────────────── */
function phpRunCodeWs(code, wsUrl) {
    phpRunning = true;
    setPhpRunBtnState(true, true);
    phpClearOutput();
    _wsStdoutBuf     = '';
    _wsShowingOutput = true;
    phpAppendOutput('⏳ Connecting…', 'mlp-php-out-info');
    setPhpStatus('Connecting…');

    var t0 = Date.now();
    var ws  = new WebSocket(wsUrl);
    _phpWs  = ws;

    ws.onopen = function() {
        phpClearOutput();
        setPhpStatus('Running…');
        var msg = { type: 'run', code: code };
        if (MLP_PHP_SECRET) msg.secret = MLP_PHP_SECRET;
        ws.send(JSON.stringify(msg));
    };

    ws.onmessage = function(ev) {
        var msg;
        try { msg = JSON.parse(ev.data); } catch(e) { phpAppendOutput(ev.data, ''); return; }
        switch (msg.type) {
            case 'stdout': {
                var chunk = msg.data || '';
                _wsStdoutBuf += chunk;
                if (_wsShowingOutput) {
                    var mPos = _wsStdoutBuf.indexOf(_MLP_VARS_START);
                    if (mPos === -1) {
                        phpAppendOutput(chunk, '');
                    } else {
                        /* marker appeared — show only what came before it in this chunk */
                        var prevLen = _wsStdoutBuf.length - chunk.length;
                        var cutAt   = Math.max(0, mPos - prevLen);
                        if (cutAt > 0) phpAppendOutput(chunk.substring(0, cutAt), '');
                        _wsShowingOutput = false;
                    }
                }
                break;
            }
            case 'stderr':
                phpAppendOutput(msg.data || '', 'mlp-php-out-err');
                break;
            case 'input_request':
                /* PHP called readline() / fgets(STDIN) — show the input bar */
                phpAppendOutput((msg.prompt ? msg.prompt : ''), 'mlp-php-out-info');
                phpShowInputRow(msg.prompt || '');
                break;
            case 'exit': {
                phpHideInputRow();
                var elapsed = Date.now() - t0;
                var exitCode = (msg.code != null) ? msg.code : 0;
                if (msg.timedOut) {
                    phpAppendOutput('\n⏱ Timed out', 'mlp-php-out-err');
                    setPhpStatus('Timed out');
                } else if (exitCode !== 0) {
                    phpAppendOutput('\n⏹ Exit code ' + exitCode, 'mlp-php-out-err');
                    setPhpStatus('Exited with code ' + exitCode);
                } else {
                    /* extract vars dump, auto-switch to preview or vars panel.
                       Output before the marker was already streamed — do NOT re-append. */
                    var wsEx    = phpExtractVarsDump(phpFilterOutput(_wsStdoutBuf));
                    var wsFiltr = wsEx.output;
                    if (wsEx.vars !== null) phpRenderVars(wsEx.vars);
                    var wsHasVars = !!(wsEx.vars && Object.keys(wsEx.vars).length);
                    if (wsFiltr && phpOutputContainsHtml(wsFiltr)) {
                        phpShowPreview(wsFiltr);
                        phpSaveOutputToProject(wsFiltr, true);
                    } else if (wsHasVars) {
                        phpSetOutputMode('vars');
                    }
                    phpAppendOutput('\n✓ Done in ' + elapsed + ' ms', 'mlp-php-out-ok');
                    setPhpStatus('Ran successfully (' + elapsed + ' ms)');
                }
                phpRunning = false; _phpWs = null; _wsStdoutBuf = ''; _wsShowingOutput = true;
                setPhpRunBtnState(false);
                break;
            }
        }
    };

    ws.onerror = function() {
        /* WebSocket not supported by server — fall back to plain fetch */
        phpHideInputRow();
        phpRunning = false; _phpWs = null;
        phpRunCodeFetch(code);
    };

    ws.onclose = function(ev) {
        phpHideInputRow();
        if (!phpRunning) return;
        /* Server closed without sending an explicit exit message (common with some runners).
           Process whatever stdout was accumulated — never show "Connection closed" error. */
        phpRunning = false; _phpWs = null;
        setPhpRunBtnState(false);
        if (_wsStdoutBuf) {
            var cls_ex     = phpExtractVarsDump(phpFilterOutput(_wsStdoutBuf));
            var cls_filtr  = cls_ex.output;
            if (cls_ex.vars !== null) phpRenderVars(cls_ex.vars);
            var cls_hasVar = !!(cls_ex.vars && Object.keys(cls_ex.vars).length);
            if (cls_filtr && phpOutputContainsHtml(cls_filtr)) {
                phpShowPreview(cls_filtr);
                phpSaveOutputToProject(cls_filtr, true);
            } else if (cls_hasVar) {
                phpSetOutputMode('vars');
            }
            phpAppendOutput('\n✓ Done', 'mlp-php-out-ok');
            setPhpStatus('Ran successfully');
        }
        _wsStdoutBuf = ''; _wsShowingOutput = true;
    };
}

/* ── HTTP fetch fallback (no interactive input) ──────────────────────── */
function phpRunCodeFetch(code) {
    phpRunning = true;
    setPhpRunBtnState(true);
    phpClearOutput();
    phpAppendOutput('⏳ Sending to server…', 'mlp-php-out-info');
    setPhpStatus('Running…');

    var headers = { 'Content-Type': 'application/json' };
    if (MLP_PHP_SECRET) headers['X-MLP-Secret'] = MLP_PHP_SECRET;

    var t0 = Date.now();
    fetch(MLP_PHP_RUNNER_URL, {
        method:  'POST',
        headers: headers,
        body:    JSON.stringify({ code: code }),
    })
    .then(function(r) {
        if (!r.ok) {
            return r.text().then(function(t) { throw new Error('HTTP ' + r.status + ': ' + t); });
        }
        return r.json();
    })
    .then(function(data) {
        phpClearOutput();
        var ms      = Date.now() - t0;
        var fetchEx = phpExtractVarsDump(phpFilterOutput(data.output));
        var out     = fetchEx.output;
        if (fetchEx.vars !== null) phpRenderVars(fetchEx.vars);
        var hasVars = !!(fetchEx.vars && Object.keys(fetchEx.vars).length);
        if (data.timedOut) {
            if (out) phpAppendOutput(out, '');
            phpAppendOutput('\n⏱ Timed out after 10 s', 'mlp-php-out-err');
            setPhpStatus('Timed out');
        } else if (data.exitCode !== 0 && data.exitCode !== null) {
            if (out) phpAppendOutput(out, '');
            else phpAppendOutput('(no output)', 'mlp-php-out-info');
            phpAppendOutput('\n⏹ Exit code ' + data.exitCode, 'mlp-php-out-err');
            setPhpStatus('Exited with code ' + data.exitCode);
        } else {
            var isHtmlOut = !!(out && phpOutputContainsHtml(out));
            if (isHtmlOut) {
                phpShowPreview(out);
                phpAppendOutput(out, '');
            } else if (out) {
                phpAppendOutput(out, '');
                if (hasVars) phpSetOutputMode('vars');
            } else {
                if (hasVars) phpSetOutputMode('vars');
                else phpAppendOutput('(no output)', 'mlp-php-out-info');
            }
            phpSaveOutputToProject(out, isHtmlOut);
            phpAppendOutput('\n✓ Done in ' + ms + ' ms', 'mlp-php-out-ok');
            setPhpStatus('Ran successfully (' + ms + ' ms)');
        }
    })
    .catch(function(err) {
        phpClearOutput();
        phpAppendOutput('Error: ' + err.message, 'mlp-php-out-err');
        setPhpStatus('Error');
    })
    .finally(function() { phpRunning = false; setPhpRunBtnState(false); });
}

function setPhpRunBtnState(isRunning, canStop) {
    var btn = $id('mlp-php-run'); if (!btn) return;
    if (isRunning) {
        if (canStop) {
            /* WebSocket mode — show a clickable Stop button */
            btn.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><rect x="4" y="4" width="16" height="16" rx="2"/></svg> Stop';
            btn.disabled = false;
            btn.style.background = 'linear-gradient(135deg,#dc2626,#b91c1c)';
        } else {
            btn.innerHTML = '<span class="mlp-php-spinner"></span> Running…';
            btn.disabled = true;
            btn.style.background = '';
        }
    } else {
        btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run';
        btn.disabled = false;
        btn.style.background = '';
    }
}

/* ── Persist last-run output into the project record ─────────────────── */
function phpSaveOutputToProject(rawOutput, isHtml) {
    if (!_phpActiveId) return;
    phpUpdateProject(_phpActiveId, {
        phpOutput:       rawOutput  || '',
        phpOutputIsHtml: !!isHtml,
        phpOutputAt:     new Date().toISOString(),
    });
}

/* ── Save — writes code to localStorage ──────────────────────────────── */
var _phpActiveId = null;
var _phpUnsaved  = false;
function phpSaveProject() {
    if (!_phpActiveId) return;
    var code = phpEditor ? phpEditor.getValue() : '';
    var now  = Date.now();
    phpUpdateProject(_phpActiveId, { php: code, type: 'php', updatedAt: new Date(now).toISOString() });
    _phpUnsaved = false;
    setPhpSave('Saved ' + new Date(now).toLocaleTimeString());
    phpToast('Saved to localStorage', 'succ', 1800);
}

/* ── Export ───────────────────────────────────────────────────────────── */
function phpExportProject() {
    var code = phpEditor ? phpEditor.getValue() : '';
    var p    = _phpActiveId ? phpGetProject(_phpActiveId) : null;
    var name = (p && p.name) ? p.name.replace(/[^a-z0-9_\-]/gi, '_') : 'php_project';
    var blob = new Blob([code], { type: 'application/x-httpd-php' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a');
    a.href = url; a.download = name + '.php';
    document.body.appendChild(a); a.click();
    setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(url); }, 500);
    phpToast('Exported ' + name + '.php', 'succ', 2200);
}

/* ── Chat helpers ─────────────────────────────────────────────────────── */
var _phpChatBusy    = false;
var _phpUndoStack   = [];

function _openPhpChat() {
    var s = $id('mlp-php-chat-sidebar'), o = $id('mlp-php-chat-overlay'), f = $id('mlp-php-chat-fab');
    if (s) s.classList.add('mlp-php-chat-open');
    if (o) o.classList.add('mlp-php-chat-open');
    if (f) f.classList.add('mlp-php-fab-hidden');
    var inp = $id('mlp-php-chat-input');
    if (inp) setTimeout(function(){ inp.focus(); }, 100);
}
function _closePhpChat() {
    var s = $id('mlp-php-chat-sidebar'), o = $id('mlp-php-chat-overlay'), f = $id('mlp-php-chat-fab');
    if (s) s.classList.remove('mlp-php-chat-open');
    if (o) o.classList.remove('mlp-php-chat-open');
    if (f) f.classList.remove('mlp-php-fab-hidden');
}

function _buildPhpCodeBlock(lang, code) {
    var wrap   = document.createElement('div');  wrap.className = 'mlp-php-chat-code-wrap';
    var header = document.createElement('div');  header.className = 'mlp-php-chat-code-header';
    var langLbl= document.createElement('span'); langLbl.className = 'mlp-php-chat-code-lang'; langLbl.textContent = lang || 'php';
    var acts   = document.createElement('div');  acts.className = 'mlp-php-chat-code-actions';
    var copyBtn= document.createElement('button'); copyBtn.className = 'mlp-php-chat-code-copy'; copyBtn.type = 'button'; copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', function() {
        navigator.clipboard && navigator.clipboard.writeText(code).then(function() {
            copyBtn.textContent = '✓ Copied';
            setTimeout(function(){ copyBtn.textContent = 'Copy'; }, 1800);
        });
    });
    var applyBtn = document.createElement('button'); applyBtn.className = 'mlp-php-chat-code-apply'; applyBtn.type = 'button'; applyBtn.textContent = '▶ Apply';
    applyBtn.addEventListener('click', function() {
        if (!phpEditor) return;
        _phpUndoStack.push(phpEditor.getValue());
        phpEditor.setValue(code);
        phpEditor.setScrollPosition({ scrollTop: 0 });
        _phpUnsaved = true; setPhpSave('● Unsaved');
        applyBtn.textContent = '✓ Applied'; applyBtn.classList.add('mlp-php-applied');
        if (!applyBtn.parentNode.querySelector('.mlp-php-chat-undo-btn')) {
            var ub = document.createElement('button'); ub.className = 'mlp-php-chat-undo-btn'; ub.type = 'button'; ub.textContent = '↩ Undo';
            ub.addEventListener('click', function() {
                var prev = _phpUndoStack.pop();
                if (prev !== undefined) { phpEditor.setValue(prev); phpEditor.setScrollPosition({ scrollTop: 0 }); _phpUnsaved = true; setPhpSave('● Unsaved'); }
                applyBtn.textContent = '▶ Apply'; applyBtn.classList.remove('mlp-php-applied');
                ub.parentNode && ub.parentNode.removeChild(ub);
            });
            applyBtn.parentNode.appendChild(ub);
        }
    });
    acts.appendChild(copyBtn); acts.appendChild(applyBtn);
    header.appendChild(langLbl); header.appendChild(acts);
    var pre = document.createElement('pre'); pre.className = 'mlp-php-chat-code-pre'; pre.textContent = code;
    wrap.appendChild(header); wrap.appendChild(pre);
    return wrap;
}

var _phpThinkingEl = null;
function _showPhpThinking() {
    _hidePhpThinking();
    var msgs = $id('mlp-php-chat-messages'); if (!msgs) return;
    var empty = msgs.querySelector('.mlp-php-chat-empty'); if (empty) msgs.innerHTML = '';
    var bubble = document.createElement('div');
    bubble.className = 'mlp-php-thinking-bubble';
    bubble.innerHTML = '<svg width="38" height="16" viewBox="0 0 38 16" fill="none"><circle class="mlp-php-think-dot" cx="7" cy="8" r="3.5" fill="#a78bfa"/><circle class="mlp-php-think-dot" cx="19" cy="8" r="3.5" fill="#a78bfa"/><circle class="mlp-php-think-dot" cx="31" cy="8" r="3.5" fill="#a78bfa"/></svg><span class="mlp-php-thinking-label">AI is thinking…</span>';
    msgs.appendChild(bubble);
    msgs.scrollTop = msgs.scrollHeight;
    _phpThinkingEl = bubble;
}
function _hidePhpThinking() {
    if (_phpThinkingEl && _phpThinkingEl.parentNode) _phpThinkingEl.parentNode.removeChild(_phpThinkingEl);
    _phpThinkingEl = null;
}

function _appendPhpChatMsg(role, text) {
    var msgs = $id('mlp-php-chat-messages'); if (!msgs) return;
    var empty = msgs.querySelector('.mlp-php-chat-empty'); if (empty) msgs.innerHTML = '';
    var bubble = document.createElement('div');
    bubble.className = 'mlp-php-chat-msg ' + role;
    if (role === 'assistant') {
        var parts = text.split(/(```[\w]*\n[\s\S]*?```)/g);
        parts.forEach(function(part) {
            var fenced = part.match(/^```([\w]*)\n([\s\S]*?)```$/);
            if (fenced) {
                bubble.appendChild(_buildPhpCodeBlock(fenced[1] || 'php', fenced[2].replace(/\n$/, '')));
            } else if (part.trim()) {
                var span = document.createElement('span'); span.textContent = part; bubble.appendChild(span);
            }
        });
    } else {
        bubble.textContent = text;
    }
    msgs.appendChild(bubble);
    msgs.scrollTop = msgs.scrollHeight;
}

function _sendPhpChat() {
    if (_phpChatBusy) return;
    var input = $id('mlp-php-chat-input');
    var text  = input ? input.value.trim() : '';
    if (!text) return;
    if (input) input.value = '';
    _appendPhpChatMsg('user', text);
    _phpChatBusy = true;
    _showPhpThinking();

    var chatKey = 'mlp_php_chat_' + (_phpActiveId || 'default');
    var history = [];
    try { history = JSON.parse(localStorage.getItem(chatKey)) || []; } catch(e) {}
    history.push({ role: 'user', content: text });
    try { localStorage.setItem(chatKey, JSON.stringify(history.slice(-20))); } catch(e) {}

    var phpCode = phpEditor ? phpEditor.getValue() : '';
    _phpLastSentText = text;   // stored so Turnstile callback can retry
    _phpLastSentCode = phpCode;
    var fd = new FormData();
    fd.append('action',   'mlp_ai_chat_php');
    fd.append('nonce',    (window.mlp_ajax && window.mlp_ajax.nonce) ? window.mlp_ajax.nonce : '');
    fd.append('message',  text);
    fd.append('php_code', phpCode);
    fd.append('history',  JSON.stringify(history.slice(-12, -1)));
    if (_phpTurnstileToken) fd.append('turnstile_token', _phpTurnstileToken);

    var ajaxUrl = (window.mlp_ajax && window.mlp_ajax.ajaxurl) ? window.mlp_ajax.ajaxurl : '';
    if (!ajaxUrl) { _hidePhpThinking(); _appendPhpChatMsg('assistant', '⚠ AI chat not configured.'); _phpChatBusy = false; return; }

    fetch(ajaxUrl, { method: 'POST', body: fd })
        .then(function(r){ return r.json(); })
        .then(function(data) {
            _hidePhpThinking();
            if (data.success && data.data && data.data.reply) {
                history.push({ role: 'assistant', content: data.data.reply });
                try { localStorage.setItem(chatKey, JSON.stringify(history.slice(-20))); } catch(e) {}
                _appendPhpChatMsg('assistant', data.data.reply);
            } else {
                var errMsg = (data.data && data.data.message) || 'AI unavailable.';
                // If the server needs Turnstile verification, show the widget & queue retry
                if (errMsg.indexOf('human verification') !== -1 || errMsg.indexOf('verification') !== -1) {
                    // Store the pending message so the callback can retry it
                    _phpPendingMsg = { text: _phpLastSentText, phpCode: _phpLastSentCode };
                    mlpPhpEnsureTurnstile();
                    // Show a prompt in the chat
                    _appendPhpChatMsg('assistant', '⚠ Please complete the security check above, then your message will be sent automatically.');
                } else {
                    _appendPhpChatMsg('assistant', '⚠ ' + errMsg);
                }
            }
        })
        .catch(function(err) { _hidePhpThinking(); _appendPhpChatMsg('assistant', '⚠ Network error: ' + err.message); })
        .finally(function() { _phpChatBusy = false; });
}

/* ── Monaco editor ────────────────────────────────────────────────────── */
var phpEditor      = null;
var phpMonacoReady = false;

function phpMountMonaco(initialCode) {
    var container = $id('mlp-php-editor'); if (!container) return;
    phpEditor = window.monaco.editor.create(container, {
        value:    initialCode || '\x3C?php\n\n$username = $_POST["username"] ?? "";\n\n$message = $username ? "Hello $username!" : "";\n\n?>\n\n\n\n<form method="POST">\n\n<input type="text" name="username" placeholder="Enter your username" required>\n\n<button type="submit">Submit</button>\n\n</form>\n\n\n\n\n\n\x3C?php if ($message) echo "<h3>$message</h3>"; ?>\n',
        language: 'php',
        theme:    'vs-dark',
        fontSize: 14, lineHeight: 22,
        minimap:  { enabled: false },
        scrollBeyondLastLine: false,
        wordWrap: 'on',
        automaticLayout: true,
        tabSize: 4, insertSpaces: true,
        fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
        fontLigatures: true,
        cursorBlinking: 'smooth',
        smoothScrolling: true,
        renderLineHighlight: 'all',
    });

    phpEditor.onDidChangeCursorPosition(function() {
        var pos = phpEditor.getPosition();
        var el = $id('mlp-php-status-pos');
        if (el && pos) el.textContent = 'Ln ' + pos.lineNumber + ', Col ' + pos.column;
    });
    phpEditor.onDidChangeModelContent(function() {
        if (!_phpUnsaved) { _phpUnsaved = true; setPhpSave('● Unsaved'); }
    });
    phpEditor.addCommand(window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.Enter, phpRunCode);
    phpEditor.addCommand(window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.KeyS, function(){ phpSaveProject(); phpEditor.focus(); });
    phpEditor.addCommand(window.monaco.KeyMod.CtrlCmd | window.monaco.KeyMod.Shift | window.monaco.KeyCode.KeyF, togglePhpFullscreen);
}

function phpWaitForMonaco(code) {
    if (window.monaco && window.monaco.editor) { phpMonacoReady = true; phpMountMonaco(code); return; }
    var t = setInterval(function() {
        if (window.monaco && window.monaco.editor) { clearInterval(t); phpMonacoReady = true; phpMountMonaco(code); }
    }, 100);
}

/* ── Open / Close ─────────────────────────────────────────────────────── */
function openPhpEditor(projectId) {
    var p = phpGetProject(projectId);
    if (!p || p.type !== 'php') return;
    _phpActiveId = projectId;
    _phpUnsaved  = false;

    var nameEl = $id('mlp-php-name');
    if (nameEl) nameEl.textContent = p.name || 'Untitled';

    $id('mlp-php-overlay').classList.add('mlp-php-active');
    document.documentElement.classList.add('mlp-php-editor-active');

    setPhpSave('');
    setPhpStatus('Ready');
    _phpPrevVars = null;
    phpClearOutput();
    phpAppendOutput('# Press Run (▶) or Ctrl+Enter to execute your PHP code.', 'mlp-php-out-info');
    phpAppendOutput('# For security reasons. we block some fonctions.', 'mlp-php-out-info');

    if (phpMonacoReady && window.monaco) {
        if (!phpEditor) { phpMountMonaco(p.php || ''); }
        else { phpEditor.setValue(p.php || ''); phpEditor.setScrollPosition({ scrollTop: 0 }); }
    } else { phpWaitForMonaco(p.php || ''); }

    /* Chat wiring */
    var chatFab = $id('mlp-php-chat-fab');
    if (chatFab) { chatFab.classList.remove('mlp-php-fab-hidden'); if (!chatFab._phpWired) { chatFab.addEventListener('click', _openPhpChat); chatFab._phpWired = true; } }
    var chatClose = $id('mlp-php-chat-close');     if (chatClose)   { var nc = chatClose.cloneNode(true);   chatClose.parentNode.replaceChild(nc, chatClose);   nc.addEventListener('click', _closePhpChat); }
    var chatSend  = $id('mlp-php-chat-send');      if (chatSend)    { var ns = chatSend.cloneNode(true);    chatSend.parentNode.replaceChild(ns, chatSend);     ns.addEventListener('click', _sendPhpChat); }
    var chatOvl   = $id('mlp-php-chat-overlay');   if (chatOvl)     chatOvl.addEventListener('click', _closePhpChat);
    var chatInp   = $id('mlp-php-chat-input');
    if (chatInp && !chatInp._phpWired) {
        chatInp._phpWired = true;
        chatInp.addEventListener('keydown', function(e) { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); _sendPhpChat(); } });
    }
}

function closePhpEditor() {
    if (_phpUnsaved && !confirm('You have unsaved changes. Leave without saving?')) return;
    $id('mlp-php-overlay').classList.remove('mlp-php-active');
    document.documentElement.classList.remove('mlp-php-editor-active');
    _closePhpChat();
    var fab = $id('mlp-php-chat-fab'); if (fab) fab.classList.add('mlp-php-fab-hidden');
    _phpActiveId = null; _phpUnsaved = false;
    /* Reopen the projects overlay — do NOT fall through to the HTML editor */
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

/* ── Resizer ──────────────────────────────────────────────────────────── */
(function(){
    var resizer = $id('mlp-php-resizer'), output = $id('mlp-php-output-wrap');
    if (!resizer || !output) return;
    var dragging = false, startX = 0, startW = 0;
    resizer.addEventListener('mousedown', function(e) {
        dragging = true; startX = e.clientX; startW = output.offsetWidth;
        resizer.classList.add('mlp-php-dragging'); document.body.style.userSelect = 'none';
    });
    document.addEventListener('mousemove', function(e) {
        if (!dragging) return;
        var newW = Math.max(220, Math.min(startW + (startX - e.clientX), window.innerWidth * 0.7));
        output.style.width = newW + 'px';
        if (phpEditor) phpEditor.layout();
    });
    document.addEventListener('mouseup', function() {
        if (!dragging) return;
        dragging = false; resizer.classList.remove('mlp-php-dragging'); document.body.style.userSelect = '';
    });
})();

/* ── Fullscreen ───────────────────────────────────────────────────────── */
function togglePhpFullscreen() {
    var o = $id('mlp-php-overlay'); if (!o) return;
    o.classList.toggle('mlp-php-fullscreen');
    if (phpEditor) phpEditor.layout();
}

/* ── Global entry point ───────────────────────────────────────────────── */
window.mlpOpenPhpEditor = openPhpEditor;

/* ── Event wiring ─────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
    var back   = $id('mlp-php-back');        if (back)   back.addEventListener('click',   closePhpEditor);
    var run    = $id('mlp-php-run');         if (run)    run.addEventListener('click',    phpRunCode);
    var save   = $id('mlp-php-save');        if (save)   save.addEventListener('click',   phpSaveProject);
    var exp    = $id('mlp-php-export');      if (exp)    exp.addEventListener('click',    phpExportProject);
    var clr    = $id('mlp-php-clear-btn');   if (clr)    clr.addEventListener('click',    phpClearOutput);
    /* Interactive input row */
    var inputSend  = $id('mlp-php-input-send');
    var inputField = $id('mlp-php-input-field');
    if (inputSend)  inputSend.addEventListener('click', phpSendInput);
    if (inputField) inputField.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') { e.preventDefault(); phpSendInput(); }
    });
    /* Catch form submits from inside the preview iframe */
    window.addEventListener('message', function(e) {
        if (!e.data || e.data.type !== 'mlp-php-form') return;
        phpHandleFormSubmit(e.data.method || 'GET', e.data.data || {});
    });
    var fs     = $id('mlp-php-fullscreen-btn'); if (fs)  fs.addEventListener('click',     togglePhpFullscreen);
    var tabOut  = $id('mlp-php-tab-output');  if (tabOut)  tabOut.addEventListener('click',  function(){ phpSetOutputMode('output'); });
    var tabPrev = $id('mlp-php-tab-preview'); if (tabPrev) tabPrev.addEventListener('click', function(){ phpSetOutputMode('preview'); });
    var tabVars = $id('mlp-php-tab-vars');    if (tabVars) tabVars.addEventListener('click', function(){ phpSetOutputMode('vars'); });
    var fsbtn  = $id('mlp-php-preview-fs-btn');  if (fsbtn)  fsbtn.addEventListener('click',  phpOpenPreviewFs);
    var fsback = $id('mlp-php-preview-fs-back'); if (fsback) fsback.addEventListener('click', phpClosePreviewFs);
    document.querySelectorAll('.mlp-php-fs-device-btn').forEach(function(btn) {
        btn.addEventListener('click', function(){ phpFsSetDevice(btn.getAttribute('data-device')); });
    });
    phpFsSetDevice('desktop');

    document.addEventListener('keydown', function(e) {
        if (!_phpActiveId) return;
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); phpRunCode(); }
        if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); phpSaveProject(); }
        if (e.key === 'Escape') {
            var fsEl = $id('mlp-php-preview-fs');
            if (fsEl && fsEl.classList.contains('mlp-php-fs-active')) { phpClosePreviewFs(); return; }
            var o = $id('mlp-php-overlay');
            if (o && o.classList.contains('mlp-php-active')) closePhpEditor();
        }
    });
});

})();
</script>
        <?php
    }
}
