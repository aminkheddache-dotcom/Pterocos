<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class MLP_CSharp {
    public static function init() {
        add_action( 'wp_head',   [ __CLASS__, 'output_styles'  ], 99 );
        add_action( 'wp_footer', [ __CLASS__, 'output_editor'  ],  6 );
    }

    public static function output_styles() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) {
            return;
        }
        ?>
<style id="mlp-csharp-styles">
/* ── C# Editor Overlay ─────────────────────────────── */
#mlp-csharp-overlay {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 99999;
    background: var(--mlp-bg, #0e0e0e);
    flex-direction: column;
    font-family: var(--mlp-font, 'JetBrains Mono', 'Fira Code', monospace);
    overflow: hidden;
}
#mlp-csharp-overlay.mlp-cs-active { display: flex; }

/* Topbar */
#mlp-cs-topbar {
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
#mlp-cs-back {
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
#mlp-cs-back:hover { border-color: #8b5cf6; color: #8b5cf6; }
#mlp-cs-title {
    flex: 1;
    font-size: .83rem;
    font-weight: 700;
    color: var(--mlp-text, #f0f0f0);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
}
#mlp-cs-title span {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 8px;
    background: rgba(139,92,246,.15);
    color: #a78bfa;
    border-radius: 4px;
    font-size: .62rem;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    margin-left: 8px;
}
.mlp-cs-btn {
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
.mlp-cs-btn:disabled { opacity: .5; cursor: not-allowed; }
#mlp-cs-run {
    background: linear-gradient(135deg, #7c3aed, #6d28d9);
    color: #fff;
    border-color: transparent;
    box-shadow: 0 1px 6px rgba(124,58,237,.35);
}
#mlp-cs-run:hover:not(:disabled) { opacity: .88; }
#mlp-cs-save {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
}
#mlp-cs-save:hover:not(:disabled) { border-color: #8b5cf6; color: #8b5cf6; }
#mlp-cs-export {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
}
#mlp-cs-export:hover:not(:disabled) { border-color: #a78bfa; color: #a78bfa; }
#mlp-cs-fullscreen-btn {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
    padding: 5px 9px;
}
#mlp-cs-fullscreen-btn:hover { border-color: #a78bfa; color: #a78bfa; }

/* Templates tab-bar button */
.mlp-cs-tpl-tab-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 0 13px;
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
    margin-left: 4px;
    border-left: 1px solid var(--mlp-border, #2a2a2a);
}
.mlp-cs-tpl-tab-btn:hover { color: #a78bfa; }
#mlp-cs-tpl-menu {
    position: fixed;
    z-index: 999997;
    background: var(--mlp-surface, #161616);
    border: 1px solid var(--mlp-border, #2a2a2a);
    border-radius: 8px;
    min-width: 235px;
    box-shadow: 0 8px 32px rgba(0,0,0,.55);
    padding: 5px 0;
    display: none;
    overflow: hidden;
}
#mlp-cs-tpl-menu.mlp-cs-tpl-open { display: block; }
.mlp-cs-tpl-item {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px 14px;
    cursor: pointer;
    transition: background .12s;
    border: none;
    background: transparent;
    width: 100%;
    text-align: left;
    font-family: inherit;
}
.mlp-cs-tpl-item:hover { background: rgba(139,92,246,.14); }
.mlp-cs-tpl-name {
    font-size: .75rem;
    font-weight: 700;
    color: var(--mlp-text, #f0f0f0);
}
.mlp-cs-tpl-desc {
    font-size: .65rem;
    color: var(--mlp-text-muted, #888);
}
.mlp-cs-tpl-divider {
    height: 1px;
    background: var(--mlp-border, #2a2a2a);
    margin: 4px 0;
}

/* Floating AI Chat FAB */
#mlp-cs-chat-fab {
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
    display: none;
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
#mlp-cs-chat-fab.mlp-cs-fab-visible { display: inline-flex; }
#mlp-cs-chat-fab:hover { opacity: .9; transform: translateY(-2px); box-shadow: 0 6px 22px rgba(124,58,237,.55); }
#mlp-cs-chat-fab.mlp-cs-fab-hidden { opacity: 0; pointer-events: none; transform: translateY(6px); }

/* Fullscreen */
#mlp-csharp-overlay.mlp-cs-fullscreen #mlp-cs-topbar,
#mlp-csharp-overlay.mlp-cs-fullscreen #mlp-cs-tabbar,
#mlp-csharp-overlay.mlp-cs-fullscreen #mlp-cs-statusbar { display: none !important; }
#mlp-csharp-overlay.mlp-cs-fullscreen #mlp-cs-output-wrap { display: none !important; }
#mlp-csharp-overlay.mlp-cs-fullscreen #mlp-cs-resizer { display: none !important; }

/* Tab bar */
#mlp-cs-tabbar {
    display: flex;
    align-items: center;
    padding: 0 14px;
    height: 36px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
    overflow-x: auto;
}
.mlp-cs-tab {
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
.mlp-cs-tab .mlp-cs-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.mlp-cs-tab.mlp-cs-tab-active { color: var(--mlp-text, #f0f0f0); border-bottom-color: #8b5cf6; }

/* Main split */
#mlp-cs-main {
    flex: 1;
    display: flex;
    flex-direction: row;
    overflow: hidden;
    min-height: 0;
}
#mlp-cs-editor-wrap {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    position: relative;
}
#mlp-cs-editor {
    flex: 1;
    min-height: 0;
    width: 100%;
}

/* Resize handle */
#mlp-cs-resizer {
    width: 5px;
    background: var(--mlp-border, #2a2a2a);
    cursor: col-resize;
    flex-shrink: 0;
    transition: background .15s;
    position: relative;
    z-index: 2;
}
#mlp-cs-resizer:hover,
#mlp-cs-resizer.mlp-cs-dragging { background: #8b5cf6; }

/* Output panel */
#mlp-cs-output-wrap {
    width: 38%;
    min-width: 220px;
    max-width: 70%;
    display: flex;
    flex-direction: column;
    background: #0a0a0a;
    border-left: 1px solid var(--mlp-border, #2a2a2a);
    overflow: hidden;
}
#mlp-cs-output-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 12px;
    height: 34px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-cs-output-title {
    flex: 1;
    font-size: .68rem;
    font-weight: 700;
    color: var(--mlp-text-muted, #888);
    text-transform: uppercase;
    letter-spacing: .07em;
}
#mlp-cs-clear-btn {
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
#mlp-cs-clear-btn:hover { color: #ef4444; background: rgba(239,68,68,.1); }
#mlp-cs-output {
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
#mlp-cs-output::-webkit-scrollbar { width: 5px; }
#mlp-cs-output::-webkit-scrollbar-thumb { background: var(--mlp-border, #2a2a2a); border-radius: 3px; }
.mlp-cs-out-line { display: block; padding: 0; }
.mlp-cs-out-err  { color: #f87171; }
.mlp-cs-out-info { color: #a78bfa; font-style: italic; font-size: .72rem; }
.mlp-cs-out-ok   { color: #34d399; font-size: .72rem; }

/* Stdin section */
#mlp-cs-stdin-wrap {
    flex-shrink: 0;
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    background: #0e0e0e;
    padding: 8px 12px 10px;
    display: flex;
    flex-direction: column;
    gap: 6px;
}
#mlp-cs-stdin-header {
    display: flex;
    align-items: center;
    gap: 6px;
}
#mlp-cs-stdin-label {
    font-size: .65rem;
    font-weight: 700;
    color: var(--mlp-text-muted, #888);
    text-transform: uppercase;
    letter-spacing: .07em;
}
#mlp-cs-stdin-hint {
    font-size: .62rem;
    color: #6b7280;
    font-style: italic;
}
#mlp-cs-stdin {
    width: 100%;
    box-sizing: border-box;
    background: #0a0a0a;
    border: 1px solid var(--mlp-border, #2a2a2a);
    border-radius: 5px;
    color: #d4d4d4;
    font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
    font-size: .75rem;
    line-height: 1.55;
    padding: 6px 8px;
    resize: vertical;
    min-height: 46px;
    max-height: 120px;
    transition: border-color .15s;
    outline: none;
}
#mlp-cs-stdin:focus { border-color: #7c3aed; }
#mlp-cs-stdin::placeholder { color: #444; }
#mlp-cs-run-panel {
    align-self: flex-end;
    background: #7c3aed;
    color: #fff;
    border: none;
    border-radius: 5px;
    font-family: inherit;
    font-size: .72rem;
    font-weight: 700;
    padding: 5px 14px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    transition: background .15s, opacity .15s;
}
#mlp-cs-run-panel:hover:not(:disabled) { background: #6d28d9; }
#mlp-cs-run-panel:disabled { opacity: .5; cursor: not-allowed; }
#mlp-cs-warmup-badge {
    font-size: .6rem;
    color: #6b7280;
    font-style: italic;
    align-self: flex-end;
}

/* Status bar */
#mlp-cs-statusbar {
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
#mlp-cs-status-lang { display: inline-flex; align-items: center; gap: 4px; color: #a78bfa; font-weight: 600; }
#mlp-cs-status-msg  { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
#mlp-cs-status-pos  { white-space: nowrap; }
#mlp-cs-status-save { white-space: nowrap; font-style: italic; }

/* Toast */
#mlp-cs-toast {
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
#mlp-cs-toast.mlp-cs-show { opacity: 1; transform: translateY(0); }
#mlp-cs-toast.mlp-cs-err  { border-color: #f87171; }
#mlp-cs-toast.mlp-cs-succ { border-color: #34d399; }

/* Spinner */
@keyframes mlp-cs-spin { to { transform: rotate(360deg); } }
.mlp-cs-spinner {
    width: 12px; height: 12px;
    border: 2px solid rgba(255,255,255,.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: mlp-cs-spin .7s linear infinite;
    display: inline-block;
    flex-shrink: 0;
}

@media (max-width: 680px) {
    #mlp-cs-main { flex-direction: column; }
    #mlp-cs-output-wrap { width: 100%; max-width: 100%; min-width: 0; border-left: none; border-top: 1px solid var(--mlp-border, #2a2a2a); height: 38%; }
    #mlp-cs-resizer { display: none; }
}

/* ── C# AI Chat Sidebar ────────────────────────────────── */
#mlp-cs-chat-sidebar {
    position: fixed;
    top: 56px;
    right: 12px;
    bottom: 20px;
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
    box-shadow: -4px 8px 40px rgba(0,0,0,.55), 0 0 0 1px rgba(139,92,246,.12), -8px 0 40px rgba(139,92,246,0.12);
    overflow: hidden;
}
#mlp-cs-chat-sidebar.mlp-cs-chat-open { transform: translateX(0); }

#mlp-cs-chat-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-cs-chat-title {
    font-size: .83rem;
    font-weight: 700;
    color: var(--mlp-text, #f0f0f0);
}
#mlp-cs-chat-close {
    background: none;
    border: none;
    color: var(--mlp-text-muted, #888);
    cursor: pointer;
    padding: 4px;
    display: flex;
    align-items: center;
    transition: color .15s;
}
#mlp-cs-chat-close:hover { color: var(--mlp-text, #f0f0f0); }

#mlp-cs-chat-messages {
    flex: 1;
    overflow-y: auto;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.mlp-cs-chat-msg {
    padding: 8px 10px;
    border-radius: 6px;
    font-size: .75rem;
    line-height: 1.5;
    max-width: 95%;
    word-wrap: break-word;
}
.mlp-cs-chat-msg.user {
    background: #2e1065;
    color: #ddd6fe;
    align-self: flex-end;
    margin-left: auto;
}
.mlp-cs-chat-msg.assistant {
    background: #1f2937;
    color: #d4d4d4;
    align-self: flex-start;
}
.mlp-cs-chat-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--mlp-text-muted, #888);
    font-size: .73rem;
    text-align: center;
    padding: 20px;
}

#mlp-cs-chat-input-area {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px;
    background: var(--mlp-surface, #161616);
    border-top: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-cs-chat-input {
    width: 100%;
    padding: 8px;
    background: rgba(0,0,0,.3);
    border: 1px solid var(--mlp-border, #2a2a2a);
    border-radius: 4px;
    color: var(--mlp-text, #f0f0f0);
    font-family: inherit;
    font-size: .75rem;
    resize: none;
    max-height: 80px;
    transition: border-color .15s;
}
#mlp-cs-chat-input:focus { outline: none; border-color: #7c3aed; }
#mlp-cs-chat-send {
    align-self: flex-end;
    padding: 5px 12px;
    background: #7c3aed;
    color: #fff;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: .73rem;
    font-weight: 600;
    transition: opacity .15s;
}
#mlp-cs-chat-send:hover:not(:disabled) { opacity: .88; }
#mlp-cs-chat-send:disabled { opacity: .5; cursor: not-allowed; }

/* Markdown in chat */
.mlp-cs-chat-msg.assistant .mlp-cs-md-h2 {
    display: block; font-size: .85rem; font-weight: 700;
    color: #c4b5fd; margin: 8px 0 3px; padding-bottom: 3px;
    border-bottom: 1px solid #2a3a4a;
}
.mlp-cs-chat-msg.assistant .mlp-cs-md-h3 {
    display: block; font-size: .78rem; font-weight: 700;
    color: #a78bfa; margin: 6px 0 2px;
}
.mlp-cs-chat-msg.assistant .mlp-cs-md-code {
    font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
    font-size: .72rem; background: rgba(0,0,0,.35);
    border: 1px solid #2a2a2a; border-radius: 3px;
    padding: 0 4px; color: #fbbf24;
}
.mlp-cs-chat-msg.assistant strong { color: #f0f0f0; font-weight: 700; }
.mlp-cs-chat-msg.assistant em { color: #d1d5db; font-style: italic; }

/* Code blocks in chat */
.mlp-cs-chat-code-wrap {
    margin: 6px 0 0; border-radius: 6px; overflow: hidden;
    border: 1px solid #2a2a2a; background: #0d0d0d; max-width: 100%;
}
.mlp-cs-chat-code-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 4px 10px; background: #1a1a1a; border-bottom: 1px solid #2a2a2a;
}
.mlp-cs-chat-code-lang { font-size: .62rem; font-weight: 700; color: #a78bfa; letter-spacing: .06em; text-transform: uppercase; }
.mlp-cs-chat-code-actions { display: flex; gap: 5px; }
.mlp-cs-chat-code-apply,
.mlp-cs-chat-code-copy {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 4px; font-family: inherit;
    font-size: .65rem; font-weight: 700; cursor: pointer;
    border: 1px solid transparent; transition: opacity .15s, background .15s;
}
.mlp-cs-chat-code-apply { background: #7c3aed; color: #fff; }
.mlp-cs-chat-code-apply:hover { opacity: .85; }
.mlp-cs-chat-code-apply.mlp-cs-applied { background: #1d4ed8; }
.mlp-cs-chat-code-copy { background: transparent; border-color: #3a3a3a; color: #888; }
.mlp-cs-chat-code-copy:hover { color: #d4d4d4; border-color: #555; }
.mlp-cs-chat-code-pre {
    margin: 0; padding: 10px 12px; overflow-x: auto;
    font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
    font-size: .73rem; line-height: 1.6; color: #d4d4d4;
    white-space: pre; background: transparent;
}
.mlp-cs-chat-undo-btn {
    display: inline-flex; align-items: center; gap: 4px;
    margin-top: 4px; padding: 2px 8px; background: transparent;
    border: 1px solid #3a3a3a; border-radius: 4px; color: #f59e0b;
    font-family: inherit; font-size: .65rem; font-weight: 700;
    cursor: pointer; transition: opacity .15s;
}
.mlp-cs-chat-undo-btn:hover { opacity: .8; }

/* Thinking animation */
.mlp-cs-thinking-bubble {
    display: flex; align-items: center; gap: 10px; padding: 10px 14px;
    background: #1f2937; border-radius: 6px; border: 1px solid rgba(167,139,250,.15);
    align-self: flex-start; max-width: 95%; box-shadow: 0 0 12px rgba(167,139,250,.07);
}
.mlp-cs-thinking-label { font-size: .68rem; color: #6b7280; font-style: italic; white-space: nowrap; }
@keyframes mlp-cs-dot-wave {
    0%, 100% { transform: translateY(0); opacity: .35; }
    50% { transform: translateY(-6px); opacity: 1; }
}
@keyframes mlp-cs-dot-glow {
    0%, 100% { filter: drop-shadow(0 0 0px #a78bfa); }
    50% { filter: drop-shadow(0 0 5px #a78bfa); }
}
.mlp-cs-think-dot {
    animation: mlp-cs-dot-wave 1.3s ease-in-out infinite, mlp-cs-dot-glow 1.3s ease-in-out infinite;
}
.mlp-cs-think-dot:nth-child(2) { animation-delay: .22s; }
.mlp-cs-think-dot:nth-child(3) { animation-delay: .44s; }
@keyframes mlp-cs-ring-pulse {
    0%, 100% { opacity: .18; r: 14; }
    50% { opacity: .45; r: 16; }
}
.mlp-cs-think-ring { animation: mlp-cs-ring-pulse 1.3s ease-in-out infinite; transform-origin: center; }

#mlp-cs-chat-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,.3);
    z-index: 999990; opacity: 0; pointer-events: none;
    transition: opacity 0.25s cubic-bezier(0.4,0,0.2,1);
}
#mlp-cs-chat-overlay.mlp-cs-chat-open { opacity: 1; pointer-events: auto; }

/* Hide HTML/CSS/JS chat when C# editor is active */
html.mlp-cs-editor-active #mlpChatToggle,
html.mlp-cs-editor-active #mlpChatSidebar { display: none !important; }
</style>
        <?php
    }

    public static function output_editor() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) {
            return;
        }
        ?>
<!-- C# Editor Overlay -->
<div id="mlp-csharp-overlay" role="dialog" aria-modal="true" aria-label="C# Editor">
  <div id="mlp-cs-topbar">
    <button id="mlp-cs-back" type="button" aria-label="Back to projects">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      Projects
    </button>
    <div id="mlp-cs-title">
      <span id="mlp-cs-name">Untitled</span>
      <span>C#</span>
    </div>
    <button id="mlp-cs-run" class="mlp-cs-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
      Run
    </button>
    <button id="mlp-cs-save" class="mlp-cs-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
      Save
    </button>
    <button id="mlp-cs-export" class="mlp-cs-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Export .cs
    </button>
    <button id="mlp-cs-fullscreen-btn" class="mlp-cs-btn" type="button" title="Toggle fullscreen (Ctrl+Shift+F)">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
    </button>
  </div>
  <div id="mlp-cs-tabbar">
    <button class="mlp-cs-tab mlp-cs-tab-active" data-tab="csharp" type="button">
      <span class="mlp-cs-dot" style="background:#8b5cf6;"></span>
      Program.cs
    </button>
    <button id="mlp-cs-tpl-btn" class="mlp-cs-tpl-tab-btn" type="button" title="Load a starter template">
      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
      Templates
    </button>
  </div>
  <div id="mlp-cs-main">
    <div id="mlp-cs-editor-wrap">
      <div id="mlp-cs-editor"></div>
    </div>
    <div id="mlp-cs-resizer" role="separator" aria-orientation="vertical" aria-label="Resize panels"></div>
    <div id="mlp-cs-output-wrap">
      <div id="mlp-cs-output-header">
        <div id="mlp-cs-output-title">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline;margin-right:4px;vertical-align:middle;"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          Output
        </div>
        <button id="mlp-cs-clear-btn" type="button" title="Clear output">Clear</button>
      </div>
      <div id="mlp-cs-stdin-wrap">
        <div id="mlp-cs-stdin-header">
          <span id="mlp-cs-stdin-label">Input (stdin)</span>
          <span id="mlp-cs-stdin-hint">for Console.ReadLine()</span>
        </div>
        <textarea id="mlp-cs-stdin" placeholder="Type program input here, one value per line…" rows="2" spellcheck="false" autocorrect="off" autocapitalize="off"></textarea>
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <span id="mlp-cs-warmup-badge"></span>
          <button id="mlp-cs-run-panel" type="button">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
            Run
          </button>
        </div>
      </div>
      <div id="mlp-cs-output" aria-live="polite" aria-label="C# output"></div>
    </div>
  </div>
  <div id="mlp-cs-statusbar">
    <span id="mlp-cs-status-lang">
      <svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>
      C# / .NET
    </span>
    <span id="mlp-cs-status-msg"></span>
    <span id="mlp-cs-status-pos">Ln 1, Col 1</span>
    <span id="mlp-cs-status-save"></span>
  </div>
</div>

<!-- C# AI Chat Sidebar (starts closed) -->
<div id="mlp-cs-chat-overlay"></div>
<div id="mlp-cs-chat-sidebar">
  <div id="mlp-cs-chat-header">
    <div id="mlp-cs-chat-title">C# AI Chat</div>
    <button id="mlp-cs-chat-close" type="button" title="Close chat">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>
  <div id="mlp-cs-chat-messages">
    <div class="mlp-cs-chat-empty">Start a conversation with the C# AI assistant</div>
  </div>
  <div id="mlp-cs-chat-input-area">
    <textarea id="mlp-cs-chat-input" placeholder="Ask about your C# code..." rows="2"></textarea>
    <button id="mlp-cs-chat-send" type="button">Send</button>
  </div>
</div>

<!-- Toast -->
<div id="mlp-cs-toast"></div>

<!-- Templates dropdown (populated by JS) -->
<div id="mlp-cs-tpl-menu" role="menu" aria-label="Code templates"></div>

<!-- Floating AI Chat FAB (hidden until C# editor is open) -->
<button id="mlp-cs-chat-fab" type="button" title="Open C# AI Chat" aria-label="Open C# AI Chat">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
  AI Chat
</button>

<script>
(function(){
'use strict';

var MLP_CS_LS      = 'mlp_projects';
var MLP_CS_TS_KEY  = <?php echo json_encode( defined( 'MLP_TURNSTILE_SITE_KEY' ) ? MLP_TURNSTILE_SITE_KEY : '' ); ?>;
var WANDBOX_URL    = 'https://wandbox.org/api/compile.json';

/* ── C# Chat State ─────────────────────────────────────────── */
var _csChatHistories = {};
var _csChatBusy      = false;
var _csChatAbort     = null;
var _csTsToken       = '';
var _csTsVerified    = false;
var _csTsPending     = '';
var _csTsWidgetId    = null;
var _csTsWidgetEl    = null;
var _csUndoStack     = [];

function _getCsChatKey(id) { return 'mlp_cs_chat_' + (id || 'default'); }

function _getCsChatHistory(key) {
    if (!_csChatHistories[key]) {
        try { _csChatHistories[key] = JSON.parse(localStorage.getItem(key)) || []; }
        catch(e) { _csChatHistories[key] = []; }
    }
    return _csChatHistories[key];
}
function _saveCsChatHistory(key, h) {
    _csChatHistories[key] = h;
    try { localStorage.setItem(key, JSON.stringify(h)); } catch(e) {}
}

function _openCsChat() {
    var s = $csid('mlp-cs-chat-sidebar'), o = $csid('mlp-cs-chat-overlay'), f = $csid('mlp-cs-chat-fab');
    if (s) s.classList.add('mlp-cs-chat-open');
    if (o) o.classList.add('mlp-cs-chat-open');
    if (f) f.classList.add('mlp-cs-fab-hidden');
    var inp = $csid('mlp-cs-chat-input');
    if (inp) setTimeout(function(){ inp.focus(); }, 100);
}
function _closeCsChat() {
    var s = $csid('mlp-cs-chat-sidebar'), o = $csid('mlp-cs-chat-overlay'), f = $csid('mlp-cs-chat-fab');
    if (s) s.classList.remove('mlp-cs-chat-open');
    if (o) o.classList.remove('mlp-cs-chat-open');
    if (f) f.classList.remove('mlp-cs-fab-hidden');
}

function _applyCodeToEditor(code, btn) {
    if (!csEditor) return;
    _csUndoStack.push(csEditor.getValue());
    csEditor.setValue(code);
    csEditor.setScrollPosition({ scrollTop: 0 });
    _csUnsaved = true; setCsSave('● Unsaved');
    if (btn) { btn.textContent = '✓ Applied'; btn.classList.add('mlp-cs-applied'); }
    if (btn && btn.parentNode && !btn.parentNode.querySelector('.mlp-cs-chat-undo-btn')) {
        var ub = document.createElement('button');
        ub.className = 'mlp-cs-chat-undo-btn'; ub.type = 'button'; ub.innerHTML = '↩ Undo';
        ub.addEventListener('click', function() {
            var prev = _csUndoStack.pop();
            if (prev !== undefined) { csEditor.setValue(prev); csEditor.setScrollPosition({scrollTop:0}); _csUnsaved=true; setCsSave('● Unsaved'); }
            if (btn) { btn.textContent = '▶ Apply'; btn.classList.remove('mlp-cs-applied'); }
            ub.parentNode && ub.parentNode.removeChild(ub);
        });
        btn.parentNode.appendChild(ub);
    }
}

function _buildCsCodeBlock(lang, code) {
    var wrap = document.createElement('div'); wrap.className = 'mlp-cs-chat-code-wrap';
    var hdr  = document.createElement('div'); hdr.className  = 'mlp-cs-chat-code-header';
    var ll   = document.createElement('span'); ll.className   = 'mlp-cs-chat-code-lang'; ll.textContent = lang || 'csharp';
    var acts = document.createElement('div'); acts.className = 'mlp-cs-chat-code-actions';
    var cp   = document.createElement('button'); cp.className = 'mlp-cs-chat-code-copy'; cp.type='button'; cp.textContent='Copy';
    cp.addEventListener('click', function(){ navigator.clipboard && navigator.clipboard.writeText(code).then(function(){ cp.textContent='✓ Copied'; setTimeout(function(){ cp.textContent='Copy'; },1800); }); });
    var ap   = document.createElement('button'); ap.className = 'mlp-cs-chat-code-apply'; ap.type='button'; ap.textContent='▶ Apply';
    ap.addEventListener('click', function(){ _applyCodeToEditor(code, ap); });
    acts.appendChild(cp); acts.appendChild(ap);
    hdr.appendChild(ll); hdr.appendChild(acts);
    var pre = document.createElement('pre'); pre.className='mlp-cs-chat-code-pre'; pre.textContent=code;
    wrap.appendChild(hdr); wrap.appendChild(pre);
    return wrap;
}

var _csThinkingEl = null;
function _showCsThinking() {
    _hideCsThinking();
    var msgs = $csid('mlp-cs-chat-messages'); if (!msgs) return;
    var empty = msgs.querySelector('.mlp-cs-chat-empty'); if (empty) msgs.innerHTML = '';
    var bub = document.createElement('div'); bub.className = 'mlp-cs-thinking-bubble';
    bub.innerHTML = [
        '<svg width="38" height="16" viewBox="0 0 38 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">',
          '<defs><radialGradient id="mlp-csg1" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="#c4b5fd"/><stop offset="100%" stop-color="#8b5cf6"/></radialGradient></defs>',
          '<circle class="mlp-cs-think-ring" cx="7" cy="8" r="14" fill="#8b5cf6"/>',
          '<circle class="mlp-cs-think-dot" cx="7"  cy="8" r="3.5" fill="url(#mlp-csg1)"/>',
          '<circle class="mlp-cs-think-dot" cx="19" cy="8" r="3.5" fill="url(#mlp-csg1)"/>',
          '<circle class="mlp-cs-think-dot" cx="31" cy="8" r="3.5" fill="url(#mlp-csg1)"/>',
        '</svg>',
        '<span class="mlp-cs-thinking-label">AI is thinking\u2026</span>'
    ].join('');
    msgs.appendChild(bub); msgs.scrollTop = msgs.scrollHeight; _csThinkingEl = bub;
}
function _hideCsThinking() {
    if (_csThinkingEl && _csThinkingEl.parentNode) _csThinkingEl.parentNode.removeChild(_csThinkingEl);
    _csThinkingEl = null;
}

function _renderMdInline(text) {
    var frag = document.createDocumentFragment();
    var re = /(`[^`]+`|\*\*[\s\S]+?\*\*|\*[^*\n]+?\*)/g, last=0, m;
    while ((m = re.exec(text)) !== null) {
        if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        var t = m[0];
        if (t.startsWith('**')) { var s=document.createElement('strong'); s.textContent=t.slice(2,-2); frag.appendChild(s); }
        else if (t.startsWith('`')) { var c=document.createElement('code'); c.className='mlp-cs-md-code'; c.textContent=t.slice(1,-1); frag.appendChild(c); }
        else { var e=document.createElement('em'); e.textContent=t.slice(1,-1); frag.appendChild(e); }
        last = m.index + t.length;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    return frag;
}

function _appendCsChatMsg(role, text) {
    var msgs = $csid('mlp-cs-chat-messages'); if (!msgs) return;
    var empty = msgs.querySelector('.mlp-cs-chat-empty'); if (empty) msgs.innerHTML = '';
    var bub = document.createElement('div'); bub.className = 'mlp-cs-chat-msg ' + role;
    if (role === 'assistant') {
        var parts = text.split(/(```[\w]*\n[\s\S]*?```)/g);
        parts.forEach(function(part) {
            var fenced = part.match(/^```([\w]*)\n([\s\S]*?)```$/);
            if (fenced) {
                bub.appendChild(_buildCsCodeBlock(fenced[1] || 'csharp', fenced[2].replace(/\n$/,'')));
            } else if (part.trim()) {
                var lines = part.split('\n');
                lines.forEach(function(line, i) {
                    if (/^### /.test(line)) { var h=document.createElement('span'); h.className='mlp-cs-md-h3'; h.appendChild(_renderMdInline(line.slice(4))); bub.appendChild(h); }
                    else if (/^## /.test(line)) { var h=document.createElement('span'); h.className='mlp-cs-md-h2'; h.appendChild(_renderMdInline(line.slice(3))); bub.appendChild(h); }
                    else if (/^# /.test(line)) { var h=document.createElement('span'); h.className='mlp-cs-md-h2'; h.appendChild(_renderMdInline(line.slice(2))); bub.appendChild(h); }
                    else if (line) { var sp=document.createElement('span'); sp.appendChild(_renderMdInline(line)); bub.appendChild(sp); }
                    if (i < lines.length-1) bub.appendChild(document.createElement('br'));
                });
            }
        });
    } else { bub.textContent = text; }
    msgs.appendChild(bub); msgs.scrollTop = msgs.scrollHeight;
}

function _sendCsChat() {
    if (_csChatBusy) return;
    var input = $csid('mlp-cs-chat-input');
    var text = _csTsPending || (input && input.value.trim());
    if (!text) return;
    _csTsPending = ''; if (input) input.value = '';
    if (!_csTsVerified) {
        _csTsPending = text;
        _appendCsChatMsg('user', text);
        _appendCsChatMsg('assistant', 'Please complete the verification to continue.');
        _renderCsTurnstile(); return;
    }
    var key = _getCsChatKey(_csActiveId);
    var hist = _getCsChatHistory(key);
    hist.push({role:'user', content:text}); _saveCsChatHistory(key, hist);
    _appendCsChatMsg('user', text);
    _csChatBusy = true; _showCsThinking();
    var code = (csEditor && csEditor.getValue) ? csEditor.getValue() : '';
    var fd = new FormData();
    fd.append('action',       'mlp_ai_chat_csharp');
    fd.append('nonce',        (window.mlp_ajax && window.mlp_ajax.nonce) ? window.mlp_ajax.nonce : '');
    fd.append('message',      text);
    fd.append('csharp_code',  code);
    fd.append('turnstile_token', _csTsToken);
    fd.append('history',      JSON.stringify(hist.slice(-12,-1)));
    var url = (window.mlp_ajax && window.mlp_ajax.ajaxurl) ? window.mlp_ajax.ajaxurl : '/wp-admin/admin-ajax.php';
    _csChatAbort = new AbortController();
    fetch(url, {method:'POST', body:fd, signal:_csChatAbort.signal})
        .then(function(r){ return r.json(); })
        .then(function(data) {
            _hideCsThinking();
            var h = _getCsChatHistory(key);
            if (data.success && data.data && data.data.reply) {
                var reply = data.data.reply;
                h.push({role:'assistant', content:reply}); _saveCsChatHistory(key, h);
                _appendCsChatMsg('assistant', reply);
            } else {
                var msg = (data.data && data.data.message) ? data.data.message : 'AI unavailable. Try again later.';
                _appendCsChatMsg('assistant', '\u26a0 ' + msg);
            }
        })
        .catch(function(err) {
            _hideCsThinking();
            if (err.name !== 'AbortError') _appendCsChatMsg('assistant', '\u26a0 Network error: ' + err.message);
        })
        .finally(function() { _csChatBusy = false; _hideCsThinking(); _removeCsTurnstileWidget(); });
}

function _removeCsTurnstileWidget() {
    if (_csTsWidgetId !== null && window.turnstile) { try { window.turnstile.remove(_csTsWidgetId); } catch(e){} _csTsWidgetId=null; }
    if (_csTsWidgetEl && _csTsWidgetEl.parentNode) _csTsWidgetEl.parentNode.removeChild(_csTsWidgetEl);
    _csTsWidgetEl = null;
}
function _renderCsTurnstile() {
    if (!MLP_CS_TS_KEY) return;
    _removeCsTurnstileWidget();
    var msgs = $csid('mlp-cs-chat-messages'); if (!msgs) return;
    var cont = document.createElement('div'); cont.style.cssText='padding:6px 0;display:flex;justify-content:center;';
    var wd = document.createElement('div'); cont.appendChild(wd); msgs.appendChild(cont); msgs.scrollTop=msgs.scrollHeight;
    _csTsWidgetEl = cont;
    function doRender() {
        if (!window.turnstile || !window.turnstile.render) return;
        _csTsWidgetId = window.turnstile.render(wd, {
            sitekey: MLP_CS_TS_KEY, theme:'dark',
            callback: function(token){ _csTsToken=token; _csTsVerified=true; setTimeout(function(){ _sendCsChat(); }, 300); },
            'error-callback': function(){ _csTsVerified=false; _csTsToken=''; }
        });
    }
    if (window.turnstile && window.turnstile.render) { doRender(); }
    else {
        var s=document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]');
        if (s) {
            var prev=s.onload; s.onload=function(){ if(typeof prev==='function') prev.call(this); doRender(); };
            var _pt=0, _pi=setInterval(function(){ if(window.turnstile&&window.turnstile.render){ clearInterval(_pi); doRender(); } if(++_pt>50) clearInterval(_pi); },100);
        } else {
            s=document.createElement('script'); s.src='https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'; s.async=true; s.onload=doRender; document.head.appendChild(s);
        }
    }
}

/* ── State ──────────────────────────────────────────────────── */
var csEditor    = null;
var csMonoReady = false;
var csRunning   = false;
var _csActiveId = null;
var _csUnsaved  = false;

function $csid(id){ return document.getElementById(id); }

/* ── Project helpers ───────────────────────────────────────── */
function csGetProjects(){ try{ return JSON.parse(localStorage.getItem(MLP_CS_LS))||[]; }catch(e){ return []; } }
function csSaveProjects(arr){ try{ localStorage.setItem(MLP_CS_LS, JSON.stringify(arr)); }catch(e){} }
function csGetProject(id){ return csGetProjects().find(function(p){ return p&&p.id===id; })||null; }
function csUpdateProject(id, patch){
    var arr=csGetProjects();
    for(var i=0;i<arr.length;i++){ if(arr[i]&&arr[i].id===id){ Object.assign(arr[i],patch); break; } }
    csSaveProjects(arr);
}

/* ── Toast ─────────────────────────────────────────────────── */
var _csToastTimer=null;
function csToast(msg,type,ms){
    var el=$csid('mlp-cs-toast'); if(!el) return;
    el.textContent=msg;
    el.className='mlp-cs-show '+(type==='err'?'mlp-cs-err':type==='succ'?'mlp-cs-succ':'');
    clearTimeout(_csToastTimer);
    _csToastTimer=setTimeout(function(){ el.className=''; }, ms||2500);
}

/* ── Output helpers ────────────────────────────────────────── */
function csClearOutput(){ var el=$csid('mlp-cs-output'); if(el) el.innerHTML=''; }
function csAppendOutput(text, cls){
    var el=$csid('mlp-cs-output'); if(!el) return;
    var span=document.createElement('span');
    span.className='mlp-cs-out-line'+(cls?' '+cls:'');
    span.textContent=text;
    el.appendChild(span); el.scrollTop=el.scrollHeight;
}
function setCsStatus(msg){ var el=$csid('mlp-cs-status-msg'); if(el) el.textContent=msg||''; }
function setCsSave(msg){ var el=$csid('mlp-cs-status-save'); if(el) el.textContent=msg||''; }

/* ── Default C# code ───────────────────────────────────────── */
var CS_DEFAULT = [
'using System;',
'',
'class Program',
'{',
'    static void Main(string[] args)',
'    {',
'        Console.WriteLine("Hello, C#!");',
'        ',
'        // Try some C# features',
'        var numbers = new int[] { 1, 2, 3, 4, 5 };',
'        foreach (var n in numbers)',
'        {',
'            Console.WriteLine($"  {n} squared = {n * n}");',
'        }',
'    }',
'}'
].join('\n');

/* ── Pre-warm Wandbox (fires when editor opens) ─────────────── */
var _csWarmedUp = false;
function csWarmup() {
    if (_csWarmedUp) return;
    _csWarmedUp = true;
    var badge = $csid('mlp-cs-warmup-badge');
    if (badge) badge.textContent = 'Warming up…';
    fetch(WANDBOX_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ compiler: 'mono-6.12.0.199', code: 'class P{static void Main(){}}', stdin: '' })
    })
    .then(function() { if (badge) badge.textContent = '● Ready'; setTimeout(function(){ if(badge) badge.textContent=''; }, 3000); })
    .catch(function() { if (badge) badge.textContent = ''; });
}

/* ── Run C# via Wandbox (pure client-side, CORS-friendly) ──── */
function _csIsOciError(data) {
    var msg = (data.compiler_error || '') + (data.compiler_message || '') + (data.program_error || '');
    return /OCI runtime|crun:|Resource temporarily unavailable/i.test(msg);
}

function _csFetchWandbox(payload, attemptsLeft) {
    return fetch(WANDBOX_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(function(r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
    })
    .then(function(data) {
        if (_csIsOciError(data) && attemptsLeft > 0) {
            csAppendOutput('Server busy — retrying… (' + attemptsLeft + ' left)', 'mlp-cs-out-info');
            return new Promise(function(resolve) { setTimeout(resolve, 1800); })
                .then(function() { return _csFetchWandbox(payload, attemptsLeft - 1); });
        }
        return data;
    });
}

function csRunCode() {
    if (csRunning) return;
    var code = csEditor ? csEditor.getValue() : '';
    if (!code.trim()) { csToast('Nothing to run', 'err'); return; }
    csRunning = true;
    csClearOutput();
    var _now = new Date();
    var _ts = _now.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
    csAppendOutput('▶ Run at ' + _ts, 'mlp-cs-out-info');
    csAppendOutput('Compiling & running C#…', 'mlp-cs-out-info');
    var runBtn      = $csid('mlp-cs-run');
    var runPanelBtn = $csid('mlp-cs-run-panel');
    var stdinEl     = $csid('mlp-cs-stdin');
    var stdinVal    = stdinEl ? stdinEl.value : '';
    if (runBtn) {
        runBtn.disabled = true;
        runBtn.innerHTML = '<span class="mlp-cs-spinner"></span> Running…';
    }
    if (runPanelBtn) {
        runPanelBtn.disabled = true;
        runPanelBtn.innerHTML = '<span class="mlp-cs-spinner"></span> Running…';
    }
    var _payload = {
        compiler: 'mono-6.12.0.199',
        code: code,
        stdin: stdinVal,
        'compiler-option-raw': '',
        'runtime-option-raw': ''
    };
    _csFetchWandbox(_payload, 2)
    .then(function(data) {
        csClearOutput();
        var hasOut = false;

        /* Compiler output / errors */
        var compMsg = (data.compiler_message || '').trim();
        var compErr = (data.compiler_error  || '').trim();

        /* If still an OCI error after all retries, show a friendly message */
        if (_csIsOciError(data)) {
            csAppendOutput('The compile server is temporarily unavailable.', 'mlp-cs-out-err');
            csAppendOutput('Please wait a few seconds and try again.', 'mlp-cs-out-info');
            setCsStatus('Server unavailable');
            return;
        }

        if (compMsg && compMsg !== compErr) {
            compMsg.split('\n').forEach(function(l){ csAppendOutput(l, 'mlp-cs-out-info'); });
            hasOut = true;
        }
        if (compErr) {
            csAppendOutput('Compiler error:', 'mlp-cs-out-err');
            compErr.split('\n').forEach(function(l){ csAppendOutput(l, 'mlp-cs-out-err'); });
            hasOut = true;
        }

        /* Program output */
        var progOut = data.program_output || '';
        var progErr = (data.program_error  || '').trim();
        if (progOut) {
            progOut.replace(/\n$/, '').split('\n').forEach(function(l){ csAppendOutput(l, ''); });
            hasOut = true;
        }
        if (progErr) {
            progErr.split('\n').forEach(function(l){ csAppendOutput(l, 'mlp-cs-out-err'); });
            hasOut = true;
        }

        if (!hasOut) { csAppendOutput('(no output)', 'mlp-cs-out-info'); }

        var status = String(data.status || '');
        if (status === '0') {
            csAppendOutput('✓ Exited with code 0', 'mlp-cs-out-ok');
            setCsStatus('Ran successfully');
        } else if (status && !compErr) {
            csAppendOutput('✗ Exited with code ' + status, 'mlp-cs-out-err');
            setCsStatus('Exited with error');
        } else if (compErr) {
            setCsStatus('Compile error');
        }
    })
    .catch(function(err) {
        csClearOutput();
        csAppendOutput('Run failed: ' + err.message, 'mlp-cs-out-err');
        setCsStatus('Run failed');
    })
    .finally(function() {
        csRunning = false;
        if (runBtn) {
            runBtn.disabled = false;
            runBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run';
        }
        if (runPanelBtn) {
            runPanelBtn.disabled = false;
            runPanelBtn.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run';
        }
    });
}

/* ── Open/Close overlay ─────────────────────────────────────── */
function openCsEditor(projectId) {
    var p = csGetProject(projectId);
    if (!p) return;
    _csActiveId = projectId;
    var overlay = $csid('mlp-csharp-overlay');
    var fab     = $csid('mlp-cs-chat-fab');
    if (overlay) overlay.classList.add('mlp-cs-active');
    if (fab)     { fab.classList.add('mlp-cs-fab-visible'); fab.classList.remove('mlp-cs-fab-hidden'); }
    document.documentElement.classList.add('mlp-cs-editor-active');
    var nameEl = $csid('mlp-cs-name');
    if (nameEl) nameEl.textContent = p.name || 'Untitled';
    var code = (p.csharp || CS_DEFAULT);
    if (csEditor) {
        csEditor.setValue(code);
        csEditor.setScrollPosition({scrollTop:0});
    }
    _csUnsaved = false; setCsSave('');
    // If the project has no saved C# code yet, persist the default immediately
    // so that buildSharePayload can find it in mlp_projects.
    if (!p.csharp) {
        csUpdateProject(_csActiveId, { csharp: code, updatedAt: new Date().toISOString() });
    }
    setCsStatus('Ready');
    setTimeout(function(){ if(csEditor) csEditor.focus(); }, 80);
    csWarmup();
}

function closeCsEditor() {
    if (_csUnsaved && _csActiveId) { csSaveProject(); }
    var overlay = $csid('mlp-csharp-overlay');
    var fab     = $csid('mlp-cs-chat-fab');
    if (overlay) overlay.classList.remove('mlp-cs-active');
    if (fab)     { fab.classList.remove('mlp-cs-fab-visible'); }
    document.documentElement.classList.remove('mlp-cs-editor-active');
    _closeCsChat();
    _csActiveId = null; _csUnsaved = false;
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

function csSaveProject() {
    if (!_csActiveId || !csEditor) return;
    var code = csEditor.getValue();
    csUpdateProject(_csActiveId, { csharp: code, updatedAt: new Date().toISOString() });
    _csUnsaved = false;
    setCsSave('Saved');
    csToast('Saved!', 'succ');
    setTimeout(function(){ setCsSave(''); }, 2500);
}

/* ── Expose open function for projects popup ─────────────────── */
window.mlpOpenCsEditor = openCsEditor;

/* ── Monaco Editor init ─────────────────────────────────────── */
function csInitMonaco() {
    if (typeof monaco === 'undefined') return;
    if (csMonoReady) return;
    csMonoReady = true;

    csEditor = monaco.editor.create($csid('mlp-cs-editor'), {
        value: CS_DEFAULT,
        language: 'csharp',
        theme: 'vs-dark',
        fontSize: 13,
        lineHeight: 21,
        fontFamily: "'JetBrains Mono','Fira Code','Consolas',monospace",
        fontLigatures: true,
        minimap: { enabled: false },
        scrollBeyondLastLine: false,
        renderLineHighlight: 'line',
        wordWrap: 'off',
        automaticLayout: true,
        folding: true,
        bracketPairColorization: { enabled: true },
        suggestOnTriggerCharacters: true,
        quickSuggestions: true,
        tabSize: 4,
        insertSpaces: true,
        renderWhitespace: 'none',
        padding: { top: 10 }
    });

    /* Cursor position tracking */
    csEditor.onDidChangeCursorPosition(function(e) {
        var pos = e.position;
        var el = $csid('mlp-cs-status-pos');
        if (el) el.textContent = 'Ln ' + pos.lineNumber + ', Col ' + pos.column;
    });

    /* Mark unsaved on content change */
    csEditor.onDidChangeModelContent(function() {
        if (!_csUnsaved) { _csUnsaved = true; setCsSave('● Unsaved'); }
    });

    /* Ctrl+S save */
    csEditor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, function() { csSaveProject(); });
    /* Ctrl+Enter run */
    csEditor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, function() { csRunCode(); });
    /* Ctrl+Shift+F fullscreen */
    csEditor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyF, function() { toggleCsFullscreen(); });
}

function toggleCsFullscreen() {
    var ov = $csid('mlp-csharp-overlay');
    if (!ov) return;
    ov.classList.toggle('mlp-cs-fullscreen');
    if (csEditor) setTimeout(function(){ csEditor.layout(); }, 50);
}

/* ── Drag-resize panel ──────────────────────────────────────── */
(function wireResizer() {
    var resizer = $csid('mlp-cs-resizer');
    var outWrap = $csid('mlp-cs-output-wrap');
    if (!resizer || !outWrap) return;
    var dragging = false, startX = 0, startW = 0;
    resizer.addEventListener('mousedown', function(e) {
        dragging = true; startX = e.clientX;
        startW = outWrap.getBoundingClientRect().width;
        resizer.classList.add('mlp-cs-dragging');
        e.preventDefault();
    });
    document.addEventListener('mousemove', function(e) {
        if (!dragging) return;
        var delta = startX - e.clientX;
        var nw = Math.max(220, Math.min(window.innerWidth * 0.7, startW + delta));
        outWrap.style.width = nw + 'px';
    });
    document.addEventListener('mouseup', function() {
        if (!dragging) return;
        dragging = false; resizer.classList.remove('mlp-cs-dragging');
        if (csEditor) csEditor.layout();
    });
})();

/* ── Wire buttons ───────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
    var backBtn    = $csid('mlp-cs-back');
    var runBtn     = $csid('mlp-cs-run');
    var saveBtn    = $csid('mlp-cs-save');
    var exportBtn  = $csid('mlp-cs-export');
    var fsBtn      = $csid('mlp-cs-fullscreen-btn');
    var clearBtn   = $csid('mlp-cs-clear-btn');
    var chatFab    = $csid('mlp-cs-chat-fab');
    var chatClose  = $csid('mlp-cs-chat-close');
    var chatOverly = $csid('mlp-cs-chat-overlay');
    var chatSend   = $csid('mlp-cs-chat-send');
    var chatInput  = $csid('mlp-cs-chat-input');

    var runPanelBtn = $csid('mlp-cs-run-panel');

    if (backBtn)      backBtn.addEventListener('click', closeCsEditor);
    if (runBtn)       runBtn.addEventListener('click', csRunCode);
    if (runPanelBtn)  runPanelBtn.addEventListener('click', csRunCode);
    if (saveBtn)      saveBtn.addEventListener('click', csSaveProject);
    if (clearBtn)     clearBtn.addEventListener('click', csClearOutput);
    if (fsBtn)      fsBtn.addEventListener('click', toggleCsFullscreen);
    if (chatFab)    chatFab.addEventListener('click', _openCsChat);
    if (chatClose)  chatClose.addEventListener('click', _closeCsChat);
    if (chatOverly) chatOverly.addEventListener('click', _closeCsChat);

    if (exportBtn) exportBtn.addEventListener('click', function() {
        if (!csEditor) return;
        var code = csEditor.getValue();
        var blob = new Blob([code], {type:'text/plain'});
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = ((_csActiveId && csGetProject(_csActiveId) && csGetProject(_csActiveId).name) || 'program') + '.cs';
        a.click(); URL.revokeObjectURL(a.href);
    });

    if (chatSend) chatSend.addEventListener('click', _sendCsChat);
    if (chatInput) {
        chatInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); _sendCsChat(); }
        });
    }

    /* ── Templates ─────────────────────────────────────────── */
    var CS_TEMPLATES = [
        {
            name: 'Hello World',
            desc: 'Basic console output — start here',
            code: [
                'using System;',
                '',
                'class Program {',
                '    static void Main() {',
                '        Console.WriteLine("Hello, World!");',
                '        Console.WriteLine("Welcome to C# on Mono.");',
                '    }',
                '}'
            ].join('\n')
        },
        {
            name: 'Classes & Inheritance',
            desc: 'OOP with base class and override',
            code: [
                'using System;',
                '',
                'class Animal {',
                '    public string Name { get; set; }',
                '    public int    Age  { get; set; }',
                '    public Animal(string name, int age) { Name = name; Age = age; }',
                '    public virtual string Speak() => Name + " makes a sound.";',
                '    public override string ToString() => Name + " (age " + Age + ")";',
                '}',
                '',
                'class Dog : Animal {',
                '    public string Breed { get; set; }',
                '    public Dog(string name, int age, string breed) : base(name, age) { Breed = breed; }',
                '    public override string Speak() => Name + " says: Woof!";',
                '}',
                '',
                'class Program {',
                '    static void Main() {',
                '        Animal[] animals = {',
                '            new Dog("Rex",   3, "Labrador"),',
                '            new Dog("Bella", 5, "Poodle"),',
                '            new Animal("Cat", 2)',
                '        };',
                '        foreach (var a in animals)',
                '            Console.WriteLine(a + " — " + a.Speak());',
                '    }',
                '}'
            ].join('\n')
        },
        {
            name: 'Async / Await',
            desc: 'Parallel async tasks with Task.WhenAll',
            code: [
                'using System;',
                'using System.Threading.Tasks;',
                '',
                'class Program {',
                '    static async Task Main() {',
                '        Console.WriteLine("Starting tasks...");',
                '        var t1 = FetchAsync("Users",    1200);',
                '        var t2 = FetchAsync("Products",  800);',
                '        var t3 = FetchAsync("Orders",    600);',
                '        await Task.WhenAll(t1, t2, t3);',
                '        Console.WriteLine("Users:    " + t1.Result);',
                '        Console.WriteLine("Products: " + t2.Result);',
                '        Console.WriteLine("Orders:   " + t3.Result);',
                '        Console.WriteLine("All done!");',
                '    }',
                '',
                '    static async Task<string> FetchAsync(string name, int ms) {',
                '        await Task.Delay(ms);',
                '        return name + " loaded (" + ms + "ms)";',
                '    }',
                '}'
            ].join('\n')
        },
        {
            name: 'LINQ Queries',
            desc: 'Filter, sort and group collections',
            code: [
                'using System;',
                'using System.Collections.Generic;',
                'using System.Linq;',
                '',
                'class Program {',
                '    static void Main() {',
                '        var students = new List<(string Name, int Grade, string Subject)> {',
                '            ("Alice",  92, "Math"),',
                '            ("Bob",    75, "Science"),',
                '            ("Carol",  88, "Math"),',
                '            ("Dave",   60, "History"),',
                '            ("Eve",    95, "Science"),',
                '            ("Frank",  82, "Math"),',
                '        };',
                '',
                '        Console.WriteLine("Top students (grade >= 85):");',
                '        var top = students',
                '            .Where(s => s.Grade >= 85)',
                '            .OrderByDescending(s => s.Grade);',
                '        foreach (var s in top)',
                '            Console.WriteLine("  " + s.Name + " — " + s.Grade);',
                '',
                '        Console.WriteLine("\\nAverage by subject:");',
                '        var bySubject = students',
                '            .GroupBy(s => s.Subject)',
                '            .Select(g => new { Subject = g.Key, Avg = g.Average(s => s.Grade) })',
                '            .OrderByDescending(x => x.Avg);',
                '        foreach (var g in bySubject)',
                '            Console.WriteLine("  " + g.Subject + ": " + g.Avg.ToString("F1"));',
                '    }',
                '}'
            ].join('\n')
        },
        {
            name: 'Exception Handling',
            desc: 'try / catch / finally with custom logic',
            code: [
                'using System;',
                '',
                'class BankAccount {',
                '    public string Owner   { get; }',
                '    private double _bal;',
                '    public BankAccount(string owner, double initial) { Owner = owner; _bal = initial; }',
                '',
                '    public void Deposit(double amount) {',
                '        if (amount <= 0) throw new ArgumentException("Deposit must be positive.");',
                '        _bal += amount;',
                '        Console.WriteLine("  Deposited $" + amount.ToString("F2") + "  Balance: $" + _bal.ToString("F2"));',
                '    }',
                '',
                '    public void Withdraw(double amount) {',
                '        if (amount <= 0) throw new ArgumentException("Amount must be positive.");',
                '        if (amount > _bal) throw new InvalidOperationException("Insufficient funds (have $" + _bal.ToString("F2") + ").");',
                '        _bal -= amount;',
                '        Console.WriteLine("  Withdrew  $" + amount.ToString("F2") + "  Balance: $" + _bal.ToString("F2"));',
                '    }',
                '}',
                '',
                'class Program {',
                '    static void Main() {',
                '        var acc = new BankAccount("Alice", 500);',
                '        Console.WriteLine("Account: " + acc.Owner + "\\n");',
                '        Try(() => acc.Deposit(200));',
                '        Try(() => acc.Withdraw(100));',
                '        Try(() => acc.Withdraw(800));',
                '        Try(() => acc.Deposit(-50));',
                '        Try(() => acc.Withdraw(300));',
                '    }',
                '    static void Try(Action op) {',
                '        try { op(); }',
                '        catch (Exception ex) { Console.WriteLine("  X " + ex.GetType().Name + ": " + ex.Message); }',
                '    }',
                '}'
            ].join('\n')
        },
        {
            name: 'Generics & Collections',
            desc: 'Generic Stack<T> built from scratch',
            code: [
                'using System;',
                'using System.Collections.Generic;',
                '',
                'class Stack<T> {',
                '    private readonly List<T> _items = new List<T>();',
                '    public void Push(T item) { _items.Add(item); }',
                '    public T Pop() {',
                '        if (_items.Count == 0) throw new InvalidOperationException("Stack is empty.");',
                '        var top = _items[_items.Count - 1];',
                '        _items.RemoveAt(_items.Count - 1);',
                '        return top;',
                '    }',
                '    public int  Count   => _items.Count;',
                '    public bool IsEmpty => _items.Count == 0;',
                '}',
                '',
                'class Program {',
                '    static void Main() {',
                '        var nums = new Stack<int>();',
                '        foreach (var n in new[]{ 10, 20, 30, 40 }) nums.Push(n);',
                '        Console.WriteLine("Int stack — popping:");',
                '        while (!nums.IsEmpty) Console.WriteLine("  " + nums.Pop());',
                '',
                '        var words = new Stack<string>();',
                '        foreach (var w in "the quick brown fox".Split(\' \')) words.Push(w);',
                '        Console.Write("\\nReversed: ");',
                '        while (!words.IsEmpty) Console.Write(words.Pop() + " ");',
                '        Console.WriteLine();',
                '    }',
                '}'
            ].join('\n')
        }
    ];

    (function wireTemplates() {
        var tplBtn  = $csid('mlp-cs-tpl-btn');
        var tplMenu = $csid('mlp-cs-tpl-menu');
        if (!tplBtn || !tplMenu) return;

        /* Build menu items */
        CS_TEMPLATES.forEach(function(tpl, i) {
            if (i > 0) {
                var div = document.createElement('div');
                div.className = 'mlp-cs-tpl-divider';
                tplMenu.appendChild(div);
            }
            var btn = document.createElement('button');
            btn.className = 'mlp-cs-tpl-item';
            btn.type = 'button';
            btn.setAttribute('role', 'menuitem');
            btn.innerHTML =
                '<span class="mlp-cs-tpl-name">' + tpl.name + '</span>' +
                '<span class="mlp-cs-tpl-desc">'  + tpl.desc + '</span>';
            btn.addEventListener('click', function() {
                closeTplMenu();
                if (!csEditor) return;
                if (window.confirm('Load template "' + tpl.name + '"?\n\nThis will replace your current code. Make sure to save anything you want to keep.')) {
                    csEditor.setValue(tpl.code);
                    csEditor.setScrollPosition({ scrollTop: 0 });
                    _csUnsaved = true; setCsSave('● Unsaved');
                    csToast(tpl.name + ' loaded', 'succ');
                }
            });
            tplMenu.appendChild(btn);
        });

        function openTplMenu() {
            var r = tplBtn.getBoundingClientRect();
            tplMenu.style.top  = (r.bottom + 6) + 'px';
            tplMenu.style.left = Math.min(r.left, window.innerWidth - 250) + 'px';
            tplMenu.classList.add('mlp-cs-tpl-open');
        }
        function closeTplMenu() { tplMenu.classList.remove('mlp-cs-tpl-open'); }

        tplBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            tplMenu.classList.contains('mlp-cs-tpl-open') ? closeTplMenu() : openTplMenu();
        });
        document.addEventListener('click', function(e) {
            if (!tplMenu.contains(e.target) && e.target !== tplBtn) closeTplMenu();
        });
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') closeTplMenu();
        });
    })();

    /* Auto-init Monaco if already loaded */
    if (typeof monaco !== 'undefined') { csInitMonaco(); }
    else {
        var checkMon = setInterval(function() {
            if (typeof monaco !== 'undefined') { clearInterval(checkMon); csInitMonaco(); }
        }, 200);
    }
});

})();
</script>
        <?php
    }
}
