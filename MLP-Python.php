<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class MLP_Python {
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
<style id="mlp-python-styles">
/* ── Python Editor Overlay ─────────────────────────────── */
#mlp-python-overlay {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 99999;
    background: var(--mlp-bg, #0e0e0e);
    flex-direction: column;
    font-family: var(--mlp-font, 'JetBrains Mono', 'Fira Code', monospace);
    overflow: hidden;
}
#mlp-python-overlay.mlp-py-active { display: flex; }

/* Topbar */
#mlp-py-topbar {
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
#mlp-py-back {
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
#mlp-py-back:hover { border-color: var(--mlp-accent, #ea580c); color: var(--mlp-accent, #ea580c); }
#mlp-py-title {
    flex: 1;
    font-size: .83rem;
    font-weight: 700;
    color: var(--mlp-text, #f0f0f0);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
}
#mlp-py-title span {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 8px;
    background: rgba(59,130,246,.15);
    color: #60a5fa;
    border-radius: 4px;
    font-size: .62rem;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    margin-left: 8px;
}
.mlp-py-btn {
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
.mlp-py-btn:disabled { opacity: .5; cursor: not-allowed; }
#mlp-py-run {
    background: linear-gradient(135deg, #16a34a, #15803d);
    color: #fff;
    border-color: transparent;
    box-shadow: 0 1px 6px rgba(22,163,74,.3);
}
#mlp-py-run:hover:not(:disabled) { opacity: .88; }
#mlp-py-save {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
}
#mlp-py-save:hover:not(:disabled) { border-color: var(--mlp-accent, #ea580c); color: var(--mlp-accent, #ea580c); }
#mlp-py-export {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
}
#mlp-py-export:hover:not(:disabled) { border-color: #60a5fa; color: #60a5fa; }
#mlp-py-fullscreen-btn {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
    padding: 5px 9px;
}
#mlp-py-fullscreen-btn:hover { border-color: #60a5fa; color: #60a5fa; }
/* Topbar chat button — hidden, replaced by floating FAB */
#mlp-py-chat-btn { display: none !important; }

/* ── Floating AI Chat Button (FAB) ─────────────────────────── */
#mlp-py-chat-fab {
    position: fixed;
    bottom: 28px;
    right: 16px;
    z-index: 999993;
    height: 38px;
    padding: 0 14px 0 11px;
    border-radius: 8px;
    background: linear-gradient(135deg, #16a34a, #15803d);
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
    box-shadow: 0 4px 18px rgba(22,163,74,.45), 0 1px 4px rgba(0,0,0,.4);
    transition: opacity .18s, transform .18s, box-shadow .18s;
}
#mlp-py-chat-fab:hover { opacity: .9; transform: translateY(-2px); box-shadow: 0 6px 22px rgba(22,163,74,.55); }
/* Hide FAB when sidebar is open so it doesn't overlap */
#mlp-py-chat-fab.mlp-py-fab-hidden { opacity: 0; pointer-events: none; transform: translateY(6px); }
/* Fullscreen: hide chrome, collapse output */
#mlp-python-overlay.mlp-py-fullscreen #mlp-py-topbar,
#mlp-python-overlay.mlp-py-fullscreen #mlp-py-tabbar,
#mlp-python-overlay.mlp-py-fullscreen #mlp-py-statusbar { display: none !important; }
#mlp-python-overlay.mlp-py-fullscreen #mlp-py-output-wrap { display: none !important; }
#mlp-python-overlay.mlp-py-fullscreen #mlp-py-resizer { display: none !important; }

/* Tab bar */
#mlp-py-tabbar {
    display: flex;
    align-items: center;
    gap: 0;
    padding: 0 14px;
    height: 36px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
    overflow-x: auto;
}
.mlp-py-tab {
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
    position: relative;
}
.mlp-py-tab .mlp-py-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.mlp-py-tab.mlp-py-tab-active { color: var(--mlp-text, #f0f0f0); border-bottom-color: #3b82f6; }

/* Main split */
#mlp-py-main {
    flex: 1;
    display: flex;
    flex-direction: row;
    overflow: hidden;
    min-height: 0;
}
#mlp-py-editor-wrap {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    position: relative;
}
#mlp-py-editor {
    flex: 1;
    min-height: 0;
    width: 100%;
}

/* Resize handle */
#mlp-py-resizer {
    width: 5px;
    background: var(--mlp-border, #2a2a2a);
    cursor: col-resize;
    flex-shrink: 0;
    transition: background .15s;
    position: relative;
    z-index: 2;
}
#mlp-py-resizer:hover,
#mlp-py-resizer.mlp-py-dragging { background: #3b82f6; }

/* Output panel */
#mlp-py-output-wrap {
    width: 38%;
    min-width: 220px;
    max-width: 70%;
    display: flex;
    flex-direction: column;
    background: #0a0a0a;
    border-left: 1px solid var(--mlp-border, #2a2a2a);
    overflow: hidden;
}
#mlp-py-output-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 12px;
    height: 34px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-py-output-title {
    flex: 1;
    font-size: .68rem;
    font-weight: 700;
    color: var(--mlp-text-muted, #888);
    text-transform: uppercase;
    letter-spacing: .07em;
}
#mlp-py-clear-btn {
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
#mlp-py-clear-btn:hover { color: #ef4444; background: rgba(239,68,68,.1); }
#mlp-py-output {
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
#mlp-py-output::-webkit-scrollbar { width: 5px; }
#mlp-py-output::-webkit-scrollbar-thumb { background: var(--mlp-border, #2a2a2a); border-radius: 3px; }
.mlp-py-out-line { display: block; padding: 0; }
.mlp-py-out-err  { color: #f87171; }
.mlp-py-out-info { color: #60a5fa; font-style: italic; font-size: .72rem; }
.mlp-py-out-ok   { color: #34d399; font-size: .72rem; }

/* Status bar */
#mlp-py-statusbar {
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
#mlp-py-status-lang { display: inline-flex; align-items: center; gap: 4px; color: #60a5fa; font-weight: 600; }
#mlp-py-status-msg  { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
#mlp-py-status-pos  { white-space: nowrap; }
#mlp-py-status-save { white-space: nowrap; font-style: italic; }

/* Toast */
#mlp-py-toast {
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
#mlp-py-toast.mlp-py-show { opacity: 1; transform: translateY(0); }
#mlp-py-toast.mlp-py-err  { border-color: #f87171; }
#mlp-py-toast.mlp-py-succ { border-color: #34d399; }

/* Loading spinner inside Run button */
@keyframes mlp-py-spin { to { transform: rotate(360deg); } }
.mlp-py-spinner {
    width: 12px;
    height: 12px;
    border: 2px solid rgba(255,255,255,.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: mlp-py-spin .7s linear infinite;
    display: inline-block;
    flex-shrink: 0;
}

@media (max-width: 680px) {
    #mlp-py-main { flex-direction: column; }
    #mlp-py-output-wrap { width: 100%; max-width: 100%; min-width: 0; border-left: none; border-top: 1px solid var(--mlp-border, #2a2a2a); height: 38%; }
    #mlp-py-resizer { display: none; }
}

/* ── Python AI Chat Sidebar ────────────────────────────────── */
#mlp-py-chat-sidebar {
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
    box-shadow: -4px 8px 40px rgba(0,0,0,.55), 0 0 0 1px rgba(22,163,74,.12), -8px 0 40px rgba(22,163,74,0.12);
    overflow: hidden;
}
#mlp-py-chat-sidebar.mlp-py-chat-open { transform: translateX(0); }

#mlp-py-chat-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-py-chat-title {
    font-size: .83rem;
    font-weight: 700;
    color: var(--mlp-text, #f0f0f0);
}
#mlp-py-chat-close {
    background: none;
    border: none;
    color: var(--mlp-text-muted, #888);
    cursor: pointer;
    padding: 4px;
    display: flex;
    align-items: center;
    transition: color .15s;
}
#mlp-py-chat-close:hover { color: var(--mlp-text, #f0f0f0); }

#mlp-py-chat-messages {
    flex: 1;
    overflow-y: auto;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.mlp-py-chat-msg {
    padding: 8px 10px;
    border-radius: 6px;
    font-size: .75rem;
    line-height: 1.5;
    max-width: 95%;
    word-wrap: break-word;
}
.mlp-py-chat-msg.user {
    background: #1e3a8a;
    color: #bfdbfe;
    align-self: flex-end;
    margin-left: auto;
}
.mlp-py-chat-msg.assistant {
    background: #1f2937;
    color: #d4d4d4;
    align-self: flex-start;
}
.mlp-py-chat-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--mlp-text-muted, #888);
    font-size: .73rem;
    text-align: center;
    padding: 20px;
}

#mlp-py-chat-input-area {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px;
    background: var(--mlp-surface, #161616);
    border-top: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-py-chat-input {
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
#mlp-py-chat-input:focus {
    outline: none;
    border-color: #16a34a;
}
#mlp-py-chat-send {
    align-self: flex-end;
    padding: 5px 12px;
    background: #16a34a;
    color: #fff;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: .73rem;
    font-weight: 600;
    transition: opacity .15s;
}
#mlp-py-chat-send:hover:not(:disabled) { opacity: .88; }
#mlp-py-chat-send:disabled { opacity: .5; cursor: not-allowed; }

/* ── Markdown elements inside chat messages ───────────────── */
.mlp-py-chat-msg.assistant .mlp-py-md-h2 {
    display: block;
    font-size: .85rem;
    font-weight: 700;
    color: #93c5fd;
    margin: 8px 0 3px;
    padding-bottom: 3px;
    border-bottom: 1px solid #2a3a4a;
}
.mlp-py-chat-msg.assistant .mlp-py-md-h3 {
    display: block;
    font-size: .78rem;
    font-weight: 700;
    color: #a5b4fc;
    margin: 6px 0 2px;
}
.mlp-py-chat-msg.assistant .mlp-py-md-code {
    font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
    font-size: .72rem;
    background: rgba(0,0,0,.35);
    border: 1px solid #2a2a2a;
    border-radius: 3px;
    padding: 0 4px;
    color: #fbbf24;
}
.mlp-py-chat-msg.assistant strong { color: #f0f0f0; font-weight: 700; }
.mlp-py-chat-msg.assistant em { color: #d1d5db; font-style: italic; }

/* ── Code blocks inside chat messages ─────────────────────── */
.mlp-py-chat-code-wrap {
    margin: 6px 0 0;
    border-radius: 6px;
    overflow: hidden;
    border: 1px solid #2a2a2a;
    background: #0d0d0d;
    max-width: 100%;
}
.mlp-py-chat-code-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 4px 10px;
    background: #1a1a1a;
    border-bottom: 1px solid #2a2a2a;
}
.mlp-py-chat-code-lang {
    font-size: .62rem;
    font-weight: 700;
    color: #60a5fa;
    letter-spacing: .06em;
    text-transform: uppercase;
}
.mlp-py-chat-code-actions {
    display: flex;
    gap: 5px;
}
.mlp-py-chat-code-apply,
.mlp-py-chat-code-copy {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: 4px;
    font-family: inherit;
    font-size: .65rem;
    font-weight: 700;
    cursor: pointer;
    border: 1px solid transparent;
    transition: opacity .15s, background .15s;
}
.mlp-py-chat-code-apply {
    background: #16a34a;
    color: #fff;
}
.mlp-py-chat-code-apply:hover { opacity: .85; }
.mlp-py-chat-code-apply.mlp-py-applied {
    background: #1d4ed8;
}
.mlp-py-chat-code-copy {
    background: transparent;
    border-color: #3a3a3a;
    color: #888;
}
.mlp-py-chat-code-copy:hover { color: #d4d4d4; border-color: #555; }
.mlp-py-chat-code-pre {
    margin: 0;
    padding: 10px 12px;
    overflow-x: auto;
    font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
    font-size: .73rem;
    line-height: 1.6;
    color: #d4d4d4;
    white-space: pre;
    background: transparent;
}
.mlp-py-chat-undo-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin-top: 4px;
    padding: 2px 8px;
    background: transparent;
    border: 1px solid #3a3a3a;
    border-radius: 4px;
    color: #f59e0b;
    font-family: inherit;
    font-size: .65rem;
    font-weight: 700;
    cursor: pointer;
    transition: opacity .15s;
}
.mlp-py-chat-undo-btn:hover { opacity: .8; }

/* ── AI Thinking Animation ─────────────────────────────────── */
.mlp-py-thinking-bubble {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    background: #1f2937;
    border-radius: 6px;
    border: 1px solid rgba(96,165,250,.15);
    align-self: flex-start;
    max-width: 95%;
    box-shadow: 0 0 12px rgba(96,165,250,.07);
}
.mlp-py-thinking-label {
    font-size: .68rem;
    color: #6b7280;
    font-style: italic;
    white-space: nowrap;
}

@keyframes mlp-py-dot-wave {
    0%, 100% { transform: translateY(0);   opacity: .35; }
    50%       { transform: translateY(-6px); opacity: 1;   }
}
@keyframes mlp-py-dot-glow {
    0%, 100% { filter: drop-shadow(0 0 0px #60a5fa); }
    50%       { filter: drop-shadow(0 0 5px #60a5fa); }
}
.mlp-py-think-dot {
    animation: mlp-py-dot-wave 1.3s ease-in-out infinite,
               mlp-py-dot-glow  1.3s ease-in-out infinite;
}
.mlp-py-think-dot:nth-child(2) {
    animation-delay: .22s;
}
.mlp-py-think-dot:nth-child(3) {
    animation-delay: .44s;
}

/* Outer ring pulse on the SVG container */
@keyframes mlp-py-ring-pulse {
    0%, 100% { opacity: .18; r: 14; }
    50%       { opacity: .45; r: 16; }
}
.mlp-py-think-ring {
    animation: mlp-py-ring-pulse 1.3s ease-in-out infinite;
    transform-origin: center;
}

#mlp-py-chat-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.3);
    z-index: 999990;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.25s cubic-bezier(0.4,0,0.2,1);
}
#mlp-py-chat-overlay.mlp-py-chat-open { 
    opacity: 1;
    pointer-events: auto;
}

/* Hide HTML/CSS/JS chat in Python editor */
html.mlp-py-editor-active #mlpChatToggle,
html.mlp-py-editor-active #mlpChatSidebar { display: none !important; }

/* ── Package Installer Panel ───────────────────────────────── */
#mlp-py-pkg-panel {
    position: fixed;
    top: 56px;
    left: 12px;
    bottom: 20px;
    width: 300px;
    max-width: calc(96vw - 12px);
    z-index: 999991;
    background: var(--mlp-bg, #0e0e0e);
    border: 1px solid var(--mlp-border, #2a2a2a);
    border-radius: 10px;
    display: flex;
    flex-direction: column;
    font-family: var(--mlp-font, 'JetBrains Mono', 'Fira Code', monospace);
    transform: translateX(-340px);
    transition: transform 0.25s cubic-bezier(0.4,0,0.2,1);
    box-shadow: 4px 8px 40px rgba(0,0,0,.55), 0 0 0 1px rgba(59,130,246,.1), 8px 0 40px rgba(59,130,246,0.08);
    overflow: hidden;
}
#mlp-py-pkg-panel.mlp-py-pkg-open { transform: translateX(0); }

#mlp-py-pkg-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-py-pkg-title {
    font-size: .83rem;
    font-weight: 700;
    color: var(--mlp-text, #f0f0f0);
    display: flex;
    align-items: center;
    gap: 6px;
}
#mlp-py-pkg-close {
    background: none;
    border: none;
    color: var(--mlp-text-muted, #888);
    cursor: pointer;
    padding: 4px;
    display: flex;
    align-items: center;
    transition: color .15s;
}
#mlp-py-pkg-close:hover { color: var(--mlp-text, #f0f0f0); }

#mlp-py-pkg-custom {
    display: flex;
    gap: 6px;
    padding: 10px 12px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-py-pkg-custom-input {
    flex: 1;
    padding: 6px 8px;
    background: rgba(0,0,0,.3);
    border: 1px solid var(--mlp-border, #2a2a2a);
    border-radius: 4px;
    color: var(--mlp-text, #f0f0f0);
    font-family: inherit;
    font-size: .73rem;
    transition: border-color .15s;
    min-width: 0;
}
#mlp-py-pkg-custom-input:focus { outline: none; border-color: #3b82f6; }
#mlp-py-pkg-custom-input::placeholder { color: #555; }
#mlp-py-pkg-custom-btn {
    padding: 6px 10px;
    background: #1d4ed8;
    color: #fff;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: .72rem;
    font-weight: 700;
    font-family: inherit;
    white-space: nowrap;
    transition: opacity .15s;
    flex-shrink: 0;
}
#mlp-py-pkg-custom-btn:hover:not(:disabled) { opacity: .85; }
#mlp-py-pkg-custom-btn:disabled { opacity: .5; cursor: not-allowed; }

#mlp-py-pkg-note {
    padding: 7px 12px;
    font-size: .65rem;
    color: #555;
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
    line-height: 1.4;
}

#mlp-py-pkg-list {
    flex: 1;
    overflow-y: auto;
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 4px;
}
#mlp-py-pkg-list::-webkit-scrollbar { width: 4px; }
#mlp-py-pkg-list::-webkit-scrollbar-thumb { background: #2a2a2a; border-radius: 2px; }

.mlp-py-pkg-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-radius: 6px;
    background: rgba(255,255,255,.03);
    border: 1px solid var(--mlp-border, #2a2a2a);
    transition: border-color .15s, background .15s;
}
.mlp-py-pkg-item:hover { border-color: #3a3a3a; background: rgba(255,255,255,.05); }
.mlp-py-pkg-info { flex: 1; min-width: 0; }
.mlp-py-pkg-name {
    font-size: .75rem;
    font-weight: 700;
    color: var(--mlp-text, #f0f0f0);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.mlp-py-pkg-desc {
    font-size: .65rem;
    color: #555;
    margin-top: 1px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.mlp-py-pkg-btn {
    padding: 4px 10px;
    border-radius: 4px;
    font-family: inherit;
    font-size: .68rem;
    font-weight: 700;
    cursor: pointer;
    border: 1px solid transparent;
    white-space: nowrap;
    flex-shrink: 0;
    transition: opacity .15s, background .15s, color .15s, border-color .15s;
}
.mlp-py-pkg-btn.idle {
    background: transparent;
    border-color: #3b82f6;
    color: #60a5fa;
}
.mlp-py-pkg-btn.idle:hover { background: rgba(59,130,246,.12); }
.mlp-py-pkg-btn.installing {
    background: transparent;
    border-color: #444;
    color: #888;
    cursor: not-allowed;
}
.mlp-py-pkg-btn.done {
    background: transparent;
    border-color: #ef4444;
    color: #f87171;
    cursor: pointer;
}
.mlp-py-pkg-btn.done:hover { background: rgba(239,68,68,.1); }
.mlp-py-pkg-btn.error {
    background: rgba(239,68,68,.1);
    border-color: #ef4444;
    color: #f87171;
}
.mlp-py-pkg-btn.error:hover { opacity: .8; }

/* Packages button sitting inline in the tab bar after the Python tab */
.mlp-py-tabbar-pkg-btn {
    margin-left: 6px;
    padding: 3px 10px;
    font-size: .72rem;
    align-self: center;
}

/* ── Inline plot images in output ─────────────────────────── */
.mlp-py-out-img-wrap {
    margin: 6px 0;
    display: block;
}
.mlp-py-out-img {
    max-width: 100%;
    border-radius: 6px;
    border: 1px solid var(--mlp-border, #2a2a2a);
    display: block;
}

/* ── Variables inspector panel ────────────────────────────── */
#mlp-py-vars-panel {
    position: fixed;
    top: 56px;
    left: 12px;
    bottom: 20px;
    width: 300px;
    max-width: calc(96vw - 12px);
    z-index: 999989;
    background: var(--mlp-bg, #0e0e0e);
    border: 1px solid var(--mlp-border, #2a2a2a);
    border-radius: 10px;
    display: flex;
    flex-direction: column;
    font-family: var(--mlp-font, 'JetBrains Mono', 'Fira Code', monospace);
    transform: translateX(-340px);
    transition: transform 0.25s cubic-bezier(0.4,0,0.2,1);
    box-shadow: 4px 8px 40px rgba(0,0,0,.55);
    overflow: hidden;
}
#mlp-py-vars-panel.mlp-py-vars-open { transform: translateX(0); }
#mlp-py-vars-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-py-vars-title {
    font-size: .83rem;
    font-weight: 700;
    color: var(--mlp-text, #f0f0f0);
    display: flex;
    align-items: center;
    gap: 6px;
}
#mlp-py-vars-close {
    background: none;
    border: none;
    color: var(--mlp-text-muted, #888);
    cursor: pointer;
    padding: 4px;
    display: flex;
    align-items: center;
    transition: color .15s;
}
#mlp-py-vars-close:hover { color: var(--mlp-text, #f0f0f0); }
#mlp-py-vars-list {
    flex: 1;
    overflow-y: auto;
    padding: 6px 8px;
    display: flex;
    flex-direction: column;
    gap: 3px;
}
#mlp-py-vars-list::-webkit-scrollbar { width: 4px; }
#mlp-py-vars-list::-webkit-scrollbar-thumb { background: #2a2a2a; border-radius: 2px; }
.mlp-py-var-row {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 6px 8px;
    border-radius: 5px;
    background: rgba(255,255,255,.03);
    border: 1px solid var(--mlp-border, #2a2a2a);
    font-size: .72rem;
    line-height: 1.4;
    word-break: break-word;
}
.mlp-py-var-name {
    color: #93c5fd;
    font-weight: 700;
    min-width: 80px;
    flex-shrink: 0;
}
.mlp-py-var-type {
    color: #6b7280;
    font-size: .62rem;
    white-space: nowrap;
}
.mlp-py-var-val {
    color: #d4d4d4;
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.mlp-py-vars-empty {
    padding: 20px;
    text-align: center;
    color: #555;
    font-size: .73rem;
}

/* ── stdin input prompt ───────────────────────────────────── */
#mlp-py-stdin-wrap {
    display: none;
    align-items: center;
    gap: 6px;
    padding: 6px 10px;
    background: rgba(59,130,246,.07);
    border-top: 1px solid rgba(59,130,246,.2);
    flex-shrink: 0;
}
#mlp-py-stdin-wrap.mlp-py-stdin-active { display: flex; }
#mlp-py-stdin-prompt {
    font-size: .72rem;
    color: #60a5fa;
    font-weight: 700;
    white-space: nowrap;
    max-width: 120px;
    overflow: hidden;
    text-overflow: ellipsis;
}
#mlp-py-stdin-input {
    flex: 1;
    background: rgba(0,0,0,.3);
    border: 1px solid rgba(59,130,246,.4);
    border-radius: 4px;
    color: #f0f0f0;
    font-family: inherit;
    font-size: .73rem;
    padding: 4px 7px;
}
#mlp-py-stdin-input:focus { outline: none; border-color: #3b82f6; }
#mlp-py-stdin-submit {
    padding: 4px 10px;
    background: #1d4ed8;
    color: #fff;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: .7rem;
    font-weight: 700;
    font-family: inherit;
    flex-shrink: 0;
}
#mlp-py-stdin-submit:hover { opacity: .85; }

/* ── Package install progress bar ────────────────────────── */
.mlp-py-pkg-progress {
    height: 3px;
    background: rgba(59,130,246,.15);
    border-radius: 2px;
    overflow: hidden;
    margin-top: 4px;
}
.mlp-py-pkg-progress-bar {
    height: 100%;
    background: linear-gradient(90deg, #3b82f6, #60a5fa);
    border-radius: 2px;
    animation: mlp-py-progress-slide 1.4s ease-in-out infinite;
    width: 40%;
}
@keyframes mlp-py-progress-slide {
    0%   { transform: translateX(-100%); }
    100% { transform: translateX(350%); }
}

/* Packages button in topbar */
#mlp-py-pkg-btn-top,
#mlp-py-vars-btn,
#mlp-py-format-btn,
#mlp-py-snippets-btn,
#mlp-py-copy-btn,
#mlp-py-profile-btn {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
}
#mlp-py-pkg-btn-top:hover:not(:disabled),
#mlp-py-vars-btn:hover:not(:disabled),
#mlp-py-format-btn:hover:not(:disabled),
#mlp-py-snippets-btn:hover:not(:disabled),
#mlp-py-copy-btn:hover:not(:disabled),
#mlp-py-profile-btn:hover:not(:disabled) { border-color: #3b82f6; color: #60a5fa; }
#mlp-py-pkg-btn-top.mlp-py-pkg-open,
#mlp-py-vars-btn.mlp-py-vars-open,
#mlp-py-format-btn.mlp-py-format-active,
#mlp-py-snippets-btn.mlp-py-snippets-open { border-color: #3b82f6; color: #60a5fa; background: rgba(59,130,246,.08); }

/* ── Error line highlight ─────────────────────────────── */
.mlp-error-line { background: rgba(239,68,68,.10) !important; }
.mlp-error-glyph::before { content: ''; display: block; width: 7px; height: 7px; background: #ef4444; border-radius: 50%; margin: 7px 0 0 1px; }

/* ── DataFrame table output ───────────────────────────── */
.mlp-py-out-df { overflow-x: auto; margin: 6px 0 4px; }
.mlp-df { border-collapse: collapse; font-size: .7rem; color: var(--mlp-text, #e5e7eb); white-space: nowrap; }
.mlp-df th, .mlp-df td { border: 1px solid var(--mlp-border, #2a2a2a); padding: 3px 10px; }
.mlp-df th { background: rgba(255,255,255,.05); color: var(--mlp-text-muted, #888); font-weight: 600; text-align: center; }
.mlp-df td { text-align: right; }
.mlp-df tr:hover td { background: rgba(255,255,255,.03); }
.mlp-df-label { font-size: .65rem; color: var(--mlp-text-muted, #888); margin-bottom: 2px; padding-left: 2px; }

/* ── Snippets dropdown panel ──────────────────────────── */
#mlp-py-snippets-panel {
    position: fixed;
    top: 83px; left: 0; right: 0;
    z-index: 999988;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.22s cubic-bezier(0.4,0,0.2,1);
    box-shadow: 0 8px 24px rgba(0,0,0,.45);
}
#mlp-py-snippets-panel.mlp-py-snippets-open { max-height: 200px; overflow-y: auto; }
#mlp-py-snippets-list {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    padding: 10px 14px 12px;
}
.mlp-py-snippet-item {
    background: transparent;
    border: 1px solid var(--mlp-border, #2a2a2a);
    border-radius: 5px;
    color: var(--mlp-text-muted, #888);
    font-family: inherit;
    font-size: .72rem;
    padding: 4px 10px;
    cursor: pointer;
    transition: border-color .15s, color .15s, background .15s;
    white-space: nowrap;
}
.mlp-py-snippet-item:hover { border-color: #3b82f6; color: #60a5fa; background: rgba(59,130,246,.06); }
/* Turtle graphics canvas */
.mlp-turtle-canvas {
    display: block;
    margin: 8px auto;
    border-radius: 6px;
    border: 1px solid rgba(255,255,255,.08);
    background: white;
    max-width: 100%;
}
/* Plotly inline chart */
.mlp-plotly-wrap { margin: 4px 0; border-radius: 6px; overflow: hidden; }
.mlp-plotly-frame {
    display: block;
    width: 100%;
    height: 460px;
    border: none;
    border-radius: 6px;
    background: white;
}
/* Profiler output */
.mlp-profiler-label { color: #a78bfa; font-weight: 600; margin-top: 6px; }
.mlp-profiler-out {
    background: rgba(167,139,250,.06);
    border: 1px solid rgba(167,139,250,.18);
    border-radius: 5px;
    color: #c4b5fd;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: .7rem;
    line-height: 1.55;
    margin: 2px 0 6px;
    overflow-x: auto;
    padding: 8px 10px;
    white-space: pre;
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
<!-- Python Editor Overlay -->
<div id="mlp-python-overlay" role="dialog" aria-modal="true" aria-label="Python Editor">
  <!-- Topbar -->
  <div id="mlp-py-topbar">
    <button id="mlp-py-back" type="button" aria-label="Back to projects">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      Projects
    </button>
    <div id="mlp-py-title">
      <span id="mlp-py-name">Untitled</span>
      <span id="mlp-py-version-badge">Python 3.12</span>
    </div>
    <button id="mlp-py-run" class="mlp-py-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
      Run
    </button>
    <button id="mlp-py-save" class="mlp-py-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
      Save
    </button>
    <button id="mlp-py-export" class="mlp-py-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Export .py
    </button>
    <button id="mlp-py-fullscreen-btn" class="mlp-py-btn" type="button" title="Toggle fullscreen (Ctrl+Shift+F)">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
    </button>
    <button id="mlp-py-chat-btn" class="mlp-py-btn" type="button" title="Python AI Chat" style="display:none">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      Chat
    </button>
  </div>
  <!-- Tab bar: Python tab + Packages button immediately after it on the left -->
  <div id="mlp-py-tabbar">
    <button class="mlp-py-tab mlp-py-tab-active" data-tab="python" type="button">
      <span class="mlp-py-dot" style="background:#3b82f6;"></span>
      Python
    </button>
    <button id="mlp-py-pkg-btn-top" class="mlp-py-btn mlp-py-tabbar-pkg-btn" type="button" title="Install packages">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
      Packages
    </button>
    <button id="mlp-py-vars-btn" class="mlp-py-btn mlp-py-tabbar-pkg-btn" type="button" title="Variables inspector">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
      Vars
    </button>
    <button id="mlp-py-format-btn" class="mlp-py-btn mlp-py-tabbar-pkg-btn" type="button" title="Format code with Black (Alt+Shift+F)">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
      Format
    </button>
    <button id="mlp-py-snippets-btn" class="mlp-py-btn mlp-py-tabbar-pkg-btn" type="button" title="Insert code snippet">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
      Snippets
    </button>
    <button id="mlp-py-copy-btn" class="mlp-py-btn mlp-py-tabbar-pkg-btn" type="button" title="Copy code to clipboard">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      Copy
    </button>
    <button id="mlp-py-profile-btn" class="mlp-py-btn mlp-py-tabbar-pkg-btn" type="button" title="Profile code with cProfile">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
      Profile
    </button>
  </div>
  <div id="mlp-py-snippets-panel"><div id="mlp-py-snippets-list"></div></div>
  <!-- Main split: editor + output -->
  <div id="mlp-py-main">
    <div id="mlp-py-editor-wrap">
      <div id="mlp-py-editor"></div>
    </div>
    <div id="mlp-py-resizer" role="separator" aria-orientation="vertical" aria-label="Resize panels"></div>
    <div id="mlp-py-output-wrap">
      <div id="mlp-py-output-header">
        <div id="mlp-py-output-title">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline;margin-right:4px;vertical-align:middle;"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          Output
        </div>
        <button id="mlp-py-clear-btn" type="button" title="Clear output">Clear</button>
      </div>
      <div id="mlp-py-output" aria-live="polite" aria-label="Python output"></div>
      <!-- Inline stdin prompt (shown only when input() is called) -->
      <div id="mlp-py-stdin-wrap">
        <span id="mlp-py-stdin-prompt">▶</span>
        <input id="mlp-py-stdin-input" type="text" autocomplete="off" spellcheck="false" placeholder="Type input and press Enter…"/>
        <button id="mlp-py-stdin-submit" type="button">↵</button>
      </div>
    </div>
  </div>
  <!-- Status bar -->
  <div id="mlp-py-statusbar">
    <span id="mlp-py-status-lang">
      <svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>
      <span id="mlp-py-status-version">Python 3.12</span>
    </span>
    <span id="mlp-py-status-msg"></span>
    <span id="mlp-py-status-pos">Ln 1, Col 1</span>
    <span id="mlp-py-status-save"></span>
  </div>
</div>

<!-- Python AI Chat Sidebar -->
<div id="mlp-py-chat-overlay"></div>
<div id="mlp-py-chat-sidebar">
  <div id="mlp-py-chat-header">
    <div id="mlp-py-chat-title">Python AI Chat</div>
    <button id="mlp-py-chat-close" type="button" title="Close chat">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>
  <div id="mlp-py-chat-messages">
    <div class="mlp-py-chat-empty">Start a conversation with the Python AI assistant</div>
  </div>
  <div id="mlp-py-chat-input-area">
    <textarea id="mlp-py-chat-input" placeholder="Ask about your code..." rows="2"></textarea>
    <button id="mlp-py-chat-send" type="button">Send</button>
  </div>
</div>

<!-- Package Installer Panel -->
<div id="mlp-py-pkg-panel">
  <div id="mlp-py-pkg-header">
    <div id="mlp-py-pkg-title">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
      Packages
    </div>
    <button id="mlp-py-pkg-close" type="button" title="Close packages">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>
  <div id="mlp-py-pkg-custom">
    <input type="text" id="mlp-py-pkg-custom-input" placeholder="Package name (e.g. arrow)" autocomplete="off" spellcheck="false"/>
    <button id="mlp-py-pkg-custom-btn" type="button">Install</button>
  </div>
  <div id="mlp-py-pkg-note">Installed packages are saved and auto-restored on next visit. Built-in packages are available instantly.</div>
  <div id="mlp-py-pkg-list"></div>
</div>

<!-- Variables Inspector Panel -->
<div id="mlp-py-vars-panel">
  <div id="mlp-py-vars-header">
    <div id="mlp-py-vars-title">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
      Variables
    </div>
    <button id="mlp-py-vars-close" type="button" title="Close inspector">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>
  <div id="mlp-py-vars-list"><div class="mlp-py-vars-empty">Run code to inspect variables</div></div>
</div>

<!-- Toast -->
<div id="mlp-py-toast"></div>

<!-- Floating AI Chat Button (hidden until Python editor is open) -->
<button id="mlp-py-chat-fab" class="mlp-py-fab-hidden" type="button" title="Open Python AI Chat" aria-label="Open Python AI Chat">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
  AI Chat
</button>

<script>
(function(){
'use strict';

/* ── Config ─────────────────────────────────────────────────── */
/* Maps Python version string → Pyodide release + human label */
var MLP_PY_VERSIONS = {
    '3.8':  { pyodide: '0.17.0', label: 'Python 3.8'  },
    '3.9':  { pyodide: '0.18.1', label: 'Python 3.9'  },
    '3.10': { pyodide: '0.22.1', label: 'Python 3.10' },
    '3.11': { pyodide: '0.25.1', label: 'Python 3.11' },
    '3.12': { pyodide: '0.26.4', label: 'Python 3.12' },
};
/* CDN templates — {ver} is replaced with the Pyodide version string */
var MLP_PY_CDN_TEMPLATES = [
    'https://cdn.jsdelivr.net/pyodide/v{ver}/full/pyodide.js',
    'https://unpkg.com/pyodide@{ver}/pyodide.js',
];
var MLP_PY_LS     = 'mlp_projects'; // same key as the main plugin
var MLP_TS_SITEKEY = <?php echo json_encode( defined( 'MLP_TURNSTILE_SITE_KEY' ) ? MLP_TURNSTILE_SITE_KEY : '' ); ?>;

/* ── Python Chat System ─────────────────────────────────────── */
var _pyChatHistories = {};  /* keyed by project ID */
var _pyChatBusy = false;
var _pyChatAbort = null;
var _pyTsToken = '';
var _pyTsVerified = false;
var _pyTsPending = '';
var _pyTsWidgetId  = null;  /* explicit-render widget ID returned by turnstile.render */
var _pyTsWidgetEl  = null;  /* the dynamically-created widget DOM element */
var _pyUndoStack   = [];    /* stack of {code, label} for undo after Apply */

function _getPyChatKey(projectId) {
    return 'mlp_py_chat_' + (projectId || 'default');
}

function _getPyChatHistory(key) {
    if (!_pyChatHistories[key]) {
        try {
            _pyChatHistories[key] = JSON.parse(localStorage.getItem(key)) || [];
        } catch (e) {
            _pyChatHistories[key] = [];
        }
    }
    return _pyChatHistories[key];
}

function _savePyChatHistory(key, history) {
    _pyChatHistories[key] = history;
    try {
        localStorage.setItem(key, JSON.stringify(history));
    } catch (e) {}
}

function _openPyChat() {
    var sidebar = $id('mlp-py-chat-sidebar');
    var overlay = $id('mlp-py-chat-overlay');
    var fab     = $id('mlp-py-chat-fab');
    if (sidebar) { sidebar.classList.add('mlp-py-chat-open'); }
    if (overlay) { overlay.classList.add('mlp-py-chat-open'); }
    if (fab)     { fab.classList.add('mlp-py-fab-hidden'); }
    var input = $id('mlp-py-chat-input');
    if (input) { setTimeout(function() { input.focus(); }, 100); }
}

function _closePyChat() {
    var sidebar = $id('mlp-py-chat-sidebar');
    var overlay = $id('mlp-py-chat-overlay');
    var fab     = $id('mlp-py-chat-fab');
    if (sidebar) { sidebar.classList.remove('mlp-py-chat-open'); }
    if (overlay) { overlay.classList.remove('mlp-py-chat-open'); }
    if (fab)     { fab.classList.remove('mlp-py-fab-hidden'); }
}

function _applyCodeToEditor(code, applyBtn) {
    if (!pyEditor) return;
    var prev = pyEditor.getValue();
    _pyUndoStack.push(prev);
    pyEditor.setValue(code);
    pyEditor.setScrollPosition({ scrollTop: 0 });
    _unsaved = true;
    setSave('● Unsaved');
    if (applyBtn) {
        applyBtn.textContent = '✓ Applied';
        applyBtn.classList.add('mlp-py-applied');
    }
    /* Show a floating undo button next to the apply btn */
    if (applyBtn && applyBtn.parentNode && !applyBtn.parentNode.querySelector('.mlp-py-chat-undo-btn')) {
        var undoBtn = document.createElement('button');
        undoBtn.className = 'mlp-py-chat-undo-btn';
        undoBtn.type = 'button';
        undoBtn.innerHTML = '↩ Undo';
        undoBtn.addEventListener('click', function () {
            var prev2 = _pyUndoStack.pop();
            if (prev2 !== undefined) {
                pyEditor.setValue(prev2);
                pyEditor.setScrollPosition({ scrollTop: 0 });
                _unsaved = true;
                setSave('● Unsaved');
            }
            if (applyBtn) {
                applyBtn.textContent = '▶ Apply';
                applyBtn.classList.remove('mlp-py-applied');
            }
            undoBtn.parentNode && undoBtn.parentNode.removeChild(undoBtn);
        });
        applyBtn.parentNode.appendChild(undoBtn);
    }
}

function _buildCodeBlock(lang, code) {
    var wrap = document.createElement('div');
    wrap.className = 'mlp-py-chat-code-wrap';

    var header = document.createElement('div');
    header.className = 'mlp-py-chat-code-header';

    var langLabel = document.createElement('span');
    langLabel.className = 'mlp-py-chat-code-lang';
    langLabel.textContent = lang || 'python';

    var actions = document.createElement('div');
    actions.className = 'mlp-py-chat-code-actions';

    var copyBtn = document.createElement('button');
    copyBtn.className = 'mlp-py-chat-code-copy';
    copyBtn.type = 'button';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', function () {
        navigator.clipboard && navigator.clipboard.writeText(code).then(function () {
            copyBtn.textContent = '✓ Copied';
            setTimeout(function () { copyBtn.textContent = 'Copy'; }, 1800);
        });
    });

    var applyBtn = document.createElement('button');
    applyBtn.className = 'mlp-py-chat-code-apply';
    applyBtn.type = 'button';
    applyBtn.textContent = '▶ Apply';
    applyBtn.addEventListener('click', function () {
        _applyCodeToEditor(code, applyBtn);
    });

    actions.appendChild(copyBtn);
    actions.appendChild(applyBtn);
    header.appendChild(langLabel);
    header.appendChild(actions);

    var pre = document.createElement('pre');
    pre.className = 'mlp-py-chat-code-pre';
    pre.textContent = code;

    wrap.appendChild(header);
    wrap.appendChild(pre);
    return wrap;
}

var _pyThinkingEl = null;

function _showPyThinking() {
    _hidePyThinking(); /* clear any stale one */
    var msgs = $id('mlp-py-chat-messages');
    if (!msgs) return;
    var empty = msgs.querySelector('.mlp-py-chat-empty');
    if (empty) msgs.innerHTML = '';

    var bubble = document.createElement('div');
    bubble.className = 'mlp-py-thinking-bubble';
    bubble.innerHTML = [
        /* Three animated dots as an SVG */
        '<svg width="38" height="16" viewBox="0 0 38 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">',
          '<defs>',
            '<radialGradient id="mlp-tg1" cx="50%" cy="50%" r="50%">',
              '<stop offset="0%" stop-color="#93c5fd"/>',
              '<stop offset="100%" stop-color="#3b82f6"/>',
            '</radialGradient>',
          '</defs>',
          /* pulse ring behind first dot */
          '<circle class="mlp-py-think-ring" cx="7" cy="8" r="14" fill="#3b82f6"/>',
          /* three dots */
          '<circle class="mlp-py-think-dot" cx="7"  cy="8" r="3.5" fill="url(#mlp-tg1)"/>',
          '<circle class="mlp-py-think-dot" cx="19" cy="8" r="3.5" fill="url(#mlp-tg1)"/>',
          '<circle class="mlp-py-think-dot" cx="31" cy="8" r="3.5" fill="url(#mlp-tg1)"/>',
        '</svg>',
        '<span class="mlp-py-thinking-label">AI is thinking…</span>'
    ].join('');

    msgs.appendChild(bubble);
    msgs.scrollTop = msgs.scrollHeight;
    _pyThinkingEl = bubble;
}

function _hidePyThinking() {
    if (_pyThinkingEl && _pyThinkingEl.parentNode) {
        _pyThinkingEl.parentNode.removeChild(_pyThinkingEl);
    }
    _pyThinkingEl = null;
}

/* ── Inline markdown renderer ────────────────────────────── */
function _renderMarkdownInline(text) {
    /* Returns a DocumentFragment with bold, italic, and inline-code nodes */
    var frag = document.createDocumentFragment();
    /* Tokenise: split on **bold**, *italic*, `code` */
    var re = /(`[^`]+`|\*\*[\s\S]+?\*\*|\*[^*\n]+?\*)/g;
    var last = 0, m;
    while ((m = re.exec(text)) !== null) {
        if (m.index > last) {
            frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        }
        var token = m[0];
        if (token.startsWith('**')) {
            var strong = document.createElement('strong');
            strong.textContent = token.slice(2, -2);
            frag.appendChild(strong);
        } else if (token.startsWith('`')) {
            var code = document.createElement('code');
            code.className = 'mlp-py-md-code';
            code.textContent = token.slice(1, -1);
            frag.appendChild(code);
        } else {
            var em = document.createElement('em');
            em.textContent = token.slice(1, -1);
            frag.appendChild(em);
        }
        last = m.index + token.length;
    }
    if (last < text.length) {
        frag.appendChild(document.createTextNode(text.slice(last)));
    }
    return frag;
}

function _appendPyChatMsg(role, text) {
    var msgs = $id('mlp-py-chat-messages');
    if (!msgs) return;
    var empty = msgs.querySelector('.mlp-py-chat-empty');
    if (empty) msgs.innerHTML = '';

    var bubble = document.createElement('div');
    bubble.className = 'mlp-py-chat-msg ' + role;

    if (role === 'assistant') {
        /* Split on fenced code blocks: ```lang\ncode\n``` */
        var parts = text.split(/(```[\w]*\n[\s\S]*?```)/g);
        parts.forEach(function (part) {
            var fenced = part.match(/^```([\w]*)\n([\s\S]*?)```$/);
            if (fenced) {
                var lang = fenced[1] || 'python';
                var code = fenced[2].replace(/\n$/, '');
                bubble.appendChild(_buildCodeBlock(lang, code));
            } else if (part.trim()) {
                /* Render markdown-formatted text lines */
                var lines = part.split('\n');
                lines.forEach(function (line, i) {
                    if (/^### /.test(line)) {
                        var h = document.createElement('span');
                        h.className = 'mlp-py-md-h3';
                        h.appendChild(_renderMarkdownInline(line.slice(4)));
                        bubble.appendChild(h);
                    } else if (/^## /.test(line)) {
                        var h = document.createElement('span');
                        h.className = 'mlp-py-md-h2';
                        h.appendChild(_renderMarkdownInline(line.slice(3)));
                        bubble.appendChild(h);
                    } else if (/^# /.test(line)) {
                        var h = document.createElement('span');
                        h.className = 'mlp-py-md-h2';
                        h.appendChild(_renderMarkdownInline(line.slice(2)));
                        bubble.appendChild(h);
                    } else if (line) {
                        var span = document.createElement('span');
                        span.appendChild(_renderMarkdownInline(line));
                        bubble.appendChild(span);
                    }
                    if (i < lines.length - 1) bubble.appendChild(document.createElement('br'));
                });
            }
        });
    } else {
        bubble.textContent = text;
    }

    msgs.appendChild(bubble);
    msgs.scrollTop = msgs.scrollHeight;
}

function _sendPyChat() {
    if (_pyChatBusy) return;
    var input = $id('mlp-py-chat-input');

    /* After captcha the input was already cleared; use the saved pending text */
    var text = _pyTsPending || (input && input.value.trim());
    if (!text) return;
    _pyTsPending = '';
    if (input) input.value = '';

    /* Check if Turnstile verification is needed */
    if (!_pyTsVerified) {
        _pyTsPending = text;
        _appendPyChatMsg('user', text);
        _appendPyChatMsg('assistant', 'Please complete the verification to continue.');
        _renderPyTurnstile();
        return;
    }
    
    var chatKey = _getPyChatKey(_activeId);
    var history = _getPyChatHistory(chatKey);
    history.push({ role: 'user', content: text });
    _savePyChatHistory(chatKey, history);
    
    _appendPyChatMsg('user', text);
    _pyChatBusy = true;
    _showPyThinking();

    var pythonCode = (pyEditor && pyEditor.getValue) ? pyEditor.getValue() : '';
    var fd = new FormData();
    fd.append('action', 'mlp_ai_chat_python');
    fd.append('nonce', (window.mlp_ajax && window.mlp_ajax.nonce) ? window.mlp_ajax.nonce : '');
    fd.append('message', text);
    fd.append('python_code', pythonCode);
    fd.append('turnstile_token', _pyTsToken);
    fd.append('history', JSON.stringify(history.slice(-12, -1)));

    var ajaxUrl = (window.mlp_ajax && window.mlp_ajax.ajaxurl) ? window.mlp_ajax.ajaxurl : '/wp-admin/admin-ajax.php';
    _pyChatAbort = new AbortController();

    fetch(ajaxUrl, { method: 'POST', body: fd, signal: _pyChatAbort.signal })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            _hidePyThinking();
            var h = _getPyChatHistory(chatKey);
            if (data.success && data.data && data.data.reply) {
                var reply = data.data.reply;
                h.push({ role: 'assistant', content: reply });
                _savePyChatHistory(chatKey, h);
                _appendPyChatMsg('assistant', reply);
            } else {
                var errMsg = (data.data && data.data.message) ? data.data.message : 'AI unavailable. Try again later.';
                _appendPyChatMsg('assistant', '⚠ ' + errMsg);
            }
        })
        .catch(function (err) {
            _hidePyThinking();
            if (err.name !== 'AbortError') {
                _appendPyChatMsg('assistant', '⚠ Network error: ' + err.message);
            }
        })
        .finally(function () {
            _pyChatBusy = false;
            /* Keep _pyTsVerified = true so captcha is NOT shown again until page reload */
            _hidePyThinking();
            _removePyTurnstileWidget();
        });
}

function _removePyTurnstileWidget() {
    if (_pyTsWidgetId !== null && window.turnstile) {
        try { window.turnstile.remove(_pyTsWidgetId); } catch(e) {}
        _pyTsWidgetId = null;
    }
    if (_pyTsWidgetEl && _pyTsWidgetEl.parentNode) {
        _pyTsWidgetEl.parentNode.removeChild(_pyTsWidgetEl);
    }
    _pyTsWidgetEl = null;
}

function _renderPyTurnstile() {
    if (!MLP_TS_SITEKEY) return;

    /* Remove any previous widget before creating a new one */
    _removePyTurnstileWidget();

    /* Create a fresh container and append it into the messages thread */
    var msgs = $id('mlp-py-chat-messages');
    if (!msgs) return;
    var container = document.createElement('div');
    container.style.cssText = 'padding:6px 0;display:flex;justify-content:center;';
    var widgetDiv = document.createElement('div');
    container.appendChild(widgetDiv);
    msgs.appendChild(container);
    msgs.scrollTop = msgs.scrollHeight;
    _pyTsWidgetEl = container;

    function doRender() {
        if (!window.turnstile || !window.turnstile.render) return;
        _pyTsWidgetId = window.turnstile.render(widgetDiv, {
            sitekey: MLP_TS_SITEKEY,
            theme: 'dark',
            callback: function (token) {
                _pyTsToken = token;
                _pyTsVerified = true;
                setTimeout(function () { _sendPyChat(); }, 300);
            },
            'error-callback': function () {
                _pyTsVerified = false;
                _pyTsToken = '';
            }
        });
    }

    if (window.turnstile && window.turnstile.render) {
        doRender();
    } else {
        var s = document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]');
        if (s) {
            var prevOnload = s.onload;
            s.onload = function() {
                if (typeof prevOnload === 'function') prevOnload.call(this);
                doRender();
            };
            var _pollTries = 0;
            var _poll = setInterval(function() {
                if (window.turnstile && window.turnstile.render) {
                    clearInterval(_poll);
                    doRender();
                }
                if (++_pollTries > 50) clearInterval(_poll);
            }, 100);
        } else {
            s = document.createElement('script');
            s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
            s.async = true;
            s.onload = doRender;
            document.head.appendChild(s);
        }
    }
}

/* ── State ──────────────────────────────────────────────────── */
var pyEditor         = null;
var monacoReady      = false;
var running          = false;
var _activeId        = null;
var _unsaved         = false;
var _activePyVersion = '3.12';             // currently selected Python version
var _pyodideInsts    = {};                 // cached Pyodide instances keyed by pyodide version
var _pyodidePromises = {};                 // in-flight load promises keyed by pyodide version

/* ── DOM refs ─────────────────────────���───────��─────────────── */
function $id(id){ return document.getElementById(id); }

/* ── Project helpers ────────────────────────────────────��───── */
function getProjects(){
    try{ return JSON.parse(localStorage.getItem(MLP_PY_LS)) || []; }catch(e){ return []; }
}
function saveProjects(arr){
    try{ localStorage.setItem(MLP_PY_LS, JSON.stringify(arr)); }catch(e){}
}
function getProject(id){
    return getProjects().find(function(p){ return p && p.id === id; }) || null;
}
function updateProject(id, patch){
    var arr = getProjects();
    for(var i=0;i<arr.length;i++){
        if(arr[i] && arr[i].id === id){ Object.assign(arr[i], patch); break; }
    }
    saveProjects(arr);
}

/* ── Toast ──────────────────────────────────────────────────── */
var _toastTimer = null;
function pyToast(msg, type, ms){
    var el = $id('mlp-py-toast');
    if(!el) return;
    el.textContent = msg;
    el.className   = 'mlp-py-show ' + (type === 'err' ? 'mlp-py-err' : type === 'succ' ? 'mlp-py-succ' : '');
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(function(){
        el.className = '';
    }, ms || 2500);
}

/* ── Output helpers ─────────────────────────────────────────── */
function clearOutput(){
    var el = $id('mlp-py-output');
    if(el) el.innerHTML = '';
}
function appendOutput(text, cls){
    var el = $id('mlp-py-output');
    if(!el) return;
    var span = document.createElement('span');
    span.className = 'mlp-py-out-line' + (cls ? ' ' + cls : '');
    span.textContent = text;
    el.appendChild(span);
    el.scrollTop = el.scrollHeight;
}
/* Append an inline image (canvas/blob URL) to the output panel */
function appendOutputImage(url) {
    var el = $id('mlp-py-output');
    if (!el) return;
    var wrap = document.createElement('div');
    wrap.className = 'mlp-py-out-img-wrap';
    var img = document.createElement('img');
    img.className = 'mlp-py-out-img';
    img.src = url;
    img.alt = 'plot output';
    wrap.appendChild(img);
    el.appendChild(wrap);
    el.scrollTop = el.scrollHeight;
}

/* Called from Python via js.mlpPyFlushOutput(text) — flushes buffered
   print() output to the panel mid-run (e.g. before each input() prompt) */
window.mlpPyFlushOutput = function(text) {
    if (text) appendOutput(text, '');
};
/* Echoes what the user typed back into the output panel */
window.mlpPyEchoInput = function(promptText, value) {
    if (promptText) appendOutput(promptText, 'mlp-py-out-info');
    appendOutput((value || '') + '\n', '');
};

/* ── Status bar ─────────────────────────────────────────────── */
function setStatus(msg){ var el=$id('mlp-py-status-msg'); if(el) el.textContent = msg || ''; }
function setSave(msg){   var el=$id('mlp-py-status-save'); if(el) el.textContent = msg || ''; }

/* ── Build a CDN URL for a given Pyodide version + CDN index ─── */
function _pyodideCdnUrl(pyVer, cdnIdx) {
    var tpl = MLP_PY_CDN_TEMPLATES[cdnIdx] || MLP_PY_CDN_TEMPLATES[0];
    return tpl.replace(/\{ver\}/g, pyVer);
}

/* ── Load Pyodide lazily, per-version, with CDN fallback ─────── */
function ensurePyodide(){
    var vinfo = MLP_PY_VERSIONS[_activePyVersion] || MLP_PY_VERSIONS['3.12'];
    var pver  = vinfo.pyodide;

    if (_pyodideInsts[pver])    return Promise.resolve(_pyodideInsts[pver]);
    if (_pyodidePromises[pver]) return _pyodidePromises[pver];

    _pyodidePromises[pver] = new Promise(function(resolve, reject) {
        function tryLoad(cdnIdx) {
            var url = _pyodideCdnUrl(pver, cdnIdx);
            var sc  = document.createElement('script');
            sc.src  = url;
            sc.id   = 'mlp-pyodide-sc-' + pver.replace(/\./g, '-');
            sc.onload = function() {
                window.loadPyodide({ indexURL: url.replace('pyodide.js', '') }).then(function(py) {
                    _pyodideInsts[pver] = py;
                    resolve(py);
                }).catch(function(e) {
                    delete _pyodidePromises[pver];
                    reject(e);
                });
            };
            sc.onerror = function() {
                if (sc.parentNode) sc.parentNode.removeChild(sc);
                if (cdnIdx < MLP_PY_CDN_TEMPLATES.length - 1) {
                    appendOutput('⚠ CDN ' + (cdnIdx + 1) + ' failed — trying fallback CDN…', 'mlp-py-out-info');
                    tryLoad(cdnIdx + 1);
                } else {
                    delete _pyodidePromises[pver];
                    reject(new Error('Failed to load ' + vinfo.label + ' runtime from all CDNs. Check your internet connection.'));
                }
            };
            document.head.appendChild(sc);
        }
        tryLoad(0);
    });
    return _pyodidePromises[pver];
}

/* ── Error message cleaner ───────────────────────────────────── */
function _cleanPyError(msg) {
    /* Strip "PythonError: " prefix Pyodide adds */
    msg = msg.replace(/^PythonError:\s*/, '');
    /* Cut off at the point where Pyodide appends its own internal traceback */
    var cutMarkers = [
        '\nThe above exception was the direct cause of the following exception:',
        '\nDuring handling of the above exception, another exception occurred:'
    ];
    cutMarkers.forEach(function(marker) {
        var idx = msg.indexOf(marker);
        if (idx !== -1) {
            var rest = msg.slice(idx);
            if (rest.indexOf('pyodide') !== -1 || rest.indexOf('_run_python') !== -1) {
                msg = msg.slice(0, idx);
            }
        }
    });
    /* Remove File lines that point to Pyodide internals */
    var lines = msg.split('\n');
    var out = [];
    var skipCodeLine = false;
    lines.forEach(function(line) {
        var isPyodideFile = /File ".*(?:pyodide|_run_python|site-packages\/pyodide)/.test(line);
        if (isPyodideFile) { skipCodeLine = true; return; }
        if (skipCodeLine && /^\s{4}[^\s]/.test(line)) { skipCodeLine = false; return; }
        skipCodeLine = false;
        out.push(line);
    });
    return out.join('\n').trim();
}

/* ── Browser compatibility patches applied before each run ───── */
var _MLP_PY_PATCHES = [
    /* input() — flush buffer, embed last output lines in the dialog for context,
       then echo the response back to the panel so it reads like a terminal */
    'import builtins as _b, sys as _sys',
    'def _mlp_input(prompt=""):',
    '    import js as _js',
    '    # Drain the stdout buffer',
    '    _buf = ""',
    '    try:',
    '        _buf = _sys.stdout.getvalue()',
    '        _sys.stdout.truncate(0)',
    '        _sys.stdout.seek(0)',
    '    except Exception: pass',
    '    # Push buffered output to the output panel',
    '    if _buf:',
    '        _js.mlpPyFlushOutput(_buf)',
    '    # Build the dialog message: last ≤8 lines of output + the prompt',
    '    _lines = [l for l in _buf.split("\\n") if l.strip()]',
    '    _ctx   = "\\n".join(_lines[-8:]) if _lines else ""',
    '    _p     = str(prompt).strip()',
    '    if _ctx and _p:',
    '        _msg = _ctx + "\\n\\n▶ " + _p',
    '    elif _ctx:',
    '        _msg = _ctx + "\\n\\n▶ Enter input:"',
    '    elif _p:',
    '        _msg = "▶ " + _p',
    '    else:',
    '        _msg = "▶ Enter input:"',
    '    val = _js.prompt(_msg)',
    '    if val is None: raise EOFError("input cancelled")',
    '    _js.mlpPyEchoInput(_p, val)',
    '    return val',
    '_b.input = _mlp_input',

    /* getpass.getpass() → prompt (hides text only on native; best we can do in browser) */
    'try:',
    '    import getpass as _gp, js as _js2',
    '    _gp.getpass = lambda prompt="Password: ", stream=None: (_js2.prompt(str(prompt)) or "")',
    '    del _gp, _js2',
    'except Exception: pass',

    /* os.system() → friendly OSError */
    'try:',
    '    import os as _os',
    '    _os.system = lambda cmd: (_ for _ in ()).throw(OSError("os.system() is not available in the browser."))',
    '    del _os',
    'except Exception: pass',

    /* subprocess.run / call / Popen → friendly OSError */
    'try:',
    '    import subprocess as _sp',
    '    def _no_shell(*a, **kw): raise OSError("subprocess is not available in the browser.")',
    '    _sp.run = _no_shell; _sp.call = _no_shell; _sp.check_call = _no_shell',
    '    _sp.check_output = _no_shell; _sp.Popen = _no_shell',
    '    del _sp, _no_shell',
    'except Exception: pass',

    /* time.sleep() → note in stdout, then return (can\'t truly block without freezing UI) */
    'try:',
    '    import time as _tm',
    '    _orig_sleep = _tm.sleep',
    '    def _mlp_sleep(secs):',
    '        import sys as _s',
    '        _s.stdout.write(f"[sleep({secs}s) — timing skipped in browser]\\n")',
    '    _tm.sleep = _mlp_sleep',
    '    del _tm, _orig_sleep',
    'except Exception: pass',

    /* webbrowser.open() → js window.open */
    'try:',
    '    import webbrowser as _wb, js as _js3',
    '    _wb.open = lambda url, new=0, autoraise=True: bool(_js3.window.open(str(url), "_blank"))',
    '    del _wb, _js3',
    'except Exception: pass',

    /* Pandas DataFrame → JS HTML table (patch once, silently skip if pandas not loaded) */
    'try:',
    '    import pandas as _pd_mlp',
    '    if not getattr(_pd_mlp.DataFrame, "_mlp_df_patched", False):',
    '        def _mlp_df_repr(self):',
    '            try:',
    '                import js as _js_df',
    '                _js_df.mlpPyShowDataFrame(',
    '                    self.to_html(max_rows=20, max_cols=12, border=0,',
    '                                 classes="mlp-df", na_rep="NaN")',
    '                )',
    '            except Exception: pass',
    '            return ""',
    '        _pd_mlp.DataFrame.__repr__ = _mlp_df_repr',
    '        _pd_mlp.DataFrame._mlp_df_patched = True',
    '    del _pd_mlp',
    'except Exception: pass',

    /* Suppress noisy DeprecationWarnings (e.g. pandas → pyarrow) */
    'import warnings as _w',
    '_w.filterwarnings("ignore", category=DeprecationWarning)',
    '_w.filterwarnings("ignore", category=FutureWarning)',
    'del _w',

    /* Patch plotly figures to render inline */
    'try:',
    '    import plotly.basedatatypes as _plt_base, plotly.io as _plt_io, js as _plt_js',
    '    if not getattr(_plt_base.BaseFigure, "_mlp_patched", False):',
    '        def _mlp_plotly_show(self, *a, **kw):',
    '            _plt_js.mlpPyShowPlotly(_plt_io.to_html(self, full_html=True, include_plotlyjs="cdn"))',
    '        _plt_base.BaseFigure.show = _mlp_plotly_show',
    '        _plt_base.BaseFigure._mlp_patched = True',
    '    del _plt_base, _plt_io, _plt_js',
    'except Exception: pass',

    /* Clean up top-level names */
    'del _b, _mlp_input'
].join('\n');

/* ── DataFrame HTML renderer ────────────────────────────────── */
window.mlpPyShowDataFrame = function(html) {
    var el = $id('mlp-py-output');
    if (!el) return;
    var label = document.createElement('div');
    label.className = 'mlp-py-out-line mlp-df-label';
    label.textContent = '▾ DataFrame';
    var wrap = document.createElement('div');
    wrap.className = 'mlp-py-out-df';
    wrap.innerHTML = html;
    el.appendChild(label);
    el.appendChild(wrap);
    el.scrollTop = el.scrollHeight;
};

/* ── Error line highlighting ────────────────────────────────── */
var _errDecorations = [];
function _highlightErrorLine(rawErr) {
    if (!pyEditor || !window.monaco) return;
    _errDecorations = pyEditor.deltaDecorations(_errDecorations, []);
    var m = rawErr.match(/File "<exec>",\s*line\s*(\d+)/);
    if (!m) return;
    var ln = parseInt(m[1], 10);
    var model = pyEditor.getModel();
    if (!model || ln < 1 || ln > model.getLineCount()) return;
    _errDecorations = pyEditor.deltaDecorations([], [{
        range: new window.monaco.Range(ln, 1, ln, model.getLineMaxColumn(ln)),
        options: {
            isWholeLine: true,
            className: 'mlp-error-line',
            glyphMarginClassName: 'mlp-error-glyph',
            overviewRulerColor: 'rgba(239,68,68,.8)',
            overviewRulerLane: 1
        }
    }]);
    pyEditor.revealLineInCenter(ln);
}
function _clearErrorDecorations() {
    if (pyEditor && _errDecorations.length) {
        _errDecorations = pyEditor.deltaDecorations(_errDecorations, []);
    }
    if (pyEditor && window.monaco) {
        var model = pyEditor.getModel();
        if (model) window.monaco.editor.setModelMarkers(model, 'lint', []);
    }
}

/* ── Inline linting (syntax errors via compile()) ───────────── */
var _pyInstance    = null;
var _lintTimer     = null;
function _scheduleLint() {
    clearTimeout(_lintTimer);
    _lintTimer = setTimeout(_runLint, 900);
}
function _runLint() {
    if (!pyEditor || !_pyInstance || !window.monaco) return;
    var code  = pyEditor.getValue();
    var model = pyEditor.getModel();
    if (!model) return;
    if (!code.trim()) { window.monaco.editor.setModelMarkers(model, 'lint', []); return; }
    _pyInstance.runPythonAsync(
        'import json as _jl\n' +
        '_lo = []\n' +
        'try:\n' +
        '    compile(' + JSON.stringify(code) + ', "<lint>", "exec")\n' +
        'except SyntaxError as _e:\n' +
        '    _lo.append({"l": _e.lineno or 1, "c": max(0,(_e.offset or 1)-1), "m": str(_e.msg)})\n' +
        'except Exception: pass\n' +
        '_jl.dumps(_lo)\n'
    ).then(function(res) {
        if (!pyEditor || !window.monaco) return;
        var items; try { items = JSON.parse(res); } catch(e) { return; }
        var mdl = pyEditor.getModel();
        if (!mdl) return;
        window.monaco.editor.setModelMarkers(mdl, 'lint', items.map(function(it) {
            return {
                severity: window.monaco.MarkerSeverity.Error,
                message:  it.m,
                startLineNumber: it.l, startColumn: it.c + 1,
                endLineNumber:   it.l, endColumn:   mdl.getLineMaxColumn(it.l)
            };
        }));
    }).catch(function(){});
}

/* ── Snippet library ────────────────────────────────────────── */
var _SNIPPETS = [
    { name: 'Hello World',        code: 'print("Hello, World!")' },
    { name: 'Matplotlib Plot',    code: 'import matplotlib.pyplot as plt\nimport numpy as np\n\nx = np.linspace(0, 2 * np.pi, 100)\nplt.figure(figsize=(7, 3))\nplt.plot(x, np.sin(x), label="sin(x)")\nplt.plot(x, np.cos(x), label="cos(x)")\nplt.legend(); plt.grid(True, alpha=0.3)\nplt.title("Trig Functions"); plt.tight_layout()\nplt.show()' },
    { name: 'Pandas DataFrame',   code: 'import pandas as pd\n\ndf = pd.DataFrame({\n    "Name":  ["Alice", "Bob", "Charlie"],\n    "Age":   [25, 30, 35],\n    "Score": [88.5, 92.0, 78.3]\n})\ndf' },
    { name: 'NumPy Arrays',       code: 'import numpy as np\n\narr = np.arange(1, 10).reshape(3, 3)\nprint("Matrix:\\n", arr)\nprint("Sum:", arr.sum(), " Mean:", arr.mean())\nprint("Transpose:\\n", arr.T)' },
    { name: 'List Comprehension', code: 'squares   = [x**2 for x in range(1, 11)]\nevens     = [x for x in range(20) if x % 2 == 0]\nflattened = [v for row in [[1,2],[3,4],[5,6]] for v in row]\n\nprint("Squares:", squares)\nprint("Evens:  ", evens)\nprint("Flat:   ", flattened)' },
    { name: 'Class + Methods',    code: 'class Animal:\n    def __init__(self, name, sound):\n        self.name = name; self.sound = sound\n    def speak(self):\n        return f"{self.name} says {self.sound}!"\n    def __repr__(self):\n        return f"Animal({self.name!r})"\n\nfor a in [Animal("Dog","Woof"), Animal("Cat","Meow")]:\n    print(a.speak())' },
    { name: 'File Read/Write',    code: '# /tmp is writable in Pyodide\nwith open("/tmp/demo.txt", "w") as f:\n    f.write("Hello!\\nLine 2\\nLine 3")\n\nwith open("/tmp/demo.txt") as f:\n    for line in f:\n        print(line.rstrip())' },
    { name: 'Fibonacci',          code: 'def fibonacci(n):\n    a, b = 0, 1\n    for _ in range(n):\n        yield a\n        a, b = b, a + b\n\nprint(list(fibonacci(15)))' },
    { name: 'Dict & JSON',        code: 'import json\n\ndata = {"user": "Alice", "scores": [95, 87, 92], "active": True}\njson_str = json.dumps(data, indent=2)\nprint(json_str)\n\nparsed = json.loads(json_str)\nprint("Avg:", round(sum(parsed["scores"]) / len(parsed["scores"]), 2))' },
    { name: 'Try / Except',       code: 'def safe_divide(a, b):\n    try:\n        return a / b\n    except ZeroDivisionError:\n        return "division by zero"\n    except TypeError as e:\n        return f"type error: {e}"\n\nfor a, b in [(10, 2), (5, 0), ("x", 2)]:\n    print(f"divide({a}, {b}) =", safe_divide(a, b))' },
];

function _openSnippets() {
    var panel = $id('mlp-py-snippets-panel');
    var btn   = $id('mlp-py-snippets-btn');
    var list  = $id('mlp-py-snippets-list');
    if (!panel) return;
    /* Build snippet buttons once */
    if (list && !list.hasChildNodes()) {
        _SNIPPETS.forEach(function(s) {
            var b = document.createElement('button');
            b.className = 'mlp-py-snippet-item';
            b.type = 'button';
            b.textContent = s.name;
            b.addEventListener('click', function() { _insertSnippet(s.code); });
            list.appendChild(b);
        });
    }
    panel.classList.add('mlp-py-snippets-open');
    if (btn) btn.classList.add('mlp-py-snippets-open');
}
function _closeSnippets() {
    var panel = $id('mlp-py-snippets-panel');
    var btn   = $id('mlp-py-snippets-btn');
    if (panel) panel.classList.remove('mlp-py-snippets-open');
    if (btn)   btn.classList.remove('mlp-py-snippets-open');
}
function _insertSnippet(code) {
    _closeSnippets();
    if (!pyEditor) return;
    var pos   = pyEditor.getPosition();
    var model = pyEditor.getModel();
    if (!model || !pos) { pyEditor.setValue(code); return; }
    /* Insert at cursor, replacing selection if any */
    var sel = pyEditor.getSelection();
    pyEditor.executeEdits('snippet', [{
        range: sel,
        text:  code,
        forceMoveMarkers: true
    }]);
    pyEditor.focus();
    _unsaved = true;
    setSave('● Unsaved');
}

/* ── stdin async queue ──────────────────────────────────────── */
var _stdinResolve = null;

function _showStdinPrompt(promptText) {
    var wrap   = $id('mlp-py-stdin-wrap');
    var prompt = $id('mlp-py-stdin-prompt');
    var inp    = $id('mlp-py-stdin-input');
    if (!wrap) return;
    if (prompt) prompt.textContent = (promptText ? promptText.trim() : '') + ' ▶';
    if (inp)    { inp.value = ''; inp.focus(); }
    wrap.classList.add('mlp-py-stdin-active');
}
function _hideStdinPrompt() {
    var wrap = $id('mlp-py-stdin-wrap');
    if (wrap) wrap.classList.remove('mlp-py-stdin-active');
}
function _submitStdin() {
    var inp = $id('mlp-py-stdin-input');
    var val = inp ? inp.value : '';
    _hideStdinPrompt();
    if (_stdinResolve) {
        _stdinResolve(val);
        _stdinResolve = null;
    }
}

/* Exposed to Pyodide via js.mlpPyRequestInput(prompt) — returns a Promise */
window.mlpPyRequestInput = function(promptText) {
    return new Promise(function(resolve) {
        _stdinResolve = resolve;
        appendOutput((promptText || '') + '', 'mlp-py-out-info');
        _showStdinPrompt(promptText || '');
    });
};

/* ── Variables inspector ────────────────────────────────────── */
function _openVarsPanel() {
    var panel = $id('mlp-py-vars-panel');
    var btn   = $id('mlp-py-vars-btn');
    if (panel) panel.classList.add('mlp-py-vars-open');
    if (btn)   btn.classList.add('mlp-py-vars-open');
}
function _closeVarsPanel() {
    var panel = $id('mlp-py-vars-panel');
    var btn   = $id('mlp-py-vars-btn');
    if (panel) panel.classList.remove('mlp-py-vars-open');
    if (btn)   btn.classList.remove('mlp-py-vars-open');
}
function _renderVars(varsJson) {
    var list = $id('mlp-py-vars-list');
    if (!list) return;
    var data;
    try { data = JSON.parse(varsJson); } catch(e) { return; }
    if (!data || !data.length) {
        list.innerHTML = '<div class="mlp-py-vars-empty">No user variables found</div>';
        return;
    }
    list.innerHTML = '';
    data.forEach(function(v) {
        var row = document.createElement('div');
        row.className = 'mlp-py-var-row';
        var nameEl = document.createElement('div');
        nameEl.className = 'mlp-py-var-name';
        nameEl.textContent = v.name;
        var typeEl = document.createElement('div');
        typeEl.className = 'mlp-py-var-type';
        typeEl.textContent = v.type;
        var valEl = document.createElement('div');
        valEl.className = 'mlp-py-var-val';
        valEl.textContent = v.val;
        valEl.title = v.val; /* tooltip for truncated values */
        row.appendChild(nameEl);
        var meta = document.createElement('div');
        meta.style.cssText = 'display:flex;flex-direction:column;flex:1;min-width:0;';
        meta.appendChild(typeEl);
        meta.appendChild(valEl);
        row.appendChild(meta);
        list.appendChild(row);
    });
}

/* ── Matplotlib inline rendering ────────────────────────────── */
window.mlpPyShowPlot = function(b64png) {
    appendOutputImage('data:image/png;base64,' + b64png);
};

/* ── Plotly inline renderer ──────────────────────────────────── */
window.mlpPyShowPlotly = function(html) {
    var el = $id('mlp-py-output');
    if (!el) return;
    var label = document.createElement('div');
    label.className = 'mlp-py-out-line mlp-df-label';
    label.textContent = '▾ Plotly Chart';
    var wrap = document.createElement('div');
    wrap.className = 'mlp-plotly-wrap';
    var iframe = document.createElement('iframe');
    iframe.className = 'mlp-plotly-frame';
    iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
    iframe.srcdoc = html;
    wrap.appendChild(iframe);
    el.appendChild(label);
    el.appendChild(wrap);
    el.scrollTop = el.scrollHeight;
};

/* ── Profiler output renderer ────────────────────────────────── */
window.mlpPyShowProfiler = function(stats) {
    var el = $id('mlp-py-output');
    if (!el) return;
    var label = document.createElement('div');
    label.className = 'mlp-py-out-line mlp-profiler-label';
    label.textContent = '⏱ Profile — top 25 calls by cumulative time';
    var pre = document.createElement('pre');
    pre.className = 'mlp-profiler-out';
    pre.textContent = stats.trim();
    el.appendChild(label);
    el.appendChild(pre);
    el.scrollTop = el.scrollHeight;
};

/* ── Turtle graphics ─────────────────────────────────────────── */
var _mlpTurtleCanvas = null;

window.mlpTurtleCmd = function(jsonStr) {
    var cmds;
    try { cmds = JSON.parse(jsonStr); } catch(e) { return; }
    var cv = _mlpTurtleCanvas;
    var ctx, W, H;

    for (var i = 0; i < cmds.length; i++) {
        var c = cmds[i];
        switch(c[0]) {
            case 'INIT': /* ['INIT', w, h, bg] — create/reset canvas */
                var el = $id('mlp-py-output');
                if (!el) break;
                var old = $id('mlp-turtle-canvas');
                if (old) old.parentNode.removeChild(old);
                cv = document.createElement('canvas');
                cv.id = 'mlp-turtle-canvas';
                cv.className = 'mlp-turtle-canvas';
                cv.width  = c[1] || 500;
                cv.height = c[2] || 400;
                el.appendChild(cv);
                el.scrollTop = el.scrollHeight;
                _mlpTurtleCanvas = cv;
                ctx = cv.getContext('2d');
                ctx.fillStyle = c[3] || 'white';
                ctx.fillRect(0, 0, cv.width, cv.height);
                break;
            case 'L': /* ['L', x1,y1,x2,y2, color, size] */
                if (!cv) break;
                W = cv.width; H = cv.height;
                ctx = cv.getContext('2d');
                ctx.beginPath();
                ctx.strokeStyle = c[5] || 'black';
                ctx.lineWidth   = c[6] || 1;
                ctx.lineCap = 'round';
                ctx.lineJoin = 'round';
                ctx.moveTo(W/2 + c[1], H/2 - c[2]);
                ctx.lineTo(W/2 + c[3], H/2 - c[4]);
                ctx.stroke();
                break;
            case 'F': /* ['F', [[x,y],...], color] */
                if (!cv) break;
                W = cv.width; H = cv.height;
                ctx = cv.getContext('2d');
                var pts = c[1];
                if (!pts || pts.length < 2) break;
                ctx.beginPath();
                ctx.moveTo(W/2 + pts[0][0], H/2 - pts[0][1]);
                for (var j = 1; j < pts.length; j++) {
                    ctx.lineTo(W/2 + pts[j][0], H/2 - pts[j][1]);
                }
                ctx.closePath();
                ctx.fillStyle = c[2] || 'black';
                ctx.fill();
                break;
            case 'D': /* ['D', x, y, size, color] */
                if (!cv) break;
                W = cv.width; H = cv.height;
                ctx = cv.getContext('2d');
                ctx.beginPath();
                ctx.arc(W/2 + c[1], H/2 - c[2], c[3]/2, 0, Math.PI*2);
                ctx.fillStyle = c[4] || 'black';
                ctx.fill();
                break;
            case 'T': /* ['T', x, y, text, fontSize, color, align] */
                if (!cv) break;
                W = cv.width; H = cv.height;
                ctx = cv.getContext('2d');
                ctx.font = (c[4] || 12) + 'px Arial';
                ctx.fillStyle = c[5] || 'black';
                ctx.textAlign = c[6] || 'left';
                ctx.textBaseline = 'alphabetic';
                ctx.fillText(c[3], W/2 + c[1], H/2 - c[2]);
                break;
            case 'BG': /* ['BG', color] */
                if (!cv) break;
                ctx = cv.getContext('2d');
                ctx.fillStyle = c[1] || 'white';
                ctx.fillRect(0, 0, cv.width, cv.height);
                break;
            case 'Z': /* ['Z', x, y, angle, visible] — end: draw turtle icon */
                if (!cv) break;
                W = cv.width; H = cv.height;
                ctx = cv.getContext('2d');
                if (c[4]) { /* visible */
                    var tx = W/2 + c[1], ty = H/2 - c[2];
                    var sz = 10;
                    /* canvas rotation: 0=right(East). turtle angle: 0=East, CCW positive.
                       canvas rotates CW for positive, so we negate the turtle angle */
                    var trad = -c[3] * Math.PI / 180;
                    ctx.save();
                    ctx.translate(tx, ty);
                    ctx.rotate(trad);
                    ctx.beginPath();
                    ctx.moveTo(sz,  0);
                    ctx.lineTo(-sz*0.6,  sz*0.55);
                    ctx.lineTo(-sz*0.28, 0);
                    ctx.lineTo(-sz*0.6, -sz*0.55);
                    ctx.closePath();
                    ctx.fillStyle   = 'rgba(34,197,94,.9)';
                    ctx.fill();
                    ctx.strokeStyle = 'rgba(21,128,61,.9)';
                    ctx.lineWidth   = 1;
                    ctx.stroke();
                    ctx.restore();
                }
                var elz = $id('mlp-py-output');
                if (elz) elz.scrollTop = elz.scrollHeight;
                break;
        }
    }
};

/* ── Turtle Python mock patch ─────────────────────────────────── */
var _MLP_TURTLE_PATCH = `\
try:
    def _mlp_setup_turtle():
        import sys as _sys, math as _math, types as _types, json as _tjson
        import js as _tjs

        class _TState:
            def reset(self):
                self.x=0.;self.y=0.;self.a=0.
                self.pd=True;self.vis=True
                self.pc='black';self.fc='black';self.ps=1
                self.C=[];self.fp=None
                self.W=500;self.H=400;self.bg='white'
            def __init__(self):self.reset()
        _ts=_TState()

        def _flush():
            if not _ts.C:return
            cmds=[['INIT',_ts.W,_ts.H,_ts.bg]]+_ts.C+[['Z',_ts.x,_ts.y,_ts.a,int(_ts.vis)]]
            _tjs.mlpTurtleCmd(_tjson.dumps(cmds))
            _ts.C=[]

        def forward(d):
            a=_math.radians(_ts.a);x2=_ts.x+d*_math.cos(a);y2=_ts.y+d*_math.sin(a)
            if _ts.pd:_ts.C.append(['L',_ts.x,_ts.y,x2,y2,_ts.pc,_ts.ps])
            if _ts.fp is not None:_ts.fp.append([x2,y2])
            _ts.x=x2;_ts.y=y2
        fd=forward
        def backward(d):forward(-d)
        bk=back=backward
        def right(a):_ts.a=(_ts.a-a)%360
        rt=right
        def left(a):_ts.a=(_ts.a+a)%360
        lt=left
        def goto(x,y=None):
            if y is None:x,y=float(x[0]),float(x[1])
            x,y=float(x),float(y)
            if _ts.pd:_ts.C.append(['L',_ts.x,_ts.y,x,y,_ts.pc,_ts.ps])
            if _ts.fp is not None:_ts.fp.append([x,y])
            _ts.x=x;_ts.y=y
        setpos=setposition=goto
        def setx(x):goto(float(x),_ts.y)
        def sety(y):goto(_ts.x,float(y))
        def home():
            _ts.a=0.
            goto(0.,0.)
        def penup():_ts.pd=False
        pu=up=penup
        def pendown():_ts.pd=True
        pd=down=pendown
        def isdown():return _ts.pd
        def pensize(w=None):
            if w is not None:_ts.ps=max(1,int(w))
            return _ts.ps
        width=pensize
        def _pc2(*a):
            if not a:return None
            v=a[0]
            if isinstance(v,str):return v
            t=v if isinstance(v,(list,tuple)) else a
            if len(t)==3:return 'rgb(%d,%d,%d)'%(int(t[0]*255),int(t[1]*255),int(t[2]*255))
            return str(v)
        def pencolor(*a):
            c=_pc2(*a)
            if c:_ts.pc=c
            elif not a:return _ts.pc
        def fillcolor(*a):
            c=_pc2(*a)
            if c:_ts.fc=c
            elif not a:return _ts.fc
        def color(*a):
            if not a:return(_ts.pc,_ts.fc)
            if len(a)==1:pencolor(a[0]);fillcolor(a[0])
            elif len(a)>=2:pencolor(a[0]);fillcolor(a[1])
        def begin_fill():_ts.fp=[[_ts.x,_ts.y]]
        def end_fill():
            if _ts.fp and len(_ts.fp)>1:_ts.C.append(['F',_ts.fp,_ts.fc])
            _ts.fp=None
        def circle(r,extent=360,steps=None):
            if r==0:return
            sg=1 if r>0 else -1;ar=abs(r)
            if steps is None:steps=max(int(ar*abs(extent)*0.06),4)
            sa=sg*extent/steps
            sl=2*ar*_math.sin(_math.radians(abs(sa)/2))
            for _ in range(steps):forward(sl);left(sa)
        def dot(size=None,color=None):
            if size is None:size=max(_ts.ps*2,4)
            _ts.C.append(['D',_ts.x,_ts.y,float(size),color or _ts.pc])
        def write(txt,move=False,align='left',font=('Arial',12,'normal')):
            fs=font[1] if font and len(font)>1 else 12
            _ts.C.append(['T',_ts.x,_ts.y,str(txt),int(fs),_ts.pc,align])
        def clear():
            _ts.C.append(['BG',_ts.bg])
            _ts.x=0.;_ts.y=0.;_ts.a=0.
        def reset():_ts.reset()
        def hideturtle():_ts.vis=False
        ht=hideturtle
        def showturtle():_ts.vis=True
        st=showturtle
        def isvisible():return _ts.vis
        def speed(s=None):pass
        def tracer(*a):pass
        def update():_flush()
        def delay(*a):pass
        def bgcolor(c):_ts.bg=c;_ts.C.append(['BG',c])
        def title(t):pass
        def setup(w=500,h=400,*a,**kw):_ts.W=int(w);_ts.H=int(h)
        def screensize(*a,**kw):pass
        def done():_flush()
        mainloop=bye=exitonclick=done
        def xcor():return _ts.x
        def ycor():return _ts.y
        def pos():
            class _P(tuple):
                def __repr__(self):return '(%.2f, %.2f)'%self
            return _P((_ts.x,_ts.y))
        position=pos
        def heading():return _ts.a
        def setheading(a):_ts.a=float(a)%360
        seth=setheading
        def towards(x,y=None):
            if y is None:x,y=float(x[0]),float(x[1])
            return _math.degrees(_math.atan2(float(y)-_ts.y,float(x)-_ts.x))%360
        def distance(x,y=None):
            if y is None:x,y=float(x[0]),float(x[1])
            return _math.hypot(float(x)-_ts.x,float(y)-_ts.y)
        class _Scr:
            def bgcolor(self,c):bgcolor(c)
            def setup(self,w=500,h=400,*a,**kw):setup(w,h)
            def title(self,t):pass
            def tracer(self,*a):pass
            def update(self):_flush()
            def done(self):_flush()
            def mainloop(self):_flush()
            def bye(self):_flush()
            def exitonclick(self):_flush()
            def screensize(self,*a,**kw):pass
            def addshape(self,*a):pass
            def register_shape(self,*a):pass
            def window_height(self):return _ts.H
            def window_width(self):return _ts.W
            def getcanvas(self):return None
            def onclick(self,*a):pass
            def listen(self,*a):pass
        _scr=_Scr()
        def Screen():return _scr
        class _T:
            def forward(self,d):return forward(d)
            def fd(self,d):return forward(d)
            def backward(self,d):return backward(d)
            def bk(self,d):return backward(d)
            def back(self,d):return backward(d)
            def right(self,a):return right(a)
            def rt(self,a):return right(a)
            def left(self,a):return left(a)
            def lt(self,a):return left(a)
            def goto(self,x,y=None):return goto(x,y)
            def setpos(self,x,y=None):return goto(x,y)
            def setposition(self,x,y=None):return goto(x,y)
            def setx(self,x):return setx(x)
            def sety(self,y):return sety(y)
            def home(self):return home()
            def circle(self,r,extent=360,steps=None):return circle(r,extent,steps)
            def dot(self,size=None,color=None):return dot(size,color)
            def penup(self):return penup()
            def pu(self):return penup()
            def up(self):return penup()
            def pendown(self):return pendown()
            def pd(self):return pendown()
            def down(self):return pendown()
            def isdown(self):return isdown()
            def pensize(self,w=None):return pensize(w)
            def width(self,w=None):return pensize(w)
            def pencolor(self,*a):return pencolor(*a)
            def fillcolor(self,*a):return fillcolor(*a)
            def color(self,*a):return color(*a)
            def begin_fill(self):return begin_fill()
            def end_fill(self):return end_fill()
            def write(self,*a,**kw):return write(*a,**kw)
            def clear(self):return clear()
            def reset(self):return reset()
            def hideturtle(self):return hideturtle()
            def ht(self):return hideturtle()
            def showturtle(self):return showturtle()
            def st(self):return showturtle()
            def isvisible(self):return isvisible()
            def speed(self,s=None):pass
            def xcor(self):return xcor()
            def ycor(self):return ycor()
            def pos(self):return pos()
            def position(self):return pos()
            def heading(self):return heading()
            def setheading(self,a):return setheading(a)
            def seth(self,a):return setheading(a)
            def towards(self,x,y=None):return towards(x,y)
            def distance(self,x,y=None):return distance(x,y)
            def shape(self,s=None):pass
            def shapesize(self,*a,**kw):pass
            def turtlesize(self,*a,**kw):pass
            def stamp(self):pass
            def clearstamp(self,s):pass
            def onclick(self,*a):pass
            def onrelease(self,*a):pass
            def ondrag(self,*a):pass
        def Turtle():return _T()
        def Pen():return _T()
        def RawTurtle(c=None):return _T()
        def RawPen(c=None):return _T()
        _tmod=_types.ModuleType('turtle')
        _tmod.__dict__.update(dict(
            forward=forward,fd=forward,backward=backward,bk=backward,back=backward,
            right=right,rt=right,left=left,lt=left,
            goto=goto,setpos=goto,setposition=goto,setx=setx,sety=sety,home=home,
            penup=penup,pu=penup,up=penup,pendown=pendown,pd=pendown,down=pendown,
            isdown=isdown,pensize=pensize,width=pensize,
            pencolor=pencolor,fillcolor=fillcolor,color=color,
            begin_fill=begin_fill,end_fill=end_fill,
            circle=circle,dot=dot,write=write,clear=clear,reset=reset,
            hideturtle=hideturtle,ht=hideturtle,showturtle=showturtle,st=showturtle,
            isvisible=isvisible,speed=speed,tracer=tracer,update=update,delay=delay,
            bgcolor=bgcolor,title=title,setup=setup,screensize=screensize,
            done=done,mainloop=done,bye=done,exitonclick=done,
            xcor=xcor,ycor=ycor,pos=pos,position=pos,
            heading=heading,setheading=setheading,seth=setheading,
            towards=towards,distance=distance,
            Screen=Screen,Turtle=Turtle,Pen=Pen,RawTurtle=RawTurtle,RawPen=RawPen,
            _mlp_flush=_flush,_mlp_state=_ts
        ))
        _sys.modules['turtle']=_tmod
    _mlp_setup_turtle()
    del _mlp_setup_turtle
except Exception:pass
`;

/* ── Copy code button ────────────────────────────────────────── */
function copyCode() {
    if (!pyEditor) return;
    var code = pyEditor.getValue();
    if (!code) return;
    var btn = $id('mlp-py-copy-btn');
    var clipSVG = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
    var checkSVG = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
    function flash() {
        if (btn) { btn.innerHTML = checkSVG + ' Copied!'; btn.style.color = '#60a5fa'; btn.style.borderColor = '#3b82f6'; }
        setTimeout(function() {
            if (btn) { btn.innerHTML = clipSVG + ' Copy'; btn.style.color = ''; btn.style.borderColor = ''; }
        }, 1600);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(code).then(flash).catch(function() {
            var ta = document.createElement('textarea');
            ta.value = code; ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
            document.body.appendChild(ta); ta.select();
            try { document.execCommand('copy'); flash(); } catch(e2) {}
            document.body.removeChild(ta);
        });
    } else {
        var ta = document.createElement('textarea');
        ta.value = code; ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); flash(); } catch(e2) {}
        document.body.removeChild(ta);
    }
}

/* ── Code formatter (autopep8 via micropip) ─────────────────── */
var _blackReady = false;
var _blackLoading = false;

function formatCode() {
    var fmtBtn = $id('mlp-py-format-btn');
    if (!pyEditor) return;
    var code = pyEditor.getValue();
    if (!code.trim()) return;
    if (fmtBtn) { fmtBtn.disabled = true; fmtBtn.textContent = 'Formatting…'; }

    var _pencilSVG = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';

    function restoreBtn() {
        if (fmtBtn) {
            fmtBtn.disabled = false;
            fmtBtn.classList.remove('mlp-py-format-active');
            fmtBtn.innerHTML = _pencilSVG + ' Format';
        }
    }

    function doFormat(py) {
        return py.runPythonAsync(
            'import autopep8 as _ap, json as _json\n' +
            '_fmtout = None\n' +
            'try:\n' +
            '    _fmtout = _json.dumps({"ok": True, "code": _ap.fix_code(' + JSON.stringify(code) + ', options={"aggressive": 1})})\n' +
            'except Exception as _e:\n' +
            '    _fmtout = _json.dumps({"ok": False, "err": str(_e)})\n' +
            '_fmtout\n'
        ).then(function(res) {
            var data;
            try { data = JSON.parse(res); } catch(e) { data = { ok: false, err: 'Unexpected response: ' + String(res) }; }
            if (data && data.ok) {
                pyEditor.setValue(data.code);
                _unsaved = true;
                setSave('● Unsaved');
                pyToast('Code formatted ✓', 'succ', 1800);
            } else {
                pyToast('Format error: ' + (data && data.err ? data.err : res), 'err', 3000);
            }
        });
    }

    ensurePyodide().then(function(py) {
        if (_blackReady) return doFormat(py);
        if (_blackLoading) { pyToast('Formatter still loading…', '', 1500); restoreBtn(); return; }
        _blackLoading = true;
        if (fmtBtn) fmtBtn.classList.add('mlp-py-format-active');
        appendOutput('📦 Loading formatter…', 'mlp-py-out-info');
        return py.loadPackage('micropip').then(function() {
            return py.runPythonAsync(
                'import micropip as _mp\nawait _mp.install("autopep8")\ndel _mp'
            );
        }).then(function() {
            _blackReady = true;
            _blackLoading = false;
            appendOutput('✓ Formatter ready', 'mlp-py-out-succ');
            return doFormat(py);
        }).catch(function(err) {
            _blackLoading = false;
            throw err;
        });
    }).catch(function(err) {
        _blackLoading = false;
        pyToast('Formatter error: ' + (err && err.message ? err.message : 'install failed'), 'err', 3500);
    }).finally(restoreBtn);
}

/* ── Run selected code ──────────────────────────────────────── */
function runSelection() {
    if (running || !pyEditor) return;
    var sel = pyEditor.getSelection();
    var selected = pyEditor.getModel() ? pyEditor.getModel().getValueInRange(sel) : '';
    if (!selected || !selected.trim()) {
        pyToast('No selection — select code first', '', 2000);
        return;
    }
    _runCodeString(selected, true);
}

/* ── Run code ───────────────────────────────────────────────── */
function runCode(){
    if(running) return;
    var code = pyEditor ? pyEditor.getValue() : '';
    if(!code.trim()){
        appendOutput('# (nothing to run)', 'mlp-py-out-info');
        return;
    }
    _runCodeString(code, false);
}

function runProfile() {
    if (running) return;
    if (!pyEditor) return;
    var code = pyEditor.getValue().trim();
    if (!code) { appendOutput('# (nothing to profile)', 'mlp-py-out-info'); return; }

    running = true; setRunBtnState(true);
    _clearErrorDecorations();
    clearOutput();
    var _vrun = MLP_PY_VERSIONS[_activePyVersion] || MLP_PY_VERSIONS['3.12'];
    appendOutput('🐍 Loading ' + _vrun.label + ' runtime…', 'mlp-py-out-info');

    var PROFILE_WRAPPER = [
        'import cProfile as _cp, pstats as _ps, io as _io',
        '_profiler = _cp.Profile()',
        '_profiler.enable()',
        'try:',
        '    exec(compile(_mlp_profile_code, "<profile>", "exec"), globals())',
        'finally:',
        '    _profiler.disable()',
        '_s = _io.StringIO()',
        '_ps.Stats(_profiler, stream=_s).sort_stats("cumulative").print_stats(25)',
        'import js as _j2',
        '_j2.mlpPyShowProfiler(_s.getvalue())',
        'del _cp, _ps, _io, _profiler, _s, _j2, _mlp_profile_code'
    ].join('\n');

    ensurePyodide().then(function(py) {
        _pyInstance = py;
        var outEl = $id('mlp-py-output');
        if (outEl) outEl.innerHTML = '';
        appendOutput('⏱ Profiling…', 'mlp-py-out-info');

        try { py.runPython('import sys, io; sys.stdout = io.StringIO(); sys.stderr = io.StringIO()'); } catch(e) {}
        try { py.runPython(_MLP_PY_PATCHES); } catch(e) {}
        try { py.runPython(_MLP_TURTLE_PATCH); } catch(e) {}

        /* Pass user code as a Python global — no escaping needed */
        try { py.globals.set('_mlp_profile_code', code); } catch(e) {}

        var t0 = Date.now();
        py.runPythonAsync(PROFILE_WRAPPER).then(function() {
            return _finishRun(py, t0, null, null);
        }).catch(function(pyErr) {
            var raw = (pyErr && pyErr.message) ? pyErr.message : String(pyErr);
            appendOutput(_cleanPyError(raw), 'mlp-py-out-err');
            setStatus('Error');
            _hideStdinPrompt();
            running = false; setRunBtnState(false);
        });
    }).catch(function(err) {
        appendOutput('⚠ ' + String(err), 'mlp-py-out-err');
        running = false; setRunBtnState(false);
    });
}

function _runCodeString(code, isSelection) {
    running = true;
    setRunBtnState(true);
    _clearErrorDecorations();
    clearOutput();
    if (isSelection) appendOutput('▶ Running selection…', 'mlp-py-out-info');
    var _vrun = MLP_PY_VERSIONS[_activePyVersion] || MLP_PY_VERSIONS['3.12'];
    appendOutput('🐍 Loading ' + _vrun.label + ' runtime…', 'mlp-py-out-info');

    ensurePyodide().then(function(py){
        _pyInstance = py;
        var outEl = $id('mlp-py-output');
        if(outEl) outEl.innerHTML = '';
        if (isSelection) appendOutput('▶ Running selection…', 'mlp-py-out-info');

        /* Reset stdout/stderr for this run */
        try {
            py.runPython('import sys, io; sys.stdout = io.StringIO(); sys.stderr = io.StringIO()');
        } catch(e) {}

        /* Patch matplotlib to render inline */
        try {
            py.runPython([
                'try:',
                '    import matplotlib',
                '    matplotlib.use("Agg")',
                '    import matplotlib.pyplot as _plt_orig',
                '    import js as _js_mlp, base64 as _b64, io as _io_mlp',
                '    _orig_show = _plt_orig.show',
                '    def _mlp_show(*a, **kw):',
                '        buf = _io_mlp.BytesIO()',
                '        _plt_orig.savefig(buf, format="png", bbox_inches="tight", dpi=120)',
                '        buf.seek(0)',
                '        _js_mlp.mlpPyShowPlot(_b64.b64encode(buf.read()).decode())',
                '        _plt_orig.clf()',
                '    _plt_orig.show = _mlp_show',
                '    del _orig_show',
                'except Exception: pass'
            ].join('\n'));
        } catch(e) {}

        /* Patch input() to use the inline stdin prompt */
        try {
            py.runPython([
                'import builtins as _b2, js as _js_inp',
                'async def _mlp_input_async(prompt=""):',
                '    import sys as _s2',
                '    buf = _s2.stdout.getvalue()',
                '    if buf: _js_inp.mlpPyFlushOutput(buf); _s2.stdout.truncate(0); _s2.stdout.seek(0)',
                '    val = await _js_inp.mlpPyRequestInput(str(prompt))',
                '    _js_inp.mlpPyEchoInput(str(prompt), val)',
                '    return val if val is not None else ""',
                '_b2.input = _mlp_input_async',
                'del _b2, _js_inp'
            ].join('\n'));
        } catch(e) {}

        /* Apply all browser-compat patches */
        try { py.runPython(_MLP_PY_PATCHES); } catch(e) {}

        /* Install turtle mock (resets state + registers sys.modules['turtle']) */
        try { py.runPython(_MLP_TURTLE_PATCH); } catch(e) {}

        var t0 = Date.now();
        var exitCode = null;

        py.runPythonAsync(code).then(function() {
            return _finishRun(py, t0, exitCode, null);
        }).catch(function(pyErr) {
            var raw = (pyErr && pyErr.message) ? pyErr.message : String(pyErr);
            var sysExitMatch = raw.match(/SystemExit(?::\s*(.*))?/);
            if (sysExitMatch) {
                exitCode = sysExitMatch[1] !== undefined ? sysExitMatch[1].trim() : '0';
                return _finishRun(py, t0, exitCode, null);
            } else {
                var preErrOut = '';
                try { preErrOut = py.runPython('sys.stdout.getvalue()'); } catch(e){}
                if (preErrOut) appendOutput(preErrOut, '');
                appendOutput(_cleanPyError(raw), 'mlp-py-out-err');
                _highlightErrorLine(raw);
                setStatus('Error — ' + (raw.split('\n').pop() || 'see output'));
                _hideStdinPrompt();
                running = false; setRunBtnState(false);
            }
        });

    }).catch(function(err){
        var outEl = $id('mlp-py-output');
        if(outEl) outEl.innerHTML = '';
        appendOutput(_cleanPyError((err && err.message) ? err.message : String(err)), 'mlp-py-out-err');
        setStatus('Error');
        _hideStdinPrompt();
        running = false; setRunBtnState(false);
    });
}

function _finishRun(py, t0, exitCode, _unused) {
    _hideStdinPrompt();
    /* Flush any remaining matplotlib figures */
    try {
        py.runPython([
            'try:',
            '    import matplotlib.pyplot as _p2',
            '    if _p2.get_fignums(): _p2.show()',
            'except Exception: pass'
        ].join('\n'));
    } catch(e) {}

    /* Flush any pending turtle drawing commands */
    try {
        py.runPython([
            'try:',
            '    import turtle as _t2',
            '    if hasattr(_t2, "_mlp_flush") and _t2._mlp_state.C: _t2._mlp_flush()',
            'except Exception: pass'
        ].join('\n'));
    } catch(e) {}

    var stdout = '', stderr = '';
    try { stdout = py.runPython('sys.stdout.getvalue()'); } catch(e){}
    try { stderr = py.runPython('sys.stderr.getvalue()'); } catch(e){}
    if (stdout) appendOutput(stdout, '');
    if (stderr) appendOutput(stderr, 'mlp-py-out-err');

    /* Capture variables for inspector */
    try {
        var varsJson = py.runPython([
            'import json as _j, builtins as _bi',
            '_skip = set(dir(_bi)) | {"__builtins__","__doc__","__loader__","__name__","__package__","__spec__","__file__","__cached__","In","Out","get_ipython","exit","quit","_","__","___"}',
            '_vars = []',
            'for _k, _v in list(globals().items()):',
            '    if _k.startswith("_") or _k in _skip: continue',
            '    if callable(_v) and not isinstance(_v, type): continue',
            '    try:',
            '        _r = repr(_v)',
            '        _vars.append({"name": _k, "type": type(_v).__name__, "val": _r[:120] + ("…" if len(_r)>120 else "")})',
            '    except Exception: pass',
            '_j.dumps(_vars[:40])'
        ].join('\n'));
        _renderVars(varsJson);
    } catch(e) {}

    var ms = Date.now() - t0;
    if (exitCode !== null) {
        var exitOk = (exitCode === '0' || exitCode === '');
        if (!stdout && !stderr) appendOutput('(no output)', 'mlp-py-out-info');
        appendOutput('\n⏹ Exited' + (exitCode ? ' (code ' + exitCode + ')' : ''), exitOk ? 'mlp-py-out-ok' : 'mlp-py-out-err');
        setStatus('Exited' + (exitCode ? ' with code ' + exitCode : ''));
    } else {
        if (!stdout && !stderr) appendOutput('(no output)', 'mlp-py-out-info');
        appendOutput('\n✓ Done in ' + ms + 'ms', 'mlp-py-out-ok');
        setStatus('Done · ' + ms + 'ms');
    }
    running = false; setRunBtnState(false);
}

function setRunBtnState(isRunning){
    var btn = $id('mlp-py-run');
    if(!btn) return;
    if(isRunning){
        btn.innerHTML = '<span class="mlp-py-spinner"></span> Running…';
        btn.disabled = true;
    } else {
        btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run';
        btn.disabled = false;
    }
}

/* ── Save ───────────────────────────────────────────────────── */
function saveProject(){
    if(!_activeId) return;
    var code = pyEditor ? pyEditor.getValue() : '';
    var now  = Date.now();
    updateProject(_activeId, {
        python:        code,
        type:          'python',
        pythonVersion: _activePyVersion,
        updated:       now,
    });
    _unsaved = false;
    var d = new Date(now);
    setSave('Saved ' + d.toLocaleTimeString());
    pyToast('Project saved', 'succ', 1800);
}

/* ── Export ──��───���──────────────────────────────────────────── */
function exportProject(){
    var code = pyEditor ? pyEditor.getValue() : '';
    var p    = _activeId ? getProject(_activeId) : null;
    var name = (p && p.name) ? p.name.replace(/[^a-z0-9_\-]/gi, '_') : 'python_project';
    var blob = new Blob([code], { type: 'text/x-python' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a');
    a.href   = url;
    a.download = name + '.py';
    document.body.appendChild(a);
    a.click();
    setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(url); }, 500);
    pyToast('Exported ' + name + '.py', 'succ', 2200);
}

/* ── Update version display in topbar + status bar ──────────── */
function _updateVersionDisplay() {
    var vinfo = MLP_PY_VERSIONS[_activePyVersion] || MLP_PY_VERSIONS['3.12'];
    var badge = $id('mlp-py-version-badge');
    if (badge) badge.textContent = vinfo.label;
    var statusVer = $id('mlp-py-status-version');
    if (statusVer) statusVer.textContent = vinfo.label;
}

/* ── Open / Close overlay ───────────────────────────────────── */
function openPythonEditor(projectId){
    var p = getProject(projectId);
    if(!p || p.type !== 'python') return;
    _activeId = projectId;
    _unsaved  = false;

    /* Load the project's saved Python version (default 3.12) */
    _activePyVersion = (p.pythonVersion && MLP_PY_VERSIONS[p.pythonVersion]) ? p.pythonVersion : '3.12';
    _updateVersionDisplay();

    var nameEl = $id('mlp-py-name');
    if(nameEl) nameEl.textContent = p.name || 'Untitled';

    var overlay = $id('mlp-python-overlay');
    if(overlay) overlay.classList.add('mlp-py-active');
    
    /* Hide HTML chat when Python editor opens */
    document.documentElement.classList.add('mlp-py-editor-active');

    setSave('');
    setStatus('Ready');
    clearOutput();
    var vinfo = MLP_PY_VERSIONS[_activePyVersion] || MLP_PY_VERSIONS['3.12'];
    appendOutput('# ' + vinfo.label + ' — Press Run (▶) or Ctrl+Enter to execute.', 'mlp-py-out-info');

    /* Mount / update Monaco */
    if(monacoReady && window.monaco){
        if(!pyEditor){
            mountMonaco(p.python || '');
        } else {
            pyEditor.setValue(p.python || '');
            pyEditor.setScrollPosition({ scrollTop: 0 });
        }
    } else {
        waitForMonacoThenMount(p.python || '');
    }

    /* Wire up Python chat listeners now that editor is open */
    var chatClose   = $id('mlp-py-chat-close');
    var chatSend    = $id('mlp-py-chat-send');
    var chatInput   = $id('mlp-py-chat-input');
    var chatOverlay = $id('mlp-py-chat-overlay');
    var chatFab     = $id('mlp-py-chat-fab');

    /* Show the FAB (hidden until editor is open) */
    if (chatFab) {
        chatFab.classList.remove('mlp-py-fab-hidden');
        /* Only attach listener once */
        if (!chatFab._mlpWired) {
            chatFab.addEventListener('click', _openPyChat);
            chatFab._mlpWired = true;
        }
    }

    if(chatClose)   chatClose.addEventListener('click', _closePyChat);
    if(chatSend)    chatSend.addEventListener('click',  _sendPyChat);
    if(chatOverlay) chatOverlay.addEventListener('click', _closePyChat);
    if(chatInput) {
        chatInput.addEventListener('keydown', function(e) {
            if((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                _sendPyChat();
            }
        });
    }

    /* ── Background pre-warm: start loading Pyodide now so first Run is instant ── */
    setTimeout(function() {
        if (_pyInstance) return; /* already warm from a previous open */
        setStatus('⚡ Warming up runtime…');
        ensurePyodide().then(function(py) {
            _pyInstance = py;
            /* Pre-apply all patches so they are not charged to the first Run */
            try { py.runPython(_MLP_PY_PATCHES); } catch(e) {}
            /* Pre-init stdout/stderr capture */
            try { py.runPython('import sys, io; sys.stdout = io.StringIO(); sys.stderr = io.StringIO()'); } catch(e) {}
            setStatus('Runtime ready ⚡');
            setTimeout(function() { setStatus('Ready'); }, 2000);
        }).catch(function() {
            setStatus('Ready'); /* silent — user will see the real error on Run */
        });
    }, 300);
}

function closePythonEditor(){
    if(_unsaved){
        if(!confirm('You have unsaved changes. Leave without saving?')) return;
    }
    var overlay = $id('mlp-python-overlay');
    if(overlay) overlay.classList.remove('mlp-py-active');

    /* Hide FAB, close chat panel, close packages panel when editor closes */
    _closePyChat();
    _closePyPackages();
    var chatFab = $id('mlp-py-chat-fab');
    if (chatFab) { chatFab.classList.add('mlp-py-fab-hidden'); }

    /* Show HTML chat when Python editor closes */
    document.documentElement.classList.remove('mlp-py-editor-active');
    
    _activeId = null;
    running   = false;
    /* Reopen the projects overlay — do NOT fall through to the HTML editor */
    if(typeof window.mlpProjectsOpen === 'function'){
        window.mlpProjectsOpen();
    } else {
        var projOverlay = document.getElementById('mlp-projects-overlay');
        if(projOverlay){
            projOverlay.classList.remove('mlp-proj-hidden');
            projOverlay.style.display = '';
            document.body.style.overflow = 'hidden';
        }
    }
}

/* ── Monaco ─────────────────────────────────────────────────── */
function _registerPyCompletions(){
    if(window._mlpPyCompletionRegistered) return;
    window._mlpPyCompletionRegistered = true;

    var PY_KEYWORDS = [
        'False','None','True','and','as','assert','async','await',
        'break','class','continue','def','del','elif','else','except',
        'finally','for','from','global','if','import','in','is',
        'lambda','nonlocal','not','or','pass','raise','return',
        'try','while','with','yield'
    ];
    var PY_BUILTINS = [
        'abs','all','any','ascii','bin','bool','breakpoint','bytearray',
        'bytes','callable','chr','classmethod','compile','complex',
        'delattr','dict','dir','divmod','enumerate','eval','exec',
        'filter','float','format','frozenset','getattr','globals',
        'hasattr','hash','help','hex','id','input','int','isinstance',
        'issubclass','iter','len','list','locals','map','max',
        'memoryview','min','next','object','oct','open','ord','pow',
        'print','property','range','repr','reversed','round','set',
        'setattr','slice','sorted','staticmethod','str','sum','super',
        'tuple','type','vars','zip',
        '__name__','__doc__','__file__','__package__','__spec__'
    ];
    var PY_SNIPPETS = [
        { label:'def',       detail:'Function definition',
          insertText:'def ${1:name}(${2:args}):\n\t${3:pass}' },
        { label:'class',     detail:'Class definition',
          insertText:'class ${1:Name}:\n\tdef __init__(self):\n\t\t${2:pass}' },
        { label:'if',        detail:'If statement',
          insertText:'if ${1:condition}:\n\t${2:pass}' },
        { label:'if/else',   detail:'If/else statement',
          insertText:'if ${1:condition}:\n\t${2:pass}\nelse:\n\t${3:pass}' },
        { label:'elif',      detail:'Elif clause',
          insertText:'elif ${1:condition}:\n\t${2:pass}' },
        { label:'for',       detail:'For loop',
          insertText:'for ${1:item} in ${2:iterable}:\n\t${3:pass}' },
        { label:'while',     detail:'While loop',
          insertText:'while ${1:condition}:\n\t${2:pass}' },
        { label:'try',       detail:'Try/except block',
          insertText:'try:\n\t${1:pass}\nexcept ${2:Exception} as ${3:e}:\n\t${4:pass}' },
        { label:'try/finally',detail:'Try/finally block',
          insertText:'try:\n\t${1:pass}\nfinally:\n\t${2:pass}' },
        { label:'with',      detail:'With statement',
          insertText:'with ${1:expr} as ${2:var}:\n\t${3:pass}' },
        { label:'import',    detail:'Import statement',
          insertText:'import ${1:module}' },
        { label:'from',      detail:'From import',
          insertText:'from ${1:module} import ${2:name}' },
        { label:'print',     detail:'print(value, ...)',
          insertText:'print(${1:value})' },
        { label:'range',     detail:'range(stop) / range(start, stop[, step])',
          insertText:'range(${1:stop})' },
        { label:'len',       detail:'Return length of object',
          insertText:'len(${1:obj})' },
        { label:'enumerate', detail:'enumerate(iterable, start=0)',
          insertText:'enumerate(${1:iterable})' },
        { label:'zip',       detail:'zip(*iterables)',
          insertText:'zip(${1:iter1}, ${2:iter2})' },
        { label:'map',       detail:'map(func, iterable)',
          insertText:'map(${1:func}, ${2:iterable})' },
        { label:'filter',    detail:'filter(func, iterable)',
          insertText:'filter(${1:func}, ${2:iterable})' },
        { label:'sorted',    detail:'sorted(iterable, *, key=None, reverse=False)',
          insertText:'sorted(${1:iterable}, key=${2:None})' },
        { label:'open',      detail:'open(file, mode="r")',
          insertText:'open(${1:filename}, ${2:"r"})' },
        { label:'lambda',    detail:'Lambda expression',
          insertText:'lambda ${1:args}: ${2:expr}' },
        { label:'list comp', detail:'List comprehension',
          insertText:'[${1:expr} for ${2:item} in ${3:iterable}]' },
        { label:'dict comp', detail:'Dict comprehension',
          insertText:'{${1:key}: ${2:value} for ${3:item} in ${4:iterable}}' },
        { label:'set comp',  detail:'Set comprehension',
          insertText:'{${1:expr} for ${2:item} in ${3:iterable}}' },
        { label:'main',      detail:'if __name__ == "__main__" guard',
          insertText:'if __name__ == "__main__":\n\t${1:main()}' },
        { label:'@property', detail:'Property decorator',
          insertText:'@property\ndef ${1:name}(self):\n\treturn self._${1:name}' },
        { label:'@staticmethod', detail:'Static method decorator',
          insertText:'@staticmethod\ndef ${1:name}(${2:args}):\n\t${3:pass}' },
        { label:'@classmethod', detail:'Class method decorator',
          insertText:'@classmethod\ndef ${1:name}(cls, ${2:args}):\n\t${3:pass}' },
    ];

    window.monaco.languages.registerCompletionItemProvider('python', {
        triggerCharacters: ['('],   /* space/tab/newline removed — they break word-prefix filtering */
        provideCompletionItems: function(model, position) {
            var word  = model.getWordUntilPosition(position);
            var range = {
                startLineNumber: position.lineNumber,
                endLineNumber:   position.lineNumber,
                startColumn:     word.startColumn,
                endColumn:       word.endColumn
            };
            var K  = window.monaco.languages.CompletionItemKind;
            var IT = window.monaco.languages.CompletionItemInsertTextRule;
            var suggestions = [];

            PY_KEYWORDS.forEach(function(kw){
                suggestions.push({
                    label: kw, kind: K.Keyword,
                    insertText: kw, range: range
                });
            });
            PY_BUILTINS.forEach(function(bi){
                suggestions.push({
                    label: bi, kind: K.Function,
                    insertText: bi, range: range
                });
            });
            PY_SNIPPETS.forEach(function(sn){
                suggestions.push({
                    label: sn.label, kind: K.Snippet,
                    detail: sn.detail,
                    insertText: sn.insertText,
                    insertTextRules: IT.InsertAsSnippet,
                    range: range
                });
            });

            /* Word-based suggestions from the current document */
            var text  = model.getValue();
            var words = text.match(/[a-zA-Z_]\w*/g) || [];
            var seen  = {};
            words.forEach(function(w){
                if(seen[w] || w.length < 3) return;
                seen[w] = true;
                suggestions.push({
                    label: w, kind: K.Text,
                    detail: 'identifier in file',
                    insertText: w, range: range
                });
            });

            return { suggestions: suggestions };
        }
    });

    /* ── self. member provider ────────────────────────────────
       Fires only when the text immediately before the cursor is
       "self."  Scans the whole document to collect:
         • instance attributes   self.foo = ...
         • method names          def bar(self ...)
       and returns them as dot-member suggestions.              */
    window.monaco.languages.registerCompletionItemProvider('python', {
        triggerCharacters: ['.'],
        provideCompletionItems: function(model, position) {
            /* Check that the character just before the cursor word is
               a dot preceded by "self"                              */
            var lineText   = model.getLineContent(position.lineNumber);
            var colBefore  = position.column - 1;            /* 1-based col before cursor word */
            var textBefore = lineText.substring(0, colBefore);

            /* Must end with "self." (allowing spaces is intentional for
               edge-cases like `self .` but we keep it strict here)   */
            if(!/\bself\.$/.test(textBefore)) return { suggestions: [] };

            var text        = model.getValue();
            var K           = window.monaco.languages.CompletionItemKind;
            var IT          = window.monaco.languages.CompletionItemInsertTextRule;
            var membersSeen = {};
            var suggestions = [];

            /* ── Determine which class block the cursor is in ────── */
            /* Walk backwards through lines to find the nearest "class Xxx:" */
            var cursorLine = position.lineNumber;
            var classIndent = -1;
            var className   = '';
            var lines = text.split('\n');
            for(var i = cursorLine - 1; i >= 0; i--){
                var m = lines[i].match(/^(\s*)class\s+(\w+)/);
                if(m){
                    classIndent = m[1].length;
                    className   = m[2];
                    break;
                }
            }

            /* ── Collect self.xxx attributes ─────────────────────── */
            /* Regex: self.identifier followed by = or ( or . or , or )  */
            var attrRe = /\bself\.([a-zA-Z_]\w*)/g;
            var match;
            while((match = attrRe.exec(text)) !== null){
                var name = match[1];
                if(membersSeen[name]) continue;
                membersSeen[name] = true;

                /* Guess kind: if there's a "def <name>(self" anywhere it's a method */
                var isMethod = new RegExp('def\\s+' + name + '\\s*\\(\\s*self').test(text);
                suggestions.push({
                    label:      name,
                    kind:       isMethod ? K.Method : K.Field,
                    detail:     isMethod ? 'method of ' + (className||'class') : 'attribute of ' + (className||'class'),
                    insertText: isMethod ? name + '(${1})' : name,
                    insertTextRules: isMethod ? IT.InsertAsSnippet : 0,
                    sortText:   '0' + name,   /* float self members to top */
                    range: {
                        startLineNumber: position.lineNumber,
                        endLineNumber:   position.lineNumber,
                        startColumn:     position.column,
                        endColumn:       position.column
                    }
                });
            }

            /* ── Also collect def'd methods that may not appear as
               self.xxx yet (e.g. defined but never called)          */
            var defRe = /def\s+([a-zA-Z_]\w*)\s*\(\s*self/g;
            while((match = defRe.exec(text)) !== null){
                var mname = match[1];
                if(membersSeen[mname]) continue;
                membersSeen[mname] = true;
                suggestions.push({
                    label:      mname,
                    kind:       K.Method,
                    detail:     'method of ' + (className||'class'),
                    insertText: mname + '(${1})',
                    insertTextRules: IT.InsertAsSnippet,
                    sortText:   '0' + mname,
                    range: {
                        startLineNumber: position.lineNumber,
                        endLineNumber:   position.lineNumber,
                        startColumn:     position.column,
                        endColumn:       position.column
                    }
                });
            }

            return { suggestions: suggestions };
        }
    });
}

function mountMonaco(initialCode){
    if(!window.monaco) return;
    var container = $id('mlp-py-editor');
    if(!container) return;

    /* Worker stub — prevents the "worker not found" console error that
       silently kills Monaco's built-in language-feature pipeline.       */
    if(!window.MonacoEnvironment){
        window.MonacoEnvironment = {
            getWorkerUrl: function(){ return 'data:text/javascript;charset=utf-8,' + encodeURIComponent('self.onmessage=function(){};'); }
        };
    }

    _registerPyCompletions();

    if(pyEditor){ pyEditor.setValue(initialCode); return; }
    pyEditor = window.monaco.editor.create(container, {
        value:     initialCode,
        language:  'python',
        theme:     'vs-dark',
        fontSize:  14,
        lineHeight: 22,
        fontFamily: "'JetBrains Mono','Fira Code','Consolas',monospace",
        minimap:   { enabled: false },
        scrollBeyondLastLine: false,
        automaticLayout: true,
        wordWrap: 'off',
        renderLineHighlight: 'line',
        cursorBlinking: 'smooth',
        smoothScrolling: true,
        folding: true,
        renderWhitespace: 'selection',
        suggestOnTriggerCharacters: true,
        quickSuggestions: { other: true, comments: false, strings: false },
        quickSuggestionsDelay: 0,
        wordBasedSuggestions: 'off',
        parameterHints: { enabled: true },
        bracketPairColorization: { enabled: true },
        padding: { top: 10, bottom: 10 },
    });
    /* Cursor position in status bar */
    pyEditor.onDidChangeCursorPosition(function(e){
        var el = $id('mlp-py-status-pos');
        if(el) el.textContent = 'Ln ' + e.position.lineNumber + ', Col ' + e.position.column;
    });
    /* Dirty tracking + inline lint */
    pyEditor.onDidChangeModelContent(function(){
        _unsaved = true;
        setSave('● Unsaved');
        _scheduleLint();
    });
    /* Keyboard shortcuts */
    pyEditor.addCommand(
        window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.Enter,
        runCode
    );
    pyEditor.addCommand(
        window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.KeyS,
        function(){ saveProject(); }
    );
}

function waitForMonacoThenMount(code){
    var tries = 0;
    var timer = setInterval(function(){
        if(window.monaco){ clearInterval(timer); monacoReady = true; mountMonaco(code); return; }
        if(++tries > 60) clearInterval(timer);
    }, 200);
}

/* ── Resizer drag ───────────────────────────────────────────── */
(function(){
    var resizer = $id('mlp-py-resizer');
    var main    = $id('mlp-py-main');
    var outWrap = $id('mlp-py-output-wrap');
    if(!resizer || !main || !outWrap) return;
    var dragging = false, startX = 0, startW = 0;
    resizer.addEventListener('mousedown', function(e){
        dragging = true; startX = e.clientX;
        startW = outWrap.getBoundingClientRect().width;
        resizer.classList.add('mlp-py-dragging');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault();
    });
    document.addEventListener('mousemove', function(e){
        if(!dragging) return;
        var dx  = startX - e.clientX;
        var mainW = main.getBoundingClientRect().width;
        var newW = Math.max(220, Math.min(mainW * 0.70, startW + dx));
        outWrap.style.width = newW + 'px';
    });
    document.addEventListener('mouseup', function(){
        if(!dragging) return;
        dragging = false;
        resizer.classList.remove('mlp-py-dragging');
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        if(pyEditor) pyEditor.layout();
    });
})();

/* ── Fullscreen toggle ──────────────────────────────────────── */
function toggleFullscreen(){
    var overlay = $id('mlp-python-overlay');
    if(!overlay) return;
    var isFs = overlay.classList.toggle('mlp-py-fullscreen');
    var btn = $id('mlp-py-fullscreen-btn');
    if(btn){
        btn.title = isFs ? 'Exit fullscreen (Ctrl+Shift+F)' : 'Toggle fullscreen (Ctrl+Shift+F)';
        btn.innerHTML = isFs
            ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="10" y1="14" x2="3" y2="21"/><line x1="21" y1="3" x2="14" y2="10"/></svg>'
            : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>';
    }
    if(pyEditor) setTimeout(function(){ pyEditor.layout(); }, 50);
}

/* ── Package installer ───────────────────────────────────────── */
var _pyPkgState = {}; /* pkgName → 'idle'|'installing'|'done'|'error' */
var MLP_PY_PKG_LS_KEY = 'mlp_py_installed_pkgs';

/* Persist installed packages + any custom entries to localStorage */
function _savePkgsToLS() {
    var defaultNames = [
        'numpy','pandas','matplotlib','scipy','sympy','Pillow',
        'scikit-learn','seaborn','statsmodels','networkx','openpyxl','beautifulsoup4'
    ];
    var installed = Object.keys(_pyPkgState).filter(function(k) {
        return _pyPkgState[k] === 'done';
    });
    var custom = MLP_PY_PACKAGES
        .filter(function(p) { return defaultNames.indexOf(p.name) === -1; })
        .map(function(p) { return { name: p.name, label: p.label, desc: p.desc }; });
    try {
        localStorage.setItem(MLP_PY_PKG_LS_KEY, JSON.stringify({ installed: installed, custom: custom }));
    } catch(e) {}
}

/* On page load: restore custom package entries and auto-reinstall saved packages */
function _loadPkgsFromLS() {
    try {
        var data = JSON.parse(localStorage.getItem(MLP_PY_PKG_LS_KEY));
        if (!data) return;
        /* Re-add any custom packages to the known list */
        if (data.custom && data.custom.length) {
            var existingNames = MLP_PY_PACKAGES.map(function(p) { return p.name; });
            data.custom.forEach(function(p) {
                if (existingNames.indexOf(p.name) === -1) {
                    MLP_PY_PACKAGES.push({ name: p.name, label: p.label, desc: p.desc || 'Custom package', builtin: false });
                }
            });
        }
        /* Auto-reinstall previously installed packages */
        if (data.installed && data.installed.length) {
            data.installed.forEach(function(pkgName) {
                var exists = MLP_PY_PACKAGES.some(function(p) { return p.name === pkgName; });
                if (!exists) {
                    MLP_PY_PACKAGES.push({ name: pkgName, label: pkgName, desc: 'Custom package', builtin: false });
                }
                _installPyPackage(pkgName);
            });
        }
    } catch(e) {}
}

var MLP_PY_PACKAGES = [
    { name: 'numpy',          label: 'NumPy',          desc: 'Numerical computing',       builtin: true  },
    { name: 'pandas',         label: 'Pandas',         desc: 'Data analysis',              builtin: true  },
    { name: 'matplotlib',     label: 'Matplotlib',     desc: 'Plotting & charts',          builtin: true  },
    { name: 'scipy',          label: 'SciPy',          desc: 'Scientific computing',       builtin: true  },
    { name: 'sympy',          label: 'SymPy',          desc: 'Symbolic math',              builtin: true  },
    { name: 'Pillow',         label: 'Pillow (PIL)',   desc: 'Image processing',           builtin: true  },
    { name: 'scikit-learn',   label: 'scikit-learn',   desc: 'Machine learning',           builtin: false },
    { name: 'seaborn',        label: 'Seaborn',        desc: 'Statistical visualisation',  builtin: false },
    { name: 'statsmodels',    label: 'statsmodels',    desc: 'Statistics & econometrics',  builtin: false },
    { name: 'networkx',       label: 'NetworkX',       desc: 'Graph / network analysis',   builtin: true  },
    { name: 'openpyxl',       label: 'openpyxl',       desc: 'Read / write Excel files',   builtin: false },
    { name: 'beautifulsoup4', label: 'BeautifulSoup4', desc: 'HTML / XML parsing',         builtin: false },
];

function _openPyPackages() {
    var panel = $id('mlp-py-pkg-panel');
    var btn   = $id('mlp-py-pkg-btn-top');
    if (panel) panel.classList.add('mlp-py-pkg-open');
    if (btn)   btn.classList.add('mlp-py-pkg-open');
    _renderPkgList();
}

function _closePyPackages() {
    var panel = $id('mlp-py-pkg-panel');
    var btn   = $id('mlp-py-pkg-btn-top');
    if (panel) panel.classList.remove('mlp-py-pkg-open');
    if (btn)   btn.classList.remove('mlp-py-pkg-open');
}

function _renderPkgList() {
    var list = $id('mlp-py-pkg-list');
    if (!list) return;
    list.innerHTML = '';
    MLP_PY_PACKAGES.forEach(function(pkg) {
        var state = _pyPkgState[pkg.name] || 'idle';
        var item = document.createElement('div');
        item.className = 'mlp-py-pkg-item';

        var info = document.createElement('div');
        info.className = 'mlp-py-pkg-info';

        var nameEl = document.createElement('div');
        nameEl.className = 'mlp-py-pkg-name';
        nameEl.textContent = pkg.label;
        if (pkg.builtin) {
            var tag = document.createElement('span');
            tag.style.cssText = 'margin-left:5px;font-size:.58rem;padding:1px 5px;background:rgba(34,197,94,.12);color:#4ade80;border-radius:3px;font-weight:700;vertical-align:middle;';
            tag.textContent = 'built-in';
            nameEl.appendChild(tag);
        }

        var descEl = document.createElement('div');
        descEl.className = 'mlp-py-pkg-desc';
        descEl.textContent = pkg.desc;

        info.appendChild(nameEl);
        info.appendChild(descEl);

        var btnEl = document.createElement('button');
        btnEl.className = 'mlp-py-pkg-btn ' + state;
        btnEl.type = 'button';
        btnEl.dataset.pkg = pkg.name;

        if (state === 'idle')            { btnEl.textContent = 'Install'; }
        else if (state === 'installing') { btnEl.textContent = '…'; btnEl.disabled = true; }
        else if (state === 'done')       { btnEl.textContent = 'Uninstall'; }
        else if (state === 'error')      { btnEl.textContent = '✗ Retry'; }

        if (state === 'idle' || state === 'error') {
            btnEl.addEventListener('click', function() { _installPyPackage(pkg.name); });
        } else if (state === 'done') {
            btnEl.addEventListener('click', function() { _uninstallPyPackage(pkg.name); });
        }

        item.appendChild(info);
        item.appendChild(btnEl);
        list.appendChild(item);
    });
}

var _pkgProgressEls = {}; /* pkgName → DOM span for its progress bar */

function _appendInstallProgress(pkgName) {
    var el = $id('mlp-py-output');
    if (!el) return;
    var wrap = document.createElement('span');
    wrap.className = 'mlp-py-out-line mlp-py-out-info';
    wrap.textContent = '📦 Installing ' + pkgName + '…';
    var bar = document.createElement('div');
    bar.className = 'mlp-py-pkg-progress';
    bar.innerHTML = '<div class="mlp-py-pkg-progress-bar"></div>';
    wrap.appendChild(bar);
    el.appendChild(wrap);
    el.scrollTop = el.scrollHeight;
    _pkgProgressEls[pkgName] = wrap;
}
function _removeInstallProgress(pkgName) {
    var el = _pkgProgressEls[pkgName];
    if (el && el.parentNode) el.parentNode.removeChild(el);
    delete _pkgProgressEls[pkgName];
}

function _installPyPackage(pkgName) {
    if (_pyPkgState[pkgName] === 'installing' || _pyPkgState[pkgName] === 'done') return;
    _pyPkgState[pkgName] = 'installing';
    _renderPkgList();

    _appendInstallProgress(pkgName);

    ensurePyodide().then(function(py) {
        /* Try Pyodide's built-in package loader first — it handles packages like
           seaborn, scikit-learn, statsmodels, etc. that ship as compiled Pyodide
           wheels. micropip alone can't install those because PyPI only has CPython
           wheels that don't run in the browser. */
        return py.loadPackage([pkgName]).catch(function() {
            /* Fall back to micropip for pure-Python packages not in Pyodide's repo */
            return py.runPythonAsync(
                'import micropip as _mp\nawait _mp.install(' + JSON.stringify(pkgName) + ')\ndel _mp'
            );
        });
    }).then(function() {
        _removeInstallProgress(pkgName);
        _pyPkgState[pkgName] = 'done';
        _savePkgsToLS();
        _renderPkgList();
        appendOutput('✓ ' + pkgName + ' installed — you can now import it.', 'mlp-py-out-ok');
        pyToast(pkgName + ' ready', 'succ', 2000);
    }).catch(function(err) {
        _removeInstallProgress(pkgName);
        _pyPkgState[pkgName] = 'error';
        _renderPkgList();
        var raw = (err && err.message) ? err.message : String(err);
        var msg = _cleanPyError(raw);
        appendOutput('✗ Failed to install ' + pkgName + ': ' + msg, 'mlp-py-out-err');
        pyToast('Install failed: ' + pkgName, 'err', 2500);
    });
}

function _uninstallPyPackage(pkgName) {
    if (_pyPkgState[pkgName] === 'installing') return;
    _pyPkgState[pkgName] = 'installing';
    _renderPkgList();
    appendOutput('🗑 Uninstalling ' + pkgName + '…', 'mlp-py-out-info');

    ensurePyodide().then(function(py) {
        /* Try micropip.uninstall; regardless of result, scrub from sys.modules */
        return py.runPythonAsync(
            'import sys as _sys\n' +
            'try:\n' +
            '    import micropip as _mp\n' +
            '    await _mp.uninstall(' + JSON.stringify(pkgName) + ')\n' +
            '    del _mp\n' +
            'except Exception:\n' +
            '    pass\n' +
            '[_sys.modules.pop(k, None) for k in list(_sys.modules.keys())\n' +
            ' if k == ' + JSON.stringify(pkgName) + ' or k.startswith(' + JSON.stringify(pkgName + '.') + ')]\n' +
            'del _sys'
        );
    }).then(function() {
        _finishUninstall(pkgName);
    }).catch(function() {
        /* Even on error, treat it as removed from session */
        _finishUninstall(pkgName);
    });
}

function _finishUninstall(pkgName) {
    var defaultNames = [
        'numpy','pandas','matplotlib','scipy','sympy','Pillow',
        'scikit-learn','seaborn','statsmodels','networkx','openpyxl','beautifulsoup4'
    ];
    _pyPkgState[pkgName] = 'idle';
    /* Remove custom packages from the list entirely */
    if (defaultNames.indexOf(pkgName) === -1) {
        MLP_PY_PACKAGES = MLP_PY_PACKAGES.filter(function(p) { return p.name !== pkgName; });
        delete _pyPkgState[pkgName];
    }
    _savePkgsToLS();
    _renderPkgList();
    appendOutput('✓ ' + pkgName + ' uninstalled from this session.', 'mlp-py-out-ok');
    pyToast(pkgName + ' removed', 'succ', 2000);
}

function _installCustomPackage() {
    var input = $id('mlp-py-pkg-custom-input');
    if (!input) return;
    var name = input.value.trim();
    if (!name) return;
    input.value = '';

    /* Add to the known list if not already there */
    var exists = MLP_PY_PACKAGES.some(function(p) { return p.name === name; });
    if (!exists) {
        MLP_PY_PACKAGES.push({ name: name, label: name, desc: 'Custom package', builtin: false });
        _savePkgsToLS(); /* persist the new custom entry immediately */
    }
    _installPyPackage(name);
}

/* ── Wire buttons ───────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function(){
    /* Restore previously installed packages from localStorage */
    _loadPkgsFromLS();

    var runBtn     = $id('mlp-py-run');
    var saveBtn    = $id('mlp-py-save');
    var exportBtn  = $id('mlp-py-export');
    var fsBtn      = $id('mlp-py-fullscreen-btn');
    var backBtn    = $id('mlp-py-back');
    var clearBtn   = $id('mlp-py-clear-btn');
    var pkgBtn     = $id('mlp-py-pkg-btn-top');
    var pkgClose   = $id('mlp-py-pkg-close');
    var pkgCustBtn = $id('mlp-py-pkg-custom-btn');
    var pkgInput   = $id('mlp-py-pkg-custom-input');

    var fmtBtn      = $id('mlp-py-format-btn');
    var varsBtn     = $id('mlp-py-vars-btn');
    var varsClose   = $id('mlp-py-vars-close');
    var snippetsBtn  = $id('mlp-py-snippets-btn');
    var copyBtn      = $id('mlp-py-copy-btn');
    var profileBtn   = $id('mlp-py-profile-btn');
    var stdinInp   = $id('mlp-py-stdin-input');
    var stdinSub   = $id('mlp-py-stdin-submit');

    if(runBtn)     runBtn.addEventListener('click',    runCode);
    if(saveBtn)    saveBtn.addEventListener('click',   saveProject);
    if(exportBtn)  exportBtn.addEventListener('click', exportProject);
    if(backBtn)    backBtn.addEventListener('click',   closePythonEditor);
    if(clearBtn)   clearBtn.addEventListener('click',  clearOutput);
    if(fsBtn)      fsBtn.addEventListener('click',     toggleFullscreen);
    if(fmtBtn)      fmtBtn.addEventListener('click',      formatCode);
    if(copyBtn)     copyBtn.addEventListener('click',     copyCode);
    if(profileBtn)  profileBtn.addEventListener('click',  runProfile);
    if(snippetsBtn) snippetsBtn.addEventListener('click', function() {
        var panel = $id('mlp-py-snippets-panel');
        if (panel && panel.classList.contains('mlp-py-snippets-open')) { _closeSnippets(); }
        else { _openSnippets(); }
    });
    if(varsBtn)    varsBtn.addEventListener('click',   function() {
        var panel = $id('mlp-py-vars-panel');
        if (panel && panel.classList.contains('mlp-py-vars-open')) { _closeVarsPanel(); }
        else { _openVarsPanel(); }
    });
    if(varsClose)  varsClose.addEventListener('click', _closeVarsPanel);
    if(stdinSub)   stdinSub.addEventListener('click',  _submitStdin);
    if(stdinInp)   stdinInp.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') { e.preventDefault(); _submitStdin(); }
    });
    if(pkgBtn)     pkgBtn.addEventListener('click',    function() {
        var panel = $id('mlp-py-pkg-panel');
        if (panel && panel.classList.contains('mlp-py-pkg-open')) { _closePyPackages(); }
        else { _openPyPackages(); }
    });
    if(pkgClose)   pkgClose.addEventListener('click',  _closePyPackages);
    if(pkgCustBtn) pkgCustBtn.addEventListener('click', _installCustomPackage);
    if(pkgInput)   pkgInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') { e.preventDefault(); _installCustomPackage(); }
    });

    /* Keyboard shortcuts */
    document.addEventListener('keydown', function(e){
        var overlay = $id('mlp-python-overlay');
        if(!overlay || !overlay.classList.contains('mlp-py-active')) return;
        if(e.key === 'Escape'){
            e.preventDefault();
            if(overlay.classList.contains('mlp-py-fullscreen')){
                toggleFullscreen();
            } else {
                closePythonEditor();
            }
        }
        /* Ctrl+Shift+F — fullscreen */
        if((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'F' || e.key === 'f')){
            e.preventDefault();
            toggleFullscreen();
        }
        /* Ctrl+Enter / Cmd+Enter — run code */
        if((e.ctrlKey || e.metaKey) && e.key === 'Enter'){
            e.preventDefault();
            runCode();
        }
        /* Alt+Shift+F — format */
        if(e.altKey && e.shiftKey && (e.key === 'F' || e.key === 'f')){
            e.preventDefault();
            formatCode();
        }
        /* Ctrl+Shift+Enter — run selection */
        if((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'Enter'){
            e.preventDefault();
            runSelection();
        }
    });
});

/* ── Public API ─────────────────────────────────────────────── */
window.mlpOpenPythonEditor  = openPythonEditor;
window.mlpClosePythonEditor = closePythonEditor;

/* ── Hook into the projects overlay's "open" action ─────────── */
/* When the projects list calls openProjectInEditor(p), if p.type === 'python'
   we intercept and open the Python editor instead. */
(function hookProjectOpen(){
    /* Poll until the projects JS is ready */
    var _orig = null;
    var tries = 0;
    var t = setInterval(function(){
        if(typeof window.mlpOpenProjectInEditor === 'function' && !window._mlpPyHooked){
            _orig = window.mlpOpenProjectInEditor;
            window.mlpOpenProjectInEditor = function(p){
                if(p && p.type === 'python'){
                    /* Close projects overlay first */
                    var projOverlay = document.getElementById('mlp-projects-overlay');
                    if(projOverlay) projOverlay.style.display = 'none';
                    openPythonEditor(p.id);
                } else {
                    _orig(p);
                }
            };
            window._mlpPyHooked = true;
            clearInterval(t);
        }
        if(++tries > 100) clearInterval(t);
    }, 150);
})();

})();
</script>
        <?php
    }
}
