<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class MLP_Ruby {
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
<style id="mlp-ruby-styles">
/* ── Ruby Editor Overlay ─────────────────────────────── */
#mlp-ruby-overlay {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 99999;
    background: var(--mlp-bg, #0e0e0e);
    flex-direction: column;
    font-family: var(--mlp-font, 'JetBrains Mono', 'Fira Code', monospace);
    overflow: hidden;
}
#mlp-ruby-overlay.mlp-rb-active { display: flex; }

/* Topbar */
#mlp-rb-topbar {
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
#mlp-rb-back {
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
#mlp-rb-back:hover { border-color: var(--mlp-accent, #ea580c); color: var(--mlp-accent, #ea580c); }
#mlp-rb-title {
    flex: 1;
    font-size: .83rem;
    font-weight: 700;
    color: var(--mlp-text, #f0f0f0);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
}
#mlp-rb-title span {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 2px 8px;
    background: rgba(220,38,38,.15);
    color: #f87171;
    border-radius: 4px;
    font-size: .62rem;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    margin-left: 8px;
}
.mlp-rb-btn {
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
.mlp-rb-btn:disabled { opacity: .5; cursor: not-allowed; }
#mlp-rb-run {
    background: linear-gradient(135deg, #dc2626, #b91c1c);
    color: #fff;
    border-color: transparent;
    box-shadow: 0 1px 6px rgba(220,38,38,.3);
}
#mlp-rb-run:hover:not(:disabled) { opacity: .88; }
#mlp-rb-save {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
}
#mlp-rb-save:hover:not(:disabled) { border-color: var(--mlp-accent, #ea580c); color: var(--mlp-accent, #ea580c); }
#mlp-rb-export {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
}
#mlp-rb-export:hover:not(:disabled) { border-color: #60a5fa; color: #60a5fa; }
#mlp-rb-fullscreen-btn {
    background: transparent;
    border-color: var(--mlp-border, #2a2a2a);
    color: var(--mlp-text-muted, #888);
    padding: 5px 9px;
}
#mlp-rb-fullscreen-btn:hover { border-color: #60a5fa; color: #60a5fa; }
#mlp-rb-chat-btn { display: none !important; }

/* ── Floating AI Chat Button (FAB) ─────────────────────────── */
#mlp-rb-chat-fab {
    position: fixed;
    bottom: 28px;
    right: 16px;
    z-index: 999993;
    height: 38px;
    padding: 0 14px 0 11px;
    border-radius: 8px;
    background: linear-gradient(135deg, #dc2626, #b91c1c);
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
    box-shadow: 0 4px 18px rgba(220,38,38,.45), 0 1px 4px rgba(0,0,0,.4);
    transition: opacity .18s, transform .18s, box-shadow .18s;
}
#mlp-rb-chat-fab:hover { opacity: .9; transform: translateY(-2px); box-shadow: 0 6px 22px rgba(220,38,38,.55); }
#mlp-rb-chat-fab.mlp-rb-fab-hidden { opacity: 0; pointer-events: none; transform: translateY(6px); }

/* Fullscreen */
#mlp-ruby-overlay.mlp-rb-fullscreen #mlp-rb-topbar,
#mlp-ruby-overlay.mlp-rb-fullscreen #mlp-rb-tabbar,
#mlp-ruby-overlay.mlp-rb-fullscreen #mlp-rb-statusbar { display: none !important; }
#mlp-ruby-overlay.mlp-rb-fullscreen #mlp-rb-output-wrap { display: none !important; }
#mlp-ruby-overlay.mlp-rb-fullscreen #mlp-rb-resizer { display: none !important; }

/* Tab bar */
#mlp-rb-tabbar {
    display: flex;
    align-items: center;
    padding: 0 14px;
    height: 36px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
    overflow-x: auto;
}
.mlp-rb-tab {
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
.mlp-rb-tab .mlp-rb-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.mlp-rb-tab.mlp-rb-tab-active { color: var(--mlp-text, #f0f0f0); border-bottom-color: #dc2626; }

/* Main split */
#mlp-rb-main {
    flex: 1;
    display: flex;
    flex-direction: row;
    overflow: hidden;
    min-height: 0;
}
#mlp-rb-editor-wrap {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    position: relative;
}
#mlp-rb-editor {
    flex: 1;
    min-height: 0;
    width: 100%;
}

/* Resize handle */
#mlp-rb-resizer {
    width: 5px;
    background: var(--mlp-border, #2a2a2a);
    cursor: col-resize;
    flex-shrink: 0;
    transition: background .15s;
    position: relative;
    z-index: 2;
}
#mlp-rb-resizer:hover,
#mlp-rb-resizer.mlp-rb-dragging { background: #dc2626; }

/* Output panel */
#mlp-rb-output-wrap {
    width: 38%;
    min-width: 220px;
    max-width: 70%;
    display: flex;
    flex-direction: column;
    background: #0a0a0a;
    border-left: 1px solid var(--mlp-border, #2a2a2a);
    overflow: hidden;
}
#mlp-rb-output-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 12px;
    height: 34px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-rb-output-title {
    flex: 1;
    font-size: .68rem;
    font-weight: 700;
    color: var(--mlp-text-muted, #888);
    text-transform: uppercase;
    letter-spacing: .07em;
}
#mlp-rb-clear-btn {
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
#mlp-rb-clear-btn:hover { color: #ef4444; background: rgba(239,68,68,.1); }
#mlp-rb-output {
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
#mlp-rb-output::-webkit-scrollbar { width: 5px; }
#mlp-rb-output::-webkit-scrollbar-thumb { background: var(--mlp-border, #2a2a2a); border-radius: 3px; }
.mlp-rb-out-line { display: block; padding: 0; }
.mlp-rb-out-err  { color: #f87171; }
.mlp-rb-out-info { color: #f87171; font-style: italic; font-size: .72rem; }
.mlp-rb-out-ok   { color: #34d399; font-size: .72rem; }

/* Status bar */
#mlp-rb-statusbar {
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
#mlp-rb-status-lang { display: inline-flex; align-items: center; gap: 4px; color: #f87171; font-weight: 600; }
#mlp-rb-status-msg  { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
#mlp-rb-status-pos  { white-space: nowrap; }
#mlp-rb-status-save { white-space: nowrap; font-style: italic; }

/* Toast */
#mlp-rb-toast {
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
#mlp-rb-toast.mlp-rb-show { opacity: 1; transform: translateY(0); }
#mlp-rb-toast.mlp-rb-err  { border-color: #f87171; }
#mlp-rb-toast.mlp-rb-succ { border-color: #34d399; }

/* Spinner */
@keyframes mlp-rb-spin { to { transform: rotate(360deg); } }
.mlp-rb-spinner {
    width: 12px;
    height: 12px;
    border: 2px solid rgba(255,255,255,.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: mlp-rb-spin .7s linear infinite;
    display: inline-block;
    flex-shrink: 0;
}

@media (max-width: 680px) {
    #mlp-rb-main { flex-direction: column; }
    #mlp-rb-output-wrap { width: 100%; max-width: 100%; min-width: 0; border-left: none; border-top: 1px solid var(--mlp-border, #2a2a2a); height: 38%; }
    #mlp-rb-resizer { display: none; }
}

/* ── Ruby AI Chat Sidebar ────────────────────────────────── */
#mlp-rb-chat-sidebar {
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
    box-shadow: -4px 8px 40px rgba(0,0,0,.55), 0 0 0 1px rgba(220,38,38,.12), -8px 0 40px rgba(220,38,38,0.12);
    overflow: hidden;
}
#mlp-rb-chat-sidebar.mlp-rb-chat-open { transform: translateX(0); }

#mlp-rb-chat-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    background: var(--mlp-surface, #161616);
    border-bottom: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-rb-chat-title {
    font-size: .83rem;
    font-weight: 700;
    color: var(--mlp-text, #f0f0f0);
}
#mlp-rb-chat-close {
    background: none;
    border: none;
    color: var(--mlp-text-muted, #888);
    cursor: pointer;
    padding: 4px;
    display: flex;
    align-items: center;
    transition: color .15s;
}
#mlp-rb-chat-close:hover { color: var(--mlp-text, #f0f0f0); }

#mlp-rb-chat-messages {
    flex: 1;
    overflow-y: auto;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.mlp-rb-chat-msg {
    padding: 8px 10px;
    border-radius: 6px;
    font-size: .75rem;
    line-height: 1.5;
    max-width: 95%;
    word-wrap: break-word;
}
.mlp-rb-chat-msg.user {
    background: #7f1d1d;
    color: #fecaca;
    align-self: flex-end;
    margin-left: auto;
}
.mlp-rb-chat-msg.assistant {
    background: #1f2937;
    color: #d4d4d4;
    align-self: flex-start;
}
.mlp-rb-chat-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--mlp-text-muted, #888);
    font-size: .73rem;
    text-align: center;
    padding: 20px;
}

#mlp-rb-chat-input-area {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px;
    background: var(--mlp-surface, #161616);
    border-top: 1px solid var(--mlp-border, #2a2a2a);
    flex-shrink: 0;
}
#mlp-rb-chat-input {
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
#mlp-rb-chat-input:focus { outline: none; border-color: #dc2626; }
#mlp-rb-chat-send {
    align-self: flex-end;
    padding: 5px 12px;
    background: #dc2626;
    color: #fff;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: .73rem;
    font-weight: 600;
    transition: opacity .15s;
}
#mlp-rb-chat-send:hover:not(:disabled) { opacity: .88; }
#mlp-rb-chat-send:disabled { opacity: .5; cursor: not-allowed; }

/* Markdown in chat */
.mlp-rb-chat-msg.assistant .mlp-rb-md-h2 {
    display: block; font-size: .85rem; font-weight: 700; color: #fca5a5;
    margin: 8px 0 3px; padding-bottom: 3px; border-bottom: 1px solid #3a2a2a;
}
.mlp-rb-chat-msg.assistant .mlp-rb-md-h3 {
    display: block; font-size: .78rem; font-weight: 700; color: #f87171; margin: 6px 0 2px;
}
.mlp-rb-chat-msg.assistant .mlp-rb-md-code {
    font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
    font-size: .72rem; background: rgba(0,0,0,.35); border: 1px solid #2a2a2a;
    border-radius: 3px; padding: 0 4px; color: #fbbf24;
}
.mlp-rb-chat-msg.assistant strong { color: #f0f0f0; font-weight: 700; }
.mlp-rb-chat-msg.assistant em { color: #d1d5db; font-style: italic; }

/* Code blocks in chat */
.mlp-rb-chat-code-wrap {
    margin: 6px 0 0; border-radius: 6px; overflow: hidden;
    border: 1px solid #2a2a2a; background: #0d0d0d; max-width: 100%;
}
.mlp-rb-chat-code-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 4px 10px; background: #1a1a1a; border-bottom: 1px solid #2a2a2a;
}
.mlp-rb-chat-code-lang {
    font-size: .62rem; font-weight: 700; color: #f87171;
    letter-spacing: .06em; text-transform: uppercase;
}
.mlp-rb-chat-code-actions { display: flex; gap: 5px; }
.mlp-rb-chat-code-apply,
.mlp-rb-chat-code-copy {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 4px; font-family: inherit;
    font-size: .65rem; font-weight: 700; cursor: pointer;
    border: 1px solid transparent; transition: opacity .15s, background .15s;
}
.mlp-rb-chat-code-apply { background: #dc2626; color: #fff; }
.mlp-rb-chat-code-apply:hover { opacity: .85; }
.mlp-rb-chat-code-apply.mlp-rb-applied { background: #1d4ed8; }
.mlp-rb-chat-code-copy { background: transparent; border-color: #3a3a3a; color: #888; }
.mlp-rb-chat-code-copy:hover { color: #d4d4d4; border-color: #555; }
.mlp-rb-chat-code-pre {
    margin: 0; padding: 10px 12px; overflow-x: auto;
    font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
    font-size: .73rem; line-height: 1.6; color: #d4d4d4; white-space: pre; background: transparent;
}
.mlp-rb-chat-undo-btn {
    display: inline-flex; align-items: center; gap: 4px; margin-top: 4px;
    padding: 2px 8px; background: transparent; border: 1px solid #3a3a3a;
    border-radius: 4px; color: #f59e0b; font-family: inherit;
    font-size: .65rem; font-weight: 700; cursor: pointer; transition: opacity .15s;
}
.mlp-rb-chat-undo-btn:hover { opacity: .8; }

/* Thinking animation */
.mlp-rb-thinking-bubble {
    display: flex; align-items: center; gap: 10px; padding: 10px 14px;
    background: #1f2937; border-radius: 6px; border: 1px solid rgba(248,113,113,.15);
    align-self: flex-start; max-width: 95%; box-shadow: 0 0 12px rgba(248,113,113,.07);
}
.mlp-rb-thinking-label { font-size: .68rem; color: #6b7280; font-style: italic; white-space: nowrap; }
@keyframes mlp-rb-dot-wave {
    0%, 100% { transform: translateY(0); opacity: .35; }
    50%       { transform: translateY(-6px); opacity: 1; }
}
@keyframes mlp-rb-dot-glow {
    0%, 100% { filter: drop-shadow(0 0 0px #f87171); }
    50%       { filter: drop-shadow(0 0 5px #f87171); }
}
.mlp-rb-think-dot {
    animation: mlp-rb-dot-wave 1.3s ease-in-out infinite,
               mlp-rb-dot-glow  1.3s ease-in-out infinite;
}
.mlp-rb-think-dot:nth-child(2) { animation-delay: .22s; }
.mlp-rb-think-dot:nth-child(3) { animation-delay: .44s; }
@keyframes mlp-rb-ring-pulse {
    0%, 100% { opacity: .18; r: 14; }
    50%       { opacity: .45; r: 16; }
}
.mlp-rb-think-ring { animation: mlp-rb-ring-pulse 1.3s ease-in-out infinite; transform-origin: center; }

#mlp-rb-chat-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,.3);
    z-index: 999990; opacity: 0; pointer-events: none;
    transition: opacity 0.25s cubic-bezier(0.4,0,0.2,1);
}
#mlp-rb-chat-overlay.mlp-rb-chat-open { opacity: 1; pointer-events: auto; }

/* Hide HTML/CSS/JS chat and Python chat in Ruby editor */
html.mlp-rb-editor-active #mlpChatToggle,
html.mlp-rb-editor-active #mlpChatSidebar,
html.mlp-rb-editor-active #mlp-py-chat-fab,
html.mlp-rb-editor-active #mlp-py-chat-sidebar,
html.mlp-rb-editor-active #mlp-py-chat-overlay { display: none !important; }
</style>
        <?php
    }

    public static function output_editor() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) {
            return;
        }
        ?>
<!-- Ruby Editor Overlay -->
<div id="mlp-ruby-overlay" role="dialog" aria-modal="true" aria-label="Ruby Editor">
  <div id="mlp-rb-topbar">
    <button id="mlp-rb-back" type="button" aria-label="Back to projects">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      Projects
    </button>
    <div id="mlp-rb-title">
      <span id="mlp-rb-name">Untitled.ruby</span>
      <span>Ruby</span>
    </div>
    <button id="mlp-rb-run" class="mlp-rb-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
      Run
    </button>
    <button id="mlp-rb-save" class="mlp-rb-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
      Save
    </button>
    <button id="mlp-rb-export" class="mlp-rb-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Export .ruby
    </button>
    <button id="mlp-rb-fullscreen-btn" class="mlp-rb-btn" type="button" title="Toggle fullscreen (Ctrl+Shift+F)">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
    </button>
    <button id="mlp-rb-chat-btn" class="mlp-rb-btn" type="button" style="display:none">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      Chat
    </button>
  </div>
  <div id="mlp-rb-tabbar">
    <button class="mlp-rb-tab mlp-rb-tab-active" data-tab="ruby" type="button">
      <span class="mlp-rb-dot" style="background:#dc2626;"></span>
      Ruby
    </button>
  </div>
  <div id="mlp-rb-main">
    <div id="mlp-rb-editor-wrap">
      <div id="mlp-rb-editor"></div>
    </div>
    <div id="mlp-rb-resizer" role="separator" aria-orientation="vertical" aria-label="Resize panels"></div>
    <div id="mlp-rb-output-wrap">
      <div id="mlp-rb-output-header">
        <div id="mlp-rb-output-title">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline;margin-right:4px;vertical-align:middle;"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          Output
        </div>
        <button id="mlp-rb-clear-btn" type="button" title="Clear output">Clear</button>
      </div>
      <div id="mlp-rb-output" aria-live="polite" aria-label="Ruby output"></div>
    </div>
  </div>
  <div id="mlp-rb-statusbar">
    <span id="mlp-rb-status-lang">
      <svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>
      Ruby
    </span>
    <span id="mlp-rb-status-msg"></span>
    <span id="mlp-rb-status-pos">Ln 1, Col 1</span>
    <span id="mlp-rb-status-save"></span>
  </div>
</div>

<!-- Ruby AI Chat Sidebar -->
<div id="mlp-rb-chat-overlay"></div>
<div id="mlp-rb-chat-sidebar">
  <div id="mlp-rb-chat-header">
    <div id="mlp-rb-chat-title">Ruby AI Chat</div>
    <button id="mlp-rb-chat-close" type="button" title="Close chat">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>
  <div id="mlp-rb-chat-messages">
    <div class="mlp-rb-chat-empty">Start a conversation with the Ruby AI assistant</div>
  </div>
  <div id="mlp-rb-chat-input-area">
    <textarea id="mlp-rb-chat-input" placeholder="Ask about your Ruby code..." rows="2"></textarea>
    <button id="mlp-rb-chat-send" type="button">Send</button>
  </div>
</div>

<!-- Toast -->
<div id="mlp-rb-toast"></div>

<!-- Floating AI Chat Button -->
<button id="mlp-rb-chat-fab" class="mlp-rb-fab-hidden" type="button" title="Open Ruby AI Chat" aria-label="Open Ruby AI Chat">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
  AI Chat
</button>

<script>
(function(){
'use strict';

/* ── Config ─────────────────────────────────────────────────── */
var MLP_RB_LS       = 'mlp_projects';
var MLP_TS_SITEKEY  = <?php echo json_encode( defined( 'MLP_TURNSTILE_SITE_KEY' ) ? MLP_TURNSTILE_SITE_KEY : '' ); ?>;

var MLP_RB_DEFAULT_CODE = [
    '# Welcome to Ruby! ',
    '# Press Run (or Ctrl+Enter) to execute.',
    '',
    'def greet(name)',
    '  "Hello, #{name}!"',
    'end',
    '',
    'puts greet("World")',
    '',
    '# Try some Ruby features:',
    'numbers = [1, 2, 3, 4, 5]',
    'puts "Sum: #{numbers.sum}"',
    'puts "Evens: #{numbers.select(&:even?).inspect}"',
    '',
    '# New code: filter out odd numbers and double the remaining numbers',
    'def double_evens(numbers)',
    '  numbers.select(&:even?).map { |n| n * 2 }',
    'end',
    '',
    'doubled_evens = double_evens(numbers)',
    'puts "Doubled Evens: #{doubled_evens.inspect}"',
    '',
    '# Another example: use **pattern matching** to categorize numbers',
    'def categorize_number(num)',
    '  case num',
    '  when 0..2 then "Small"',
    '  when 3..5 then "Medium"',
    '  else "Large"',
    '  end',
    'end',
    '',
    'categorized_numbers = numbers.map { |n| categorize_number(n) }',
    'puts "Categorized Numbers: #{categorized_numbers.inspect}"',
].join("\n");

/* ── State ───────────────────────────────────────────────────── */
var rbEditor   = null;
var monacoReady = false;
var running    = false;
var _activeId  = null;
var _unsaved   = false;

/* ── Ruby Chat State ─────────────────────────────────────────── */
var _rbChatHistories = {};
var _rbChatBusy = false;
var _rbTsToken = '';
var _rbTsVerified = false;
var _rbTsPending = '';
var _rbTsWidgetId  = null;
var _rbTsWidgetEl  = null;
var _rbUndoStack   = [];

/* ── Helpers ─────────────────────────────────────────────────── */
function $id(id) { return document.getElementById(id); }

function getProject(id) {
    try {
        var list = JSON.parse(localStorage.getItem(MLP_RB_LS)) || [];
        return list.find(function(p){ return p.id === id; }) || null;
    } catch(e){ return null; }
}

function updateProject(id, data) {
    try {
        var list = JSON.parse(localStorage.getItem(MLP_RB_LS)) || [];
        var idx  = list.findIndex(function(p){ return p.id === id; });
        if (idx < 0) return;
        Object.assign(list[idx], data);
        localStorage.setItem(MLP_RB_LS, JSON.stringify(list));
    } catch(e){}
}

function setSave(msg) {
    var el = $id('mlp-rb-status-save');
    if (el) el.textContent = msg;
}

function setStatus(msg) {
    var el = $id('mlp-rb-status-msg');
    if (el) el.textContent = msg;
}

function clearOutput() {
    var el = $id('mlp-rb-output');
    if (el) el.innerHTML = '';
}

function appendOutput(text, cls) {
    var el = $id('mlp-rb-output');
    if (!el) return;
    var line = document.createElement('span');
    line.className = 'mlp-rb-out-line' + (cls ? ' ' + cls : '');
    line.textContent = text;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
}

function rbToast(msg, type, dur) {
    var el = $id('mlp-rb-toast');
    if (!el) return;
    el.textContent = msg;
    el.className = 'mlp-rb-show' + (type === 'err' ? ' mlp-rb-err' : type === 'succ' ? ' mlp-rb-succ' : '');
    clearTimeout(el._rbTimer);
    el._rbTimer = setTimeout(function(){
        el.className = '';
    }, dur || 2500);
}

/* ── Run (iframe sandbox with Opal.js) ───────────────────────── */
function runCode() {
    if (running) return;
    var code = rbEditor ? rbEditor.getValue() : '';
    if (!code.trim()) {
        appendOutput('# Nothing to run.', 'mlp-rb-out-info');
        return;
    }
    running = true;
    setRunBtnState(true);
    clearOutput();
    appendOutput('# Loading Ruby runtime…', 'mlp-rb-out-info');
    setStatus('Running…');

    /* Build a sandboxed iframe that loads Opal and runs the code */
    var msgId = 'mlprb_' + Date.now() + '_' + Math.random().toString(36).slice(2);
    var iframe = document.createElement('iframe');
    iframe.style.cssText = 'position:absolute;width:0;height:0;border:0;left:-9999px;top:-9999px;';
    iframe.setAttribute('sandbox', 'allow-scripts');
    document.body.appendChild(iframe);

    /* Safety timeout — 15 s */
    var killed = false;
    var timer = setTimeout(function() {
        killed = true;
        window.removeEventListener('message', handler);
        try { document.body.removeChild(iframe); } catch(x){}
        clearOutput();
        appendOutput('Error: Execution timed out (15s)', 'mlp-rb-out-err');
        setStatus('Timeout');
        running = false;
        setRunBtnState(false);
    }, 15000);

    function handler(e) {
        var d = e.data;
        if (!d || d._mlpId !== msgId) return;
        if (killed) return;
        clearTimeout(timer);
        window.removeEventListener('message', handler);
        try { document.body.removeChild(iframe); } catch(x){}
        clearOutput();
        if (d.type === 'out') {
            if (d.stdout) appendOutput(d.stdout, '');
            if (d.stderr) appendOutput(d.stderr, 'mlp-rb-out-err');
            if (!d.stdout && !d.stderr) appendOutput('(no output)', 'mlp-rb-out-info');
            appendOutput('\n✓ Done in ' + d.ms + 'ms', 'mlp-rb-out-ok');
            setStatus('Ran successfully (' + d.ms + 'ms)');
        } else {
            appendOutput(d.text || 'RuntimeError', 'mlp-rb-out-err');
            setStatus('Error');
        }
        running = false;
        setRunBtnState(false);
    }
    window.addEventListener('message', handler);

    /* Build the iframe HTML — captures puts/print/p via console.log override */
    var encodedCode = JSON.stringify(code);
    var encodedId   = JSON.stringify(msgId);
    var iframeHtml = '<!DOCTYPE html><html><head>' +
        '<script src="https://cdn.opalrb.com/opal/1.8.2/opal.min.js"><\/script>' +
        '<script src="https://cdn.opalrb.com/opal/1.8.2/opal-parser.min.js"><\/script>' +
        '<\/head><body><script>' +
        '(function(){' +
        'var ID=' + encodedId + ';' +
        'var t0=Date.now();' +
        /* Opal puts/print call console.log in the browser — capture it */
        'var _lines=[];' +
        'var _origLog=console.log;' +
        'console.log=function(){' +
        '  _lines.push(Array.prototype.slice.call(arguments).join(" "));' +
        '};' +
        'window.onerror=function(msg,src,line){' +
        '  console.log=_origLog;' +
        '  parent.postMessage({_mlpId:ID,type:"err",text:msg+(line?" (line "+line+")":"")}, "*");' +
        '  return true;' +
        '};' +
        'function run(){' +
        '  try{' +
        '    Opal.require("opal-parser");' +
        '    Opal.eval(' + encodedCode + ');' +
        '    console.log=_origLog;' +
        '    parent.postMessage({_mlpId:ID,type:"out",' +
        '      stdout:_lines.join("\\n"),' +
        '      stderr:"",' +
        '      ms:Date.now()-t0' +
        '    },"*");' +
        '  }catch(e){' +
        '    console.log=_origLog;' +
        '    var msg=(e&&e.message)?e.message:String(e);' +
        '    msg=msg.replace(/\\$opal/g,"").replace(/Opal\\./g,"");' +
        '    parent.postMessage({_mlpId:ID,type:"err",text:msg},"*");' +
        '  }' +
        '}' +
        'if(document.readyState==="complete"){run();}else{window.addEventListener("load",run);}' +
        '})();' +
        '<\/script><\/body><\/html>';

    iframe.srcdoc = iframeHtml;
}

function setRunBtnState(isRunning) {
    var btn = $id('mlp-rb-run');
    if (!btn) return;
    if (isRunning) {
        btn.innerHTML = '<span class="mlp-rb-spinner"></span> Running…';
        btn.disabled = true;
    } else {
        btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run';
        btn.disabled = false;
    }
}

/* ── Save ────────────────────────────────────────────────────── */
function saveProject() {
    if (!_activeId) return;
    var code = rbEditor ? rbEditor.getValue() : '';
    var now  = Date.now();
    updateProject(_activeId, {
        ruby:    code,
        type:    'ruby',
        updated: now,
    });
    _unsaved = false;
    var d = new Date(now);
    setSave('Saved ' + d.toLocaleTimeString());
    rbToast('Project saved', 'succ', 1800);
}

/* ── Export ──────────────────────────────────────────────────── */
function exportProject() {
    var code = rbEditor ? rbEditor.getValue() : '';
    var p    = _activeId ? getProject(_activeId) : null;
    var name = (p && p.name) ? p.name.replace(/[^a-z0-9_\-]/gi, '_') : 'ruby_project';
    var blob = new Blob([code], { type: 'text/x-ruby' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a');
    a.href   = url;
    a.download = name + '.ruby';
    document.body.appendChild(a);
    a.click();
    setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(url); }, 500);
    rbToast('Exported ' + name + '.ruby', 'succ', 2200);
}

/* ── Open / Close overlay ────────────────────────────────────── */
function openRubyEditor(projectId) {
    var p = getProject(projectId);
    if (!p || p.type !== 'ruby') return;
    _activeId = projectId;
    _unsaved  = false;

    var nameEl = $id('mlp-rb-name');
    if (nameEl) nameEl.textContent = (p.name || 'Untitled') + '.ruby';

    var overlay = $id('mlp-ruby-overlay');
    if (overlay) overlay.classList.add('mlp-rb-active');

    document.documentElement.classList.add('mlp-rb-editor-active');

    setSave('');
    setStatus('Ready');
    clearOutput();
    appendOutput('# Press Run (▶) or Ctrl+Enter to execute your Ruby code.', 'mlp-rb-out-info');

    var initialCode = p.ruby || MLP_RB_DEFAULT_CODE;
    if (monacoReady && window.monaco) {
        if (!rbEditor) {
            mountMonaco(initialCode);
        } else {
            rbEditor.setValue(initialCode);
            rbEditor.setScrollPosition({ scrollTop: 0 });
        }
    } else {
        waitForMonacoThenMount(initialCode);
    }

    /* Wire chat listeners */
    var chatClose   = $id('mlp-rb-chat-close');
    var chatSend    = $id('mlp-rb-chat-send');
    var chatInput   = $id('mlp-rb-chat-input');
    var chatOverlay = $id('mlp-rb-chat-overlay');
    var chatFab     = $id('mlp-rb-chat-fab');

    if (chatFab) {
        chatFab.classList.remove('mlp-rb-fab-hidden');
        if (!chatFab._mlpWired) {
            chatFab.addEventListener('click', _openRbChat);
            chatFab._mlpWired = true;
        }
    }
    if (chatClose)   chatClose.addEventListener('click', _closeRbChat);
    if (chatSend)    chatSend.addEventListener('click',  _sendRbChat);
    if (chatOverlay) chatOverlay.addEventListener('click', _closeRbChat);
    if (chatInput) {
        chatInput.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                _sendRbChat();
            }
        });
    }
}

function closeRubyEditor() {
    if (_unsaved) {
        if (!confirm('You have unsaved changes. Leave without saving?')) return;
    }
    var overlay = $id('mlp-ruby-overlay');
    if (overlay) overlay.classList.remove('mlp-rb-active');

    _closeRbChat();
    var chatFab = $id('mlp-rb-chat-fab');
    if (chatFab) { chatFab.classList.add('mlp-rb-fab-hidden'); }

    document.documentElement.classList.remove('mlp-rb-editor-active');

    _activeId = null;
    running   = false;

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
    var container = $id('mlp-rb-editor');
    if (!container) return;
    if (rbEditor) { rbEditor.setValue(initialCode); return; }
    rbEditor = window.monaco.editor.create(container, {
        value:     initialCode,
        language:  'ruby',
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
        parameterHints: { enabled: true },
        bracketPairColorization: { enabled: true },
        padding: { top: 10, bottom: 10 },
    });
    rbEditor.onDidChangeCursorPosition(function(e) {
        var el = $id('mlp-rb-status-pos');
        if (el) el.textContent = 'Ln ' + e.position.lineNumber + ', Col ' + e.position.column;
    });
    rbEditor.onDidChangeModelContent(function() {
        _unsaved = true;
        setSave('● Unsaved');
    });
    rbEditor.addCommand(
        window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.Enter, runCode
    );
    rbEditor.addCommand(
        window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.KeyS,
        function(){ saveProject(); }
    );
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
    var resizer = $id('mlp-rb-resizer');
    var main    = $id('mlp-rb-main');
    var outWrap = $id('mlp-rb-output-wrap');
    if (!resizer || !main || !outWrap) return;
    var dragging = false, startX = 0, startW = 0;
    resizer.addEventListener('mousedown', function(e) {
        dragging = true; startX = e.clientX;
        startW = outWrap.getBoundingClientRect().width;
        resizer.classList.add('mlp-rb-dragging');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault();
    });
    document.addEventListener('mousemove', function(e) {
        if (!dragging) return;
        var dx   = startX - e.clientX;
        var mainW = main.getBoundingClientRect().width;
        var newW  = Math.max(220, Math.min(mainW * 0.70, startW + dx));
        outWrap.style.width = newW + 'px';
    });
    document.addEventListener('mouseup', function() {
        if (!dragging) return;
        dragging = false;
        resizer.classList.remove('mlp-rb-dragging');
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        if (rbEditor) rbEditor.layout();
    });
})();

/* ── Fullscreen ──────────────────────────────────────────────── */
function toggleFullscreen() {
    var overlay = $id('mlp-ruby-overlay');
    if (!overlay) return;
    var isFs = overlay.classList.toggle('mlp-rb-fullscreen');
    var btn = $id('mlp-rb-fullscreen-btn');
    if (btn) {
        btn.title = isFs ? 'Exit fullscreen (Ctrl+Shift+F)' : 'Toggle fullscreen (Ctrl+Shift+F)';
        btn.innerHTML = isFs
            ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="10" y1="14" x2="3" y2="21"/><line x1="21" y1="3" x2="14" y2="10"/></svg>'
            : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>';
    }
    if (rbEditor) setTimeout(function(){ rbEditor.layout(); }, 50);
}

/* ── Ruby Chat System ────────────────────────────────────────── */
function _getRbChatKey(projectId) { return 'mlp_rb_chat_' + (projectId || 'default'); }

function _getRbChatHistory(key) {
    if (!_rbChatHistories[key]) {
        try { _rbChatHistories[key] = JSON.parse(localStorage.getItem(key)) || []; }
        catch(e) { _rbChatHistories[key] = []; }
    }
    return _rbChatHistories[key];
}

function _saveRbChatHistory(key, history) {
    _rbChatHistories[key] = history;
    try { localStorage.setItem(key, JSON.stringify(history)); } catch(e) {}
}

function _openRbChat() {
    var sidebar = $id('mlp-rb-chat-sidebar');
    var overlay = $id('mlp-rb-chat-overlay');
    var fab     = $id('mlp-rb-chat-fab');
    if (sidebar) sidebar.classList.add('mlp-rb-chat-open');
    if (overlay) overlay.classList.add('mlp-rb-chat-open');
    if (fab)     fab.classList.add('mlp-rb-fab-hidden');
    var input = $id('mlp-rb-chat-input');
    if (input) setTimeout(function() { input.focus(); }, 100);
}

function _closeRbChat() {
    var sidebar = $id('mlp-rb-chat-sidebar');
    var overlay = $id('mlp-rb-chat-overlay');
    var fab     = $id('mlp-rb-chat-fab');
    if (sidebar) sidebar.classList.remove('mlp-rb-chat-open');
    if (overlay) overlay.classList.remove('mlp-rb-chat-open');
    if (fab)     fab.classList.remove('mlp-rb-fab-hidden');
}

function _applyCodeToRbEditor(code, applyBtn) {
    if (!rbEditor) return;
    var prev = rbEditor.getValue();
    _rbUndoStack.push(prev);
    rbEditor.setValue(code);
    rbEditor.setScrollPosition({ scrollTop: 0 });
    _unsaved = true;
    setSave('● Unsaved');
    if (applyBtn) {
        applyBtn.textContent = '✓ Applied';
        applyBtn.classList.add('mlp-rb-applied');
    }
    if (applyBtn && applyBtn.parentNode && !applyBtn.parentNode.querySelector('.mlp-rb-chat-undo-btn')) {
        var undoBtn = document.createElement('button');
        undoBtn.className = 'mlp-rb-chat-undo-btn';
        undoBtn.type = 'button';
        undoBtn.innerHTML = '↩ Undo';
        undoBtn.addEventListener('click', function() {
            var prev2 = _rbUndoStack.pop();
            if (prev2 !== undefined) {
                rbEditor.setValue(prev2);
                rbEditor.setScrollPosition({ scrollTop: 0 });
                _unsaved = true;
                setSave('● Unsaved');
            }
            if (applyBtn) { applyBtn.textContent = '▶ Apply'; applyBtn.classList.remove('mlp-rb-applied'); }
            undoBtn.parentNode && undoBtn.parentNode.removeChild(undoBtn);
        });
        applyBtn.parentNode.appendChild(undoBtn);
    }
}

function _buildRbCodeBlock(lang, code) {
    var wrap   = document.createElement('div');
    wrap.className = 'mlp-rb-chat-code-wrap';
    var header = document.createElement('div');
    header.className = 'mlp-rb-chat-code-header';
    var langLabel = document.createElement('span');
    langLabel.className = 'mlp-rb-chat-code-lang';
    langLabel.textContent = lang || 'ruby';
    var actions = document.createElement('div');
    actions.className = 'mlp-rb-chat-code-actions';
    var copyBtn = document.createElement('button');
    copyBtn.className = 'mlp-rb-chat-code-copy';
    copyBtn.type = 'button';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', function() {
        navigator.clipboard && navigator.clipboard.writeText(code).then(function() {
            copyBtn.textContent = '✓ Copied';
            setTimeout(function() { copyBtn.textContent = 'Copy'; }, 1800);
        });
    });
    var applyBtn = document.createElement('button');
    applyBtn.className = 'mlp-rb-chat-code-apply';
    applyBtn.type = 'button';
    applyBtn.textContent = '▶ Apply';
    applyBtn.addEventListener('click', function() { _applyCodeToRbEditor(code, applyBtn); });
    actions.appendChild(copyBtn);
    actions.appendChild(applyBtn);
    header.appendChild(langLabel);
    header.appendChild(actions);
    var pre = document.createElement('pre');
    pre.className = 'mlp-rb-chat-code-pre';
    pre.textContent = code;
    wrap.appendChild(header);
    wrap.appendChild(pre);
    return wrap;
}

var _rbThinkingEl = null;
function _showRbThinking() {
    _hideRbThinking();
    var msgs = $id('mlp-rb-chat-messages');
    if (!msgs) return;
    var empty = msgs.querySelector('.mlp-rb-chat-empty');
    if (empty) msgs.innerHTML = '';
    var bubble = document.createElement('div');
    bubble.className = 'mlp-rb-thinking-bubble';
    bubble.innerHTML = [
        '<svg width="38" height="16" viewBox="0 0 38 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">',
          '<defs><radialGradient id="mlp-rbg1" cx="50%" cy="50%" r="50%">',
            '<stop offset="0%" stop-color="#fca5a5"/>',
            '<stop offset="100%" stop-color="#dc2626"/>',
          '</radialGradient></defs>',
          '<circle class="mlp-rb-think-ring" cx="7" cy="8" r="14" fill="#dc2626"/>',
          '<circle class="mlp-rb-think-dot" cx="7"  cy="8" r="3.5" fill="url(#mlp-rbg1)"/>',
          '<circle class="mlp-rb-think-dot" cx="19" cy="8" r="3.5" fill="url(#mlp-rbg1)"/>',
          '<circle class="mlp-rb-think-dot" cx="31" cy="8" r="3.5" fill="url(#mlp-rbg1)"/>',
        '</svg>',
        '<span class="mlp-rb-thinking-label">AI is thinking…</span>'
    ].join('');
    msgs.appendChild(bubble);
    msgs.scrollTop = msgs.scrollHeight;
    _rbThinkingEl = bubble;
}
function _hideRbThinking() {
    if (_rbThinkingEl && _rbThinkingEl.parentNode) _rbThinkingEl.parentNode.removeChild(_rbThinkingEl);
    _rbThinkingEl = null;
}

function _renderRbMarkdownInline(text) {
    var frag = document.createDocumentFragment();
    var re = /(`[^`]+`|\*\*[\s\S]+?\*\*|\*[^*\n]+?\*)/g;
    var last = 0, m;
    while ((m = re.exec(text)) !== null) {
        if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        var token = m[0];
        if (token.startsWith('**')) {
            var strong = document.createElement('strong');
            strong.textContent = token.slice(2, -2);
            frag.appendChild(strong);
        } else if (token.startsWith('`')) {
            var code = document.createElement('code');
            code.className = 'mlp-rb-md-code';
            code.textContent = token.slice(1, -1);
            frag.appendChild(code);
        } else {
            var em = document.createElement('em');
            em.textContent = token.slice(1, -1);
            frag.appendChild(em);
        }
        last = m.index + token.length;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    return frag;
}

function _appendRbChatMsg(role, text) {
    var msgs = $id('mlp-rb-chat-messages');
    if (!msgs) return;
    var empty = msgs.querySelector('.mlp-rb-chat-empty');
    if (empty) msgs.innerHTML = '';
    var bubble = document.createElement('div');
    bubble.className = 'mlp-rb-chat-msg ' + role;
    if (role === 'assistant') {
        var parts = text.split(/(```[\w]*\n[\s\S]*?```)/g);
        parts.forEach(function(part) {
            var fenced = part.match(/^```([\w]*)\n([\s\S]*?)```$/);
            if (fenced) {
                var lang = fenced[1] || 'ruby';
                var code = fenced[2].replace(/\n$/, '');
                bubble.appendChild(_buildRbCodeBlock(lang, code));
            } else if (part.trim()) {
                var lines = part.split('\n');
                lines.forEach(function(line, i) {
                    if (/^### /.test(line)) {
                        var h = document.createElement('span'); h.className = 'mlp-rb-md-h3';
                        h.appendChild(_renderRbMarkdownInline(line.slice(4))); bubble.appendChild(h);
                    } else if (/^## /.test(line)) {
                        var h = document.createElement('span'); h.className = 'mlp-rb-md-h2';
                        h.appendChild(_renderRbMarkdownInline(line.slice(3))); bubble.appendChild(h);
                    } else if (/^# /.test(line)) {
                        var h = document.createElement('span'); h.className = 'mlp-rb-md-h2';
                        h.appendChild(_renderRbMarkdownInline(line.slice(2))); bubble.appendChild(h);
                    } else if (line) {
                        var span = document.createElement('span');
                        span.appendChild(_renderRbMarkdownInline(line)); bubble.appendChild(span);
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

function _renderRbTurnstile() {
    if (!MLP_TS_SITEKEY) { _rbTsVerified = true; _sendRbChat(); return; }
    var msgs = $id('mlp-rb-chat-messages');
    if (!msgs) return;
    _rbTsWidgetEl = document.createElement('div');
    _rbTsWidgetEl.style.cssText = 'margin:8px 0;';
    msgs.appendChild(_rbTsWidgetEl);
    msgs.scrollTop = msgs.scrollHeight;
    function doRender() {
        if (window.turnstile) {
            _rbTsWidgetId = turnstile.render(_rbTsWidgetEl, {
                sitekey: MLP_TS_SITEKEY,
                theme: 'dark',
                size: 'compact',
                callback: function(token) {
                    _rbTsToken = token;
                    _rbTsVerified = true;
                    _sendRbChat();
                },
            });
        } else {
            setTimeout(doRender, 300);
        }
    }
    doRender();
}

function _sendRbChat() {
    if (_rbChatBusy) return;
    var input = $id('mlp-rb-chat-input');
    var text = _rbTsPending || (input && input.value.trim());
    if (!text) return;
    _rbTsPending = '';
    if (input) input.value = '';

    if (!_rbTsVerified) {
        _rbTsPending = text;
        _appendRbChatMsg('user', text);
        _appendRbChatMsg('assistant', 'Please complete the verification to continue.');
        _renderRbTurnstile();
        return;
    }

    var chatKey = _getRbChatKey(_activeId);
    var history = _getRbChatHistory(chatKey);
    history.push({ role: 'user', content: text });
    _appendRbChatMsg('user', text);
    _showRbThinking();
    _rbChatBusy = true;

    var sendBtn = $id('mlp-rb-chat-send');
    if (sendBtn) sendBtn.disabled = true;

    var rubyCode = rbEditor ? rbEditor.getValue() : '';
    var formData = new FormData();
    formData.append('action',      'mlp_ai_chat_ruby');
    formData.append('nonce',       (window.mlp_ajax && window.mlp_ajax.nonce) ? window.mlp_ajax.nonce : '');
    formData.append('message',     text);
    formData.append('ruby_code',   rubyCode);
    formData.append('history',     JSON.stringify(history.slice(-10)));
    formData.append('turnstile_token', _rbTsToken || '');

    fetch((window.mlp_ajax && window.mlp_ajax.ajaxurl) ? window.mlp_ajax.ajaxurl : '/wp-admin/admin-ajax.php', {
        method: 'POST',
        body: formData,
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        _hideRbThinking();
        if (data && data.success && data.data && data.data.reply) {
            var reply = data.data.reply;
            history.push({ role: 'assistant', content: reply });
            _saveRbChatHistory(chatKey, history);
            _appendRbChatMsg('assistant', reply);
        } else {
            var errMsg = (data && data.data && data.data.message) ? data.data.message : 'AI request failed. Please try again.';
            _appendRbChatMsg('assistant', '⚠ ' + errMsg);
        }
    })
    .catch(function(err) {
        _hideRbThinking();
        _appendRbChatMsg('assistant', '⚠ Network error. Please check your connection.');
    })
    .finally(function() {
        _rbChatBusy = false;
        if (sendBtn) sendBtn.disabled = false;
    });
}

/* ── Wire buttons ────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
    var runBtn    = $id('mlp-rb-run');
    var saveBtn   = $id('mlp-rb-save');
    var exportBtn = $id('mlp-rb-export');
    var fsBtn     = $id('mlp-rb-fullscreen-btn');
    var backBtn   = $id('mlp-rb-back');
    var clearBtn  = $id('mlp-rb-clear-btn');

    if (runBtn)    runBtn.addEventListener('click',    runCode);
    if (saveBtn)   saveBtn.addEventListener('click',   saveProject);
    if (exportBtn) exportBtn.addEventListener('click', exportProject);
    if (backBtn)   backBtn.addEventListener('click',   closeRubyEditor);
    if (clearBtn)  clearBtn.addEventListener('click',  clearOutput);
    if (fsBtn)     fsBtn.addEventListener('click',     toggleFullscreen);

    document.addEventListener('keydown', function(e) {
        var overlay = $id('mlp-ruby-overlay');
        if (!overlay || !overlay.classList.contains('mlp-rb-active')) return;
        if (e.key === 'Escape') {
            e.preventDefault();
            if (overlay.classList.contains('mlp-rb-fullscreen')) {
                toggleFullscreen();
            } else {
                closeRubyEditor();
            }
        }
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'F' || e.key === 'f')) {
            e.preventDefault();
            toggleFullscreen();
        }
    });
});

/* ── Public API ──────────────────────────────────────────────── */
window.mlpOpenRubyEditor  = openRubyEditor;
window.mlpCloseRubyEditor = closeRubyEditor;

/* ── Hook into projects overlay open action ──────────────────── */
(function hookProjectOpen() {
    var tries = 0;
    var t = setInterval(function() {
        if (typeof window.mlpOpenProjectInEditor === 'function' && !window._mlpRbHooked) {
            var _orig = window.mlpOpenProjectInEditor;
            window.mlpOpenProjectInEditor = function(p) {
                if (p && p.type === 'ruby') {
                    var projOverlay = document.getElementById('mlp-projects-overlay');
                    if (projOverlay) projOverlay.style.display = 'none';
                    openRubyEditor(p.id);
                } else {
                    _orig(p);
                }
            };
            window._mlpRbHooked = true;
            clearInterval(t);
        }
        if (++tries > 100) clearInterval(t);
    }, 150);
})();

})();
</script>
        <?php
    }
}
