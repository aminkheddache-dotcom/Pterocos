<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class MLP_SQL {
    public static function init() {
        add_action( 'wp_head',   [ __CLASS__, 'output_styles' ], 99 );
        add_action( 'wp_footer', [ __CLASS__, 'output_editor' ],  6 );
    }

    public static function output_styles() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) return;
        ?>
<style id="mlp-sql-styles">
/* ── SQL Editor Overlay ──────────────────────────────────────── */
:root {
    --sq-bg:        #07101e;
    --sq-surface:   #0c1929;
    --sq-surface2:  #102240;
    --sq-border:    #1b3a5e;
    --sq-accent:    #0ea5e9;
    --sq-accent2:   #38bdf8;
    --sq-text:      #dde8f5;
    --sq-muted:     #5b7fa6;
    --sq-success:   #22c55e;
    --sq-error:     #f87171;
    --sq-warn:      #fbbf24;
    --sq-font:      'JetBrains Mono','Fira Code','Consolas',monospace;
}
#mlp-sql-overlay {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 99999;
    background: var(--sq-bg);
    flex-direction: column;
    font-family: var(--sq-font);
    overflow: hidden;
}
#mlp-sql-overlay.mlp-sq-active { display: flex; }

/* Topbar */
#mlp-sq-topbar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 14px;
    height: 46px;
    background: var(--sq-surface);
    border-bottom: 1px solid var(--sq-border);
    flex-shrink: 0;
    overflow-x: auto;
    overflow-y: hidden;
}
#mlp-sq-back {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 11px;
    background: transparent;
    border: 1px solid var(--sq-border);
    border-radius: 6px;
    color: var(--sq-muted);
    font-size: .75rem;
    font-weight: 600;
    cursor: pointer;
    font-family: inherit;
    transition: border-color .15s, color .15s;
    white-space: nowrap;
    flex-shrink: 0;
}
#mlp-sq-back:hover { border-color: var(--sq-accent); color: var(--sq-accent); }
#mlp-sq-title {
    flex: 1;
    font-size: .83rem;
    font-weight: 700;
    color: var(--sq-text);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
}
#mlp-sq-title span {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    background: rgba(14,165,233,.15);
    color: var(--sq-accent2);
    border-radius: 4px;
    font-size: .62rem;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    margin-left: 8px;
}
.mlp-sq-btn {
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
.mlp-sq-btn:disabled { opacity: .45; cursor: not-allowed; }
#mlp-sq-run {
    background: linear-gradient(135deg, #0284c7, #0369a1);
    color: #fff;
    box-shadow: 0 1px 8px rgba(2,132,199,.35);
}
#mlp-sq-run:hover:not(:disabled) { opacity: .88; }
#mlp-sq-save, #mlp-sq-export, #mlp-sq-clear-db, #mlp-sq-fs-btn {
    background: transparent;
    border-color: var(--sq-border);
    color: var(--sq-muted);
}
#mlp-sq-save:hover:not(:disabled)     { border-color: var(--sq-accent); color: var(--sq-accent); }
#mlp-sq-export:hover:not(:disabled)   { border-color: var(--sq-accent2); color: var(--sq-accent2); }
#mlp-sq-clear-db:hover:not(:disabled) { border-color: var(--sq-error); color: var(--sq-error); }
#mlp-sq-fs-btn:hover { border-color: var(--sq-accent); color: var(--sq-accent); }
#mlp-sq-fs-btn { padding: 5px 9px; }

/* Floating AI Chat FAB */
#mlp-sq-chat-fab {
    position: fixed;
    bottom: 28px;
    right: 16px;
    z-index: 999993;
    height: 38px;
    padding: 0 14px 0 11px;
    border-radius: 8px;
    background: linear-gradient(135deg, #0284c7, #0369a1);
    border: none;
    color: #fff;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-family: var(--sq-font);
    font-size: .75rem;
    font-weight: 700;
    letter-spacing: .02em;
    white-space: nowrap;
    box-shadow: 0 4px 18px rgba(2,132,199,.45), 0 1px 4px rgba(0,0,0,.4);
    transition: opacity .18s, transform .18s;
}
#mlp-sq-chat-fab:hover { opacity: .9; transform: translateY(-2px); }
#mlp-sq-chat-fab.mlp-sq-fab-hidden { opacity: 0; pointer-events: none; transform: translateY(6px); }

/* Fullscreen */
#mlp-sql-overlay.mlp-sq-fullscreen #mlp-sq-topbar,
#mlp-sql-overlay.mlp-sq-fullscreen #mlp-sq-statusbar { display: none !important; }
#mlp-sql-overlay.mlp-sq-fullscreen #mlp-sq-results-pane { display: none !important; }
#mlp-sql-overlay.mlp-sq-fullscreen #mlp-sq-h-resizer { display: none !important; }

/* ── Main body ───────────────────────────────────────────────── */
#mlp-sq-body {
    flex: 1;
    display: flex;
    flex-direction: row;
    overflow: hidden;
    min-height: 0;
}

/* Schema sidebar */
#mlp-sq-schema {
    width: 200px;
    min-width: 140px;
    max-width: 320px;
    display: flex;
    flex-direction: column;
    background: var(--sq-surface);
    border-right: 1px solid var(--sq-border);
    overflow: hidden;
    flex-shrink: 0;
}
#mlp-sq-schema-header {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 0 10px;
    height: 32px;
    background: var(--sq-surface2);
    border-bottom: 1px solid var(--sq-border);
    flex-shrink: 0;
    font-size: .65rem;
    font-weight: 700;
    color: var(--sq-muted);
    text-transform: uppercase;
    letter-spacing: .08em;
}
#mlp-sq-schema-tree {
    flex: 1;
    overflow-y: auto;
    padding: 6px 0;
}
#mlp-sq-schema-tree::-webkit-scrollbar { width: 4px; }
#mlp-sq-schema-tree::-webkit-scrollbar-thumb { background: var(--sq-border); border-radius: 2px; }
.sq-tree-empty {
    padding: 10px 12px;
    font-size: .7rem;
    color: var(--sq-muted);
    font-style: italic;
}
.sq-tree-table {
    margin-bottom: 2px;
}
.sq-tree-table-header {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 4px 10px;
    font-size: .72rem;
    font-weight: 700;
    color: var(--sq-accent2);
    cursor: pointer;
    user-select: none;
    transition: background .1s;
    border-radius: 3px;
    margin: 0 4px;
}
.sq-tree-table-header:hover { background: rgba(14,165,233,.1); }
.sq-tree-table-chevron {
    font-style: normal;
    font-size: .65rem;
    color: var(--sq-muted);
    transition: transform .15s;
    line-height: 1;
}
.sq-tree-table-header.sq-open .sq-tree-table-chevron { transform: rotate(90deg); }
.sq-tree-cols {
    display: none;
    padding: 2px 0 4px 18px;
}
.sq-tree-table-header.sq-open + .sq-tree-cols { display: block; }
.sq-tree-col {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 2px 6px;
    font-size: .67rem;
    color: var(--sq-muted);
}
.sq-tree-col-type {
    font-size: .6rem;
    background: rgba(14,165,233,.12);
    color: var(--sq-accent);
    border-radius: 3px;
    padding: 0 4px;
    margin-left: auto;
    white-space: nowrap;
}
.sq-tree-col-pk { color: var(--sq-warn); font-size: .62rem; }

/* Vertical resizer between schema and editor+results */
#mlp-sq-v-resizer {
    width: 5px;
    background: var(--sq-border);
    cursor: col-resize;
    flex-shrink: 0;
    transition: background .15s;
    position: relative;
    z-index: 2;
}
#mlp-sq-v-resizer:hover,
#mlp-sq-v-resizer.sq-dragging { background: var(--sq-accent); }

/* Editor + results column */
#mlp-sq-center {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    min-width: 0;
}

/* Editor pane */
#mlp-sq-editor-pane {
    flex: 0 0 55%;
    min-height: 120px;
    display: flex;
    flex-direction: column;
    position: relative;
}
#mlp-sq-editor {
    flex: 1;
    min-height: 0;
    width: 100%;
}

/* Horizontal resizer between editor and results */
#mlp-sq-h-resizer {
    height: 5px;
    background: var(--sq-border);
    cursor: row-resize;
    flex-shrink: 0;
    transition: background .15s;
    z-index: 2;
}
#mlp-sq-h-resizer:hover,
#mlp-sq-h-resizer.sq-dragging { background: var(--sq-accent); }

/* Results pane */
#mlp-sq-results-pane {
    flex: 1;
    min-height: 80px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    border-top: 1px solid var(--sq-border);
}
#mlp-sq-results-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 12px;
    height: 30px;
    background: var(--sq-surface2);
    border-bottom: 1px solid var(--sq-border);
    flex-shrink: 0;
    font-size: .65rem;
    color: var(--sq-muted);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .07em;
}
#mlp-sq-results-title { flex: 1; }
#mlp-sq-results-meta { font-size: .62rem; color: var(--sq-accent); font-style: normal; letter-spacing: 0; font-weight: 600; }
#mlp-sq-results-body {
    flex: 1;
    overflow: auto;
    background: var(--sq-bg);
    font-size: .75rem;
}
#mlp-sq-results-body::-webkit-scrollbar { width: 6px; height: 6px; }
#mlp-sq-results-body::-webkit-scrollbar-thumb { background: var(--sq-border); border-radius: 3px; }
.sq-results-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--sq-muted);
    font-size: .73rem;
    font-style: italic;
    padding: 20px;
    text-align: center;
}
.sq-results-msg {
    padding: 10px 14px;
    font-size: .75rem;
    color: var(--sq-success);
    display: flex;
    align-items: center;
    gap: 6px;
}
.sq-results-msg.sq-err { color: var(--sq-error); }
.sq-results-msg.sq-warn { color: var(--sq-warn); }
.sq-results-block { margin-bottom: 2px; }
.sq-results-block-label {
    padding: 4px 10px;
    font-size: .62rem;
    font-weight: 700;
    color: var(--sq-accent);
    background: var(--sq-surface2);
    border-bottom: 1px solid var(--sq-border);
    letter-spacing: .06em;
    text-transform: uppercase;
}

/* Results table */
.sq-table-wrap { overflow-x: auto; }
.sq-table {
    border-collapse: collapse;
    min-width: 100%;
    font-size: .73rem;
    font-family: var(--sq-font);
}
.sq-table th {
    position: sticky;
    top: 0;
    background: var(--sq-surface2);
    color: var(--sq-accent2);
    font-weight: 700;
    font-size: .67rem;
    text-transform: uppercase;
    letter-spacing: .05em;
    padding: 6px 12px;
    text-align: left;
    white-space: nowrap;
    border-bottom: 2px solid var(--sq-accent);
    border-right: 1px solid var(--sq-border);
    z-index: 1;
}
.sq-table th:last-child { border-right: none; }
.sq-table td {
    padding: 5px 12px;
    color: var(--sq-text);
    border-bottom: 1px solid var(--sq-border);
    border-right: 1px solid rgba(27,58,94,.5);
    white-space: nowrap;
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
}
.sq-table td:last-child { border-right: none; }
.sq-table td.sq-null { color: var(--sq-muted); font-style: italic; }
.sq-table tr:hover td { background: rgba(14,165,233,.06); }
.sq-table tr:nth-child(even) td { background: rgba(12,25,41,.4); }
.sq-table tr:nth-child(even):hover td { background: rgba(14,165,233,.08); }
.sq-row-num {
    color: var(--sq-muted);
    font-size: .62rem;
    text-align: right;
    user-select: none;
    border-right: 1px solid var(--sq-border) !important;
    padding-right: 8px !important;
    padding-left: 6px !important;
    min-width: 28px;
}

/* Status bar */
#mlp-sq-statusbar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 0 14px;
    height: 24px;
    background: var(--sq-surface);
    border-top: 1px solid var(--sq-border);
    flex-shrink: 0;
    font-size: .62rem;
    color: var(--sq-muted);
    overflow: hidden;
}
#mlp-sq-status-lang { display: inline-flex; align-items: center; gap: 4px; color: var(--sq-accent); font-weight: 700; }
#mlp-sq-status-msg  { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
#mlp-sq-status-pos  { white-space: nowrap; }
#mlp-sq-status-save { white-space: nowrap; font-style: italic; }

/* Toast */
#mlp-sq-toast {
    position: fixed;
    bottom: 22px;
    right: 22px;
    z-index: 999999;
    background: var(--sq-surface);
    border: 1px solid var(--sq-border);
    border-radius: 8px;
    padding: 10px 14px;
    font-size: .78rem;
    font-weight: 600;
    color: var(--sq-text);
    box-shadow: 0 6px 24px rgba(0,0,0,.4);
    opacity: 0;
    transform: translateY(8px);
    transition: opacity .22s, transform .22s;
    pointer-events: none;
    font-family: var(--sq-font);
}
#mlp-sq-toast.sq-show { opacity: 1; transform: translateY(0); }
#mlp-sq-toast.sq-err  { border-color: var(--sq-error); }
#mlp-sq-toast.sq-ok   { border-color: var(--sq-success); }

/* Spinner */
@keyframes sq-spin { to { transform: rotate(360deg); } }
.sq-spinner {
    width: 12px; height: 12px;
    border: 2px solid rgba(255,255,255,.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: sq-spin .7s linear infinite;
    display: inline-block;
    flex-shrink: 0;
}

/* ── AI Chat Sidebar ─────────────────────────────────────────── */
#mlp-sq-chat-sidebar {
    position: fixed;
    top: 56px; right: 12px; bottom: 20px;
    width: 360px;
    max-width: calc(96vw - 12px);
    z-index: 999991;
    background: var(--sq-bg);
    border: 1px solid var(--sq-border);
    border-radius: 10px;
    display: flex;
    flex-direction: column;
    font-family: var(--sq-font);
    transform: translateX(400px);
    transition: transform 0.25s cubic-bezier(0.4,0,0.2,1);
    box-shadow: -4px 8px 40px rgba(0,0,0,.55), 0 0 0 1px rgba(14,165,233,.12), -8px 0 40px rgba(14,165,233,.1);
    overflow: hidden;
}
#mlp-sq-chat-sidebar.sq-chat-open { transform: translateX(0); }
#mlp-sq-chat-overlay {
    position: fixed; inset: 0;
    background: rgba(0,0,0,.3);
    z-index: 999990;
    opacity: 0; pointer-events: none;
    transition: opacity 0.25s cubic-bezier(0.4,0,0.2,1);
}
#mlp-sq-chat-overlay.sq-chat-open { opacity: 1; pointer-events: auto; }
#mlp-sq-chat-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 14px;
    background: var(--sq-surface);
    border-bottom: 1px solid var(--sq-border);
    flex-shrink: 0;
}
#mlp-sq-chat-title { font-size: .83rem; font-weight: 700; color: var(--sq-text); }
#mlp-sq-chat-close {
    background: none; border: none; color: var(--sq-muted);
    cursor: pointer; padding: 4px; display: flex; align-items: center;
    transition: color .15s;
}
#mlp-sq-chat-close:hover { color: var(--sq-text); }
#mlp-sq-chat-messages {
    flex: 1; overflow-y: auto;
    padding: 12px; display: flex; flex-direction: column; gap: 10px;
}
.sq-chat-msg {
    padding: 8px 10px; border-radius: 6px;
    font-size: .75rem; line-height: 1.5;
    max-width: 95%; word-wrap: break-word;
}
.sq-chat-msg.user   { background: #0c2a4a; color: #93c5fd; align-self: flex-end; margin-left: auto; }
.sq-chat-msg.assistant { background: #0f1e35; color: #d4d4d4; align-self: flex-start; }
.sq-chat-empty {
    display: flex; align-items: center; justify-content: center;
    height: 100%; color: var(--sq-muted);
    font-size: .73rem; text-align: center; padding: 20px;
}
#mlp-sq-chat-input-area {
    display: flex; flex-direction: column; gap: 8px;
    padding: 10px;
    background: var(--sq-surface);
    border-top: 1px solid var(--sq-border);
    flex-shrink: 0;
}
#mlp-sq-chat-input {
    width: 100%; padding: 8px;
    background: rgba(0,0,0,.3);
    border: 1px solid var(--sq-border);
    border-radius: 4px; color: var(--sq-text);
    font-family: inherit; font-size: .75rem;
    resize: none; max-height: 80px;
    transition: border-color .15s;
}
#mlp-sq-chat-input:focus { outline: none; border-color: var(--sq-accent); }
#mlp-sq-chat-send {
    align-self: flex-end; padding: 5px 12px;
    background: #0284c7; color: #fff;
    border: none; border-radius: 4px;
    cursor: pointer; font-size: .73rem; font-weight: 600;
    transition: opacity .15s; font-family: inherit;
}
#mlp-sq-chat-send:hover:not(:disabled) { opacity: .88; }
#mlp-sq-chat-send:disabled { opacity: .5; cursor: not-allowed; }

/* Chat code blocks */
.sq-chat-code-wrap { margin: 6px 0 0; border-radius: 6px; overflow: hidden; border: 1px solid var(--sq-border); background: #050d1a; max-width: 100%; }
.sq-chat-code-header { display: flex; align-items: center; justify-content: space-between; padding: 4px 10px; background: var(--sq-surface2); border-bottom: 1px solid var(--sq-border); }
.sq-chat-code-lang { font-size: .62rem; font-weight: 700; color: var(--sq-accent2); letter-spacing: .06em; text-transform: uppercase; }
.sq-chat-code-actions { display: flex; gap: 5px; }
.sq-chat-code-apply, .sq-chat-code-copy {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 4px;
    font-family: inherit; font-size: .65rem; font-weight: 700;
    cursor: pointer; border: 1px solid transparent;
    transition: opacity .15s, background .15s;
}
.sq-chat-code-apply { background: #0284c7; color: #fff; }
.sq-chat-code-apply:hover { opacity: .85; }
.sq-chat-code-apply.sq-applied { background: #1d4ed8; }
.sq-chat-code-copy { background: transparent; border-color: #2a3a4a; color: #888; }
.sq-chat-code-copy:hover { color: #d4d4d4; border-color: #445; }
.sq-chat-code-pre { margin: 0; padding: 10px 12px; overflow-x: auto; font-family: var(--sq-font); font-size: .73rem; line-height: 1.6; color: #d4d4d4; white-space: pre; background: transparent; }
.sq-chat-undo-btn {
    display: inline-flex; align-items: center; gap: 4px; margin-top: 4px;
    padding: 2px 8px; background: transparent; border: 1px solid #3a3a3a;
    border-radius: 4px; color: var(--sq-warn);
    font-family: inherit; font-size: .65rem; font-weight: 700; cursor: pointer;
    transition: opacity .15s;
}
.sq-chat-undo-btn:hover { opacity: .8; }

/* Markdown in chat */
.sq-chat-msg.assistant .sq-md-code { font-family: var(--sq-font); font-size: .72rem; background: rgba(0,0,0,.35); border: 1px solid var(--sq-border); border-radius: 3px; padding: 0 4px; color: var(--sq-warn); }
.sq-chat-msg.assistant .sq-md-h2 { display: block; font-size: .85rem; font-weight: 700; color: #93c5fd; margin: 8px 0 3px; padding-bottom: 3px; border-bottom: 1px solid #1a2a3a; }
.sq-chat-msg.assistant .sq-md-h3 { display: block; font-size: .78rem; font-weight: 700; color: #a5b4fc; margin: 6px 0 2px; }
.sq-chat-msg.assistant strong { color: var(--sq-text); font-weight: 700; }
.sq-chat-msg.assistant em { color: #d1d5db; font-style: italic; }

/* Thinking animation */
.sq-thinking-bubble { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: #0f1e35; border-radius: 6px; border: 1px solid rgba(14,165,233,.15); align-self: flex-start; max-width: 95%; }
.sq-thinking-label { font-size: .68rem; color: var(--sq-muted); font-style: italic; white-space: nowrap; }
@keyframes sq-dot-wave { 0%,100%{transform:translateY(0);opacity:.35} 50%{transform:translateY(-6px);opacity:1} }
@keyframes sq-dot-glow { 0%,100%{filter:drop-shadow(0 0 0px #0ea5e9)} 50%{filter:drop-shadow(0 0 5px #0ea5e9)} }
.sq-think-dot { animation: sq-dot-wave 1.3s ease-in-out infinite, sq-dot-glow 1.3s ease-in-out infinite; }
.sq-think-dot:nth-child(2) { animation-delay: .22s; }
.sq-think-dot:nth-child(3) { animation-delay: .44s; }
@keyframes sq-ring-pulse { 0%,100%{opacity:.18;r:14} 50%{opacity:.45;r:16} }
.sq-think-ring { animation: sq-ring-pulse 1.3s ease-in-out infinite; transform-origin: center; }

/* Hide HTML chat when SQL editor is open */
html.mlp-sq-editor-active #mlpChatToggle,
html.mlp-sq-editor-active #mlpChatSidebar,
html.mlp-sq-editor-active #mlp-py-chat-fab { display: none !important; }

@media (max-width: 680px) {
    #mlp-sq-schema { display: none; }
    #mlp-sq-v-resizer { display: none; }
    #mlp-sq-editor-pane { flex: 0 0 50%; }
}
</style>
        <?php
    }

    public static function output_editor() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) return;
        ?>
<!-- ── SQL Editor Overlay ─────────────────────────────────────── -->
<div id="mlp-sql-overlay" role="dialog" aria-modal="true" aria-label="SQL Editor">

  <!-- Topbar -->
  <div id="mlp-sq-topbar">
    <button id="mlp-sq-back" type="button" aria-label="Back to projects">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      Projects
    </button>
    <div id="mlp-sq-title">
      <span id="mlp-sq-name">Untitled</span>
      <span>
        <svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor" style="opacity:.8"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15v-4H7l5-8v4h4l-5 8z"/></svg>
        SQLite
      </span>
    </div>
    <button id="mlp-sq-run" class="mlp-sq-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
      Run
    </button>
    <button id="mlp-sq-save" class="mlp-sq-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
      Save
    </button>
    <button id="mlp-sq-export" class="mlp-sq-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Export .db
    </button>
    <button id="mlp-sq-clear-db" class="mlp-sq-btn" type="button" title="Reset the in-memory database">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-4.66"/></svg>
      Clear DB
    </button>
    <button id="mlp-sq-fs-btn" class="mlp-sq-btn" type="button" title="Toggle fullscreen (Ctrl+Shift+F)">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
    </button>
  </div>

  <!-- Body: schema sidebar + editor + results -->
  <div id="mlp-sq-body">

    <!-- Schema sidebar -->
    <div id="mlp-sq-schema">
      <div id="mlp-sq-schema-header">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>
        Schema
      </div>
      <div id="mlp-sq-schema-tree">
        <div class="sq-tree-empty">Run a query to see tables</div>
      </div>
    </div>

    <!-- Vertical resizer -->
    <div id="mlp-sq-v-resizer" role="separator" aria-orientation="vertical" aria-label="Resize schema panel"></div>

    <!-- Center: editor + horizontal resizer + results -->
    <div id="mlp-sq-center">
      <div id="mlp-sq-editor-pane">
        <div id="mlp-sq-editor"></div>
      </div>
      <div id="mlp-sq-h-resizer" role="separator" aria-orientation="horizontal" aria-label="Resize results panel"></div>
      <div id="mlp-sq-results-pane">
        <div id="mlp-sq-results-header">
          <span id="mlp-sq-results-title">
            <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline;margin-right:4px;vertical-align:middle;"><rect x="3" y="3" width="18" height="5" rx="1"/><rect x="3" y="10" width="18" height="5" rx="1"/><rect x="3" y="17" width="18" height="5" rx="1"/></svg>
            Results
          </span>
          <span id="mlp-sq-results-meta"></span>
        </div>
        <div id="mlp-sq-results-body">
          <div class="sq-results-empty">Press ▶ Run or Ctrl+Enter to execute your queries</div>
        </div>
      </div>
    </div>

  </div>

  <!-- Status bar -->
  <div id="mlp-sq-statusbar">
    <span id="mlp-sq-status-lang">
      <svg width="8" height="8" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>
      SQLite 3
    </span>
    <span id="mlp-sq-status-msg"></span>
    <span id="mlp-sq-status-pos">Ln 1, Col 1</span>
    <span id="mlp-sq-status-save"></span>
  </div>
</div>

<!-- SQL AI Chat Sidebar -->
<div id="mlp-sq-chat-overlay"></div>
<div id="mlp-sq-chat-sidebar">
  <div id="mlp-sq-chat-header">
    <div id="mlp-sq-chat-title">SQL AI Chat</div>
    <button id="mlp-sq-chat-close" type="button" title="Close chat">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>
  <div id="mlp-sq-chat-messages">
    <div class="sq-chat-empty">Ask the SQL AI assistant about your queries</div>
  </div>
  <div id="mlp-sq-chat-input-area">
    <textarea id="mlp-sq-chat-input" placeholder="Ask about SQL, queries, optimization…" rows="2"></textarea>
    <button id="mlp-sq-chat-send" type="button">Send</button>
  </div>
</div>

<!-- Toast -->
<div id="mlp-sq-toast"></div>

<!-- Floating AI Chat FAB -->
<button id="mlp-sq-chat-fab" class="mlp-sq-fab-hidden" type="button" aria-label="Open SQL AI Chat">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
  AI Chat
</button>

<script>
(function(){
'use strict';

/* ── Config ──────────────────────────────────────────────────── */
var SQLJS_URL      = 'https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.12.0/sql-wasm.js';
var SQLJS_WASM_URL = 'https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.12.0/sql-wasm.wasm';
var MLP_LS         = 'mlp_projects';
var MLP_SQ_TS_KEY  = <?php echo json_encode( defined( 'MLP_TURNSTILE_SITE_KEY' ) ? MLP_TURNSTILE_SITE_KEY : '' ); ?>;

/* ── SQL AI Chat ─────────────────────────────────────────────── */
var _sqChatHistories = {};
var _sqChatBusy      = false;
var _sqChatAbort     = null;
var _sqTsToken       = '';
var _sqTsVerified    = false;
var _sqTsPending     = '';
var _sqTsWidgetId    = null;
var _sqTsWidgetEl    = null;
var _sqUndoStack     = [];
var _sqThinkingEl    = null;

function _getSqChatKey(id) { return 'mlp_sq_chat_' + (id || 'default'); }

function _getSqChatHistory(key) {
    if (!_sqChatHistories[key]) {
        try { _sqChatHistories[key] = JSON.parse(localStorage.getItem(key)) || []; }
        catch(e) { _sqChatHistories[key] = []; }
    }
    return _sqChatHistories[key];
}
function _saveSqChatHistory(key, h) {
    _sqChatHistories[key] = h;
    try { localStorage.setItem(key, JSON.stringify(h)); } catch(e) {}
}

function _openSqChat() {
    var s = $id('mlp-sq-chat-sidebar'), o = $id('mlp-sq-chat-overlay'), f = $id('mlp-sq-chat-fab');
    if (s) s.classList.add('sq-chat-open');
    if (o) o.classList.add('sq-chat-open');
    if (f) f.classList.add('mlp-sq-fab-hidden');
    var inp = $id('mlp-sq-chat-input');
    if (inp) setTimeout(function(){ inp.focus(); }, 100);
}
function _closeSqChat() {
    var s = $id('mlp-sq-chat-sidebar'), o = $id('mlp-sq-chat-overlay'), f = $id('mlp-sq-chat-fab');
    if (s) s.classList.remove('sq-chat-open');
    if (o) o.classList.remove('sq-chat-open');
    if (f) f.classList.remove('mlp-sq-fab-hidden');
}

function _applySQLToEditor(code, btn) {
    if (!sqEditor) return;
    var prev = sqEditor.getValue();
    _sqUndoStack.push(prev);
    sqEditor.setValue(code);
    sqEditor.setScrollPosition({ scrollTop: 0 });
    _unsaved = true;
    setSqSave('● Unsaved');
    if (btn) {
        btn.textContent = '✓ Applied';
        btn.classList.add('sq-applied');
        if (btn.parentNode && !btn.parentNode.querySelector('.sq-chat-undo-btn')) {
            var u = document.createElement('button');
            u.className = 'sq-chat-undo-btn'; u.type = 'button'; u.innerHTML = '↩ Undo';
            u.addEventListener('click', function() {
                var prev2 = _sqUndoStack.pop();
                if (prev2 !== undefined) { sqEditor.setValue(prev2); sqEditor.setScrollPosition({ scrollTop: 0 }); _unsaved = true; setSqSave('● Unsaved'); }
                btn.textContent = '▶ Apply'; btn.classList.remove('sq-applied');
                u.parentNode && u.parentNode.removeChild(u);
            });
            btn.parentNode.appendChild(u);
        }
    }
}

function _buildSqCodeBlock(lang, code) {
    var wrap = document.createElement('div'); wrap.className = 'sq-chat-code-wrap';
    var hdr  = document.createElement('div'); hdr.className  = 'sq-chat-code-header';
    var lbl  = document.createElement('span'); lbl.className = 'sq-chat-code-lang'; lbl.textContent = lang || 'sql';
    var acts = document.createElement('div'); acts.className = 'sq-chat-code-actions';
    var cp   = document.createElement('button'); cp.className = 'sq-chat-code-copy'; cp.type = 'button'; cp.textContent = 'Copy';
    cp.addEventListener('click', function() {
        navigator.clipboard && navigator.clipboard.writeText(code).then(function(){ cp.textContent = '✓ Copied'; setTimeout(function(){ cp.textContent = 'Copy'; }, 1800); });
    });
    var ap = document.createElement('button'); ap.className = 'sq-chat-code-apply'; ap.type = 'button'; ap.textContent = '▶ Apply';
    ap.addEventListener('click', function() { _applySQLToEditor(code, ap); });
    acts.appendChild(cp); acts.appendChild(ap);
    hdr.appendChild(lbl); hdr.appendChild(acts);
    var pre = document.createElement('pre'); pre.className = 'sq-chat-code-pre'; pre.textContent = code;
    wrap.appendChild(hdr); wrap.appendChild(pre);
    return wrap;
}

function _showSqThinking() {
    _hideSqThinking();
    var msgs = $id('mlp-sq-chat-messages');
    if (!msgs) return;
    var em = msgs.querySelector('.sq-chat-empty'); if (em) msgs.innerHTML = '';
    var b = document.createElement('div'); b.className = 'sq-thinking-bubble';
    b.innerHTML = '<svg width="38" height="16" viewBox="0 0 38 16" fill="none"><defs><radialGradient id="sq-tg1" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="#38bdf8"/><stop offset="100%" stop-color="#0ea5e9"/></radialGradient></defs><circle class="sq-think-ring" cx="7" cy="8" r="14" fill="#0ea5e9"/><circle class="sq-think-dot" cx="7" cy="8" r="3.5" fill="url(#sq-tg1)"/><circle class="sq-think-dot" cx="19" cy="8" r="3.5" fill="url(#sq-tg1)"/><circle class="sq-think-dot" cx="31" cy="8" r="3.5" fill="url(#sq-tg1)"/></svg><span class="sq-thinking-label">AI is thinking…</span>';
    msgs.appendChild(b); msgs.scrollTop = msgs.scrollHeight;
    _sqThinkingEl = b;
}
function _hideSqThinking() {
    if (_sqThinkingEl && _sqThinkingEl.parentNode) _sqThinkingEl.parentNode.removeChild(_sqThinkingEl);
    _sqThinkingEl = null;
}

function _renderMdInline(text) {
    var frag = document.createDocumentFragment();
    var re = /(`[^`]+`|\*\*[\s\S]+?\*\*|\*[^*\n]+?\*)/g;
    var last = 0, m;
    while ((m = re.exec(text)) !== null) {
        if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        var tok = m[0];
        if (tok.startsWith('**')) { var s = document.createElement('strong'); s.textContent = tok.slice(2,-2); frag.appendChild(s); }
        else if (tok.startsWith('`')) { var c = document.createElement('code'); c.className = 'sq-md-code'; c.textContent = tok.slice(1,-1); frag.appendChild(c); }
        else { var e = document.createElement('em'); e.textContent = tok.slice(1,-1); frag.appendChild(e); }
        last = m.index + tok.length;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    return frag;
}

function _appendSqChatMsg(role, text) {
    var msgs = $id('mlp-sq-chat-messages');
    if (!msgs) return;
    var em = msgs.querySelector('.sq-chat-empty'); if (em) msgs.innerHTML = '';
    var b = document.createElement('div'); b.className = 'sq-chat-msg ' + role;
    if (role === 'assistant') {
        var parts = text.split(/(```[\w]*\n[\s\S]*?```)/g);
        parts.forEach(function(part) {
            var fence = part.match(/^```([\w]*)\n([\s\S]*?)```$/);
            if (fence) {
                b.appendChild(_buildSqCodeBlock(fence[1] || 'sql', fence[2].replace(/\n$/, '')));
            } else if (part.trim()) {
                var lines = part.split('\n');
                lines.forEach(function(line, i) {
                    if (/^### /.test(line))      { var h = document.createElement('span'); h.className = 'sq-md-h3'; h.appendChild(_renderMdInline(line.slice(4))); b.appendChild(h); }
                    else if (/^## /.test(line))  { var h = document.createElement('span'); h.className = 'sq-md-h2'; h.appendChild(_renderMdInline(line.slice(3))); b.appendChild(h); }
                    else if (/^# /.test(line))   { var h = document.createElement('span'); h.className = 'sq-md-h2'; h.appendChild(_renderMdInline(line.slice(2))); b.appendChild(h); }
                    else if (line)               { var sp = document.createElement('span'); sp.appendChild(_renderMdInline(line)); b.appendChild(sp); }
                    if (i < lines.length - 1) b.appendChild(document.createElement('br'));
                });
            }
        });
    } else { b.textContent = text; }
    msgs.appendChild(b); msgs.scrollTop = msgs.scrollHeight;
}

function _sendSqChat() {
    if (_sqChatBusy) return;
    var inp  = $id('mlp-sq-chat-input');
    var text = _sqTsPending || (inp && inp.value.trim());
    if (!text) return;
    _sqTsPending = '';
    if (inp) inp.value = '';
    if (!_sqTsVerified) {
        _sqTsPending = text;
        _appendSqChatMsg('user', text);
        _appendSqChatMsg('assistant', 'Please complete the verification to continue.');
        _renderSqTurnstile();
        return;
    }
    var key = _getSqChatKey(_sqActiveId);
    var hist = _getSqChatHistory(key);
    hist.push({ role: 'user', content: text });
    _saveSqChatHistory(key, hist);
    _appendSqChatMsg('user', text);
    _sqChatBusy = true;
    _showSqThinking();
    var sqlCode = sqEditor ? sqEditor.getValue() : '';
    var fd = new FormData();
    fd.append('action', 'mlp_ai_chat_sql');
    fd.append('nonce', (window.mlp_ajax && window.mlp_ajax.nonce) ? window.mlp_ajax.nonce : '');
    fd.append('message', text);
    fd.append('sql_code', sqlCode);
    fd.append('turnstile_token', _sqTsToken);
    fd.append('history', JSON.stringify(hist.slice(-12, -1)));
    var url = (window.mlp_ajax && window.mlp_ajax.ajaxurl) ? window.mlp_ajax.ajaxurl : '/wp-admin/admin-ajax.php';
    _sqChatAbort = new AbortController();
    fetch(url, { method: 'POST', body: fd, signal: _sqChatAbort.signal })
        .then(function(r){ return r.json(); })
        .then(function(data) {
            _hideSqThinking();
            var h = _getSqChatHistory(key);
            if (data.success && data.data && data.data.reply) {
                h.push({ role: 'assistant', content: data.data.reply });
                _saveSqChatHistory(key, h);
                _appendSqChatMsg('assistant', data.data.reply);
            } else {
                var err = (data.data && data.data.message) ? data.data.message : 'AI unavailable. Try again later.';
                _appendSqChatMsg('assistant', '⚠ ' + err);
            }
        })
        .catch(function(err) {
            _hideSqThinking();
            if (err.name !== 'AbortError') _appendSqChatMsg('assistant', '⚠ Network error: ' + err.message);
        })
        .finally(function() { _sqChatBusy = false; _hideSqThinking(); _removeSqTsWidget(); });
}

function _removeSqTsWidget() {
    if (_sqTsWidgetId !== null && window.turnstile) { try { window.turnstile.remove(_sqTsWidgetId); } catch(e){} _sqTsWidgetId = null; }
    if (_sqTsWidgetEl && _sqTsWidgetEl.parentNode) _sqTsWidgetEl.parentNode.removeChild(_sqTsWidgetEl);
    _sqTsWidgetEl = null;
}

function _renderSqTurnstile() {
    if (!MLP_SQ_TS_KEY) return;
    _removeSqTsWidget();
    var msgs = $id('mlp-sq-chat-messages'); if (!msgs) return;
    var cont = document.createElement('div'); cont.style.cssText = 'padding:6px 0;display:flex;justify-content:center;';
    var wd = document.createElement('div'); cont.appendChild(wd); msgs.appendChild(cont); msgs.scrollTop = msgs.scrollHeight;
    _sqTsWidgetEl = cont;
    function doRender() {
        if (!window.turnstile || !window.turnstile.render) return;
        _sqTsWidgetId = window.turnstile.render(wd, {
            sitekey: MLP_SQ_TS_KEY, theme: 'dark',
            callback: function(tok){ _sqTsToken = tok; _sqTsVerified = true; setTimeout(_sendSqChat, 300); },
            'error-callback': function(){ _sqTsVerified = false; _sqTsToken = ''; }
        });
    }
    if (window.turnstile && window.turnstile.render) { doRender(); }
    else {
        var s = document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]');
        if (!s) { s = document.createElement('script'); s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'; s.async = true; document.head.appendChild(s); }
        s.onload = doRender;
        var _p = setInterval(function(){ if (window.turnstile && window.turnstile.render){ clearInterval(_p); doRender(); } }, 100);
        setTimeout(function(){ clearInterval(_p); }, 8000);
    }
}

/* ── State ───────────────────────────────────────────────────── */
var sqEditor      = null;
var monacoReady   = false;
var _sqActiveId   = null;
var _unsaved      = false;
var _sqlJs        = null;   /* sql.js SQL constructor */
var _sqlJsPromise = null;   /* in-flight load promise */
var _db           = null;   /* current SQLite DB instance */

/* ── DOM helper ──────────────────────────────────────────────── */
function $id(id) { return document.getElementById(id); }

/* ── Project helpers ─────────────────────────────────────────── */
function getProjects() { try { return JSON.parse(localStorage.getItem(MLP_LS)) || []; } catch(e) { return []; } }
function saveProjects(a) { try { localStorage.setItem(MLP_LS, JSON.stringify(a)); } catch(e) {} }
function getProject(id) { return getProjects().find(function(p){ return p && p.id === id; }) || null; }
function updateProject(id, patch) {
    var a = getProjects();
    for (var i = 0; i < a.length; i++) { if (a[i] && a[i].id === id) { Object.assign(a[i], patch); break; } }
    saveProjects(a);
}

/* ── Toast ───────────────────────────────────────────────────── */
var _toastT = null;
function sqToast(msg, type, ms) {
    var el = $id('mlp-sq-toast'); if (!el) return;
    el.textContent = msg;
    el.className = 'sq-show' + (type === 'err' ? ' sq-err' : type === 'ok' ? ' sq-ok' : '');
    clearTimeout(_toastT);
    _toastT = setTimeout(function(){ el.className = ''; }, ms || 2500);
}

/* ── Status helpers ──────────────────────────────────────────── */
function setSqStatus(m) { var el = $id('mlp-sq-status-msg');  if (el) el.textContent = m || ''; }
function setSqSave(m)   { var el = $id('mlp-sq-status-save'); if (el) el.textContent = m || ''; }
function setSqMeta(m)   { var el = $id('mlp-sq-results-meta'); if (el) el.textContent = m || ''; }

/* ── Ensure sql.js loaded (singleton) ───────────────────────── */
function ensureSqlJS() {
    if (_sqlJs) return Promise.resolve(_sqlJs);
    if (_sqlJsPromise) return _sqlJsPromise;
    _sqlJsPromise = new Promise(function(resolve, reject) {
        var sc = document.createElement('script');
        sc.src = SQLJS_URL;
        sc.onload = function() {
            window.initSqlJs({ locateFile: function() { return SQLJS_WASM_URL; } })
                .then(function(SQL) { _sqlJs = SQL; resolve(SQL); })
                .catch(function(e) { _sqlJsPromise = null; reject(e); });
        };
        sc.onerror = function() { _sqlJsPromise = null; reject(new Error('Failed to load sql.js. Check your internet connection.')); };
        document.head.appendChild(sc);
    });
    return _sqlJsPromise;
}

function getOrCreateDB(SQL) {
    if (!_db) _db = new SQL.Database();
    return _db;
}

function resetDB() {
    if (_db) { try { _db.close(); } catch(e){} }
    _db = null;
    if (_sqlJs) _db = new _sqlJs.Database();
}

/* ── Schema sidebar ─────────────────────────────────────────── */
function updateSchema() {
    var tree = $id('mlp-sq-schema-tree');
    if (!tree || !_db) return;
    var tables = [];
    try {
        var res = _db.exec("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
        if (res.length && res[0].values) tables = res[0].values.map(function(r){ return r[0]; });
    } catch(e) { return; }
    if (tables.length === 0) { tree.innerHTML = '<div class="sq-tree-empty">No tables yet</div>'; return; }
    tree.innerHTML = '';
    tables.forEach(function(tname) {
        var cols = [];
        try {
            var pr = _db.exec('PRAGMA table_info(' + JSON.stringify(tname) + ')');
            if (pr.length && pr[0].values) {
                cols = pr[0].values.map(function(r) {
                    return { name: r[1], type: r[2] || 'ANY', pk: r[5] > 0 };
                });
            }
        } catch(e) {}
        var tbl = document.createElement('div'); tbl.className = 'sq-tree-table';
        var hdr = document.createElement('div'); hdr.className = 'sq-tree-table-header';
        hdr.innerHTML = '<span class="sq-tree-table-chevron">›</span><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="5" rx="1"/><rect x="3" y="10" width="18" height="5" rx="1"/><rect x="3" y="17" width="18" height="5" rx="1"/></svg>' + escHtml(tname) + ' <span style="color:var(--sq-muted);font-size:.6rem;margin-left:2px;">(' + cols.length + ')</span>';
        var colsEl = document.createElement('div'); colsEl.className = 'sq-tree-cols';
        cols.forEach(function(col) {
            var cd = document.createElement('div'); cd.className = 'sq-tree-col';
            cd.innerHTML = (col.pk ? '<span class="sq-tree-col-pk" title="Primary Key">🔑</span>' : '<span style="width:14px;display:inline-block"></span>') + '<span>' + escHtml(col.name) + '</span><span class="sq-tree-col-type">' + escHtml(col.type) + '</span>';
            colsEl.appendChild(cd);
        });
        hdr.addEventListener('click', function() {
            hdr.classList.toggle('sq-open');
        });
        tbl.appendChild(hdr); tbl.appendChild(colsEl);
        tree.appendChild(tbl);
    });
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

/* ── Results rendering ──────────────────────────────────────── */
function renderResults(results, stats) {
    var body = $id('mlp-sq-results-body');
    if (!body) return;
    body.innerHTML = '';
    if (!results || results.length === 0) {
        body.innerHTML = '<div class="sq-results-msg">✓ ' + escHtml(stats || 'Query executed successfully') + '</div>';
        setSqMeta(stats || '');
        return;
    }
    var totalRows = 0;
    results.forEach(function(rs, idx) {
        if (!rs || !rs.columns) return;
        var block = document.createElement('div'); block.className = 'sq-results-block';
        if (results.length > 1) {
            var lbl = document.createElement('div'); lbl.className = 'sq-results-block-label';
            lbl.textContent = 'Result set ' + (idx + 1);
            block.appendChild(lbl);
        }
        var wrap = document.createElement('div'); wrap.className = 'sq-table-wrap';
        var tbl = document.createElement('table'); tbl.className = 'sq-table';
        var thead = document.createElement('thead'); var tr = document.createElement('tr');
        var thRn = document.createElement('th'); thRn.textContent = '#'; thRn.style.width = '36px'; tr.appendChild(thRn);
        rs.columns.forEach(function(col) {
            var th = document.createElement('th'); th.textContent = col; tr.appendChild(th);
        });
        thead.appendChild(tr); tbl.appendChild(thead);
        var tbody = document.createElement('tbody');
        (rs.values || []).forEach(function(row, ri) {
            totalRows++;
            var r = document.createElement('tr');
            var td0 = document.createElement('td'); td0.className = 'sq-row-num'; td0.textContent = ri + 1; r.appendChild(td0);
            row.forEach(function(cell) {
                var td = document.createElement('td');
                if (cell === null || cell === undefined) { td.className = 'sq-null'; td.textContent = 'NULL'; }
                else { td.textContent = String(cell); td.title = String(cell); }
                r.appendChild(td);
            });
            tbody.appendChild(r);
        });
        tbl.appendChild(tbody); wrap.appendChild(tbl); block.appendChild(wrap);
        body.appendChild(block);
    });
    var meta = totalRows + ' row' + (totalRows !== 1 ? 's' : '') + (stats ? ' · ' + stats : '');
    setSqMeta(meta);
    setSqStatus(meta);
}

function renderError(msg) {
    var body = $id('mlp-sq-results-body');
    if (body) body.innerHTML = '<div class="sq-results-msg sq-err">✗ ' + escHtml(msg) + '</div>';
    setSqMeta('Error');
    setSqStatus('Error — ' + msg.split('\n')[0]);
}

/* ── SQL statement splitter (respects strings and comments) ─── */
function splitStatements(sql) {
    var stmts = [], cur = '', inStr = false, strChar = '', i = 0;
    while (i < sql.length) {
        var ch = sql[i];
        if (!inStr && (sql.slice(i, i+2) === '--')) {
            var nl = sql.indexOf('\n', i);
            i = nl === -1 ? sql.length : nl + 1;
            continue;
        }
        if (!inStr && (sql.slice(i, i+2) === '/*')) {
            var ec = sql.indexOf('*/', i + 2);
            i = ec === -1 ? sql.length : ec + 2;
            continue;
        }
        if (!inStr && (ch === "'" || ch === '"' || ch === '`')) { inStr = true; strChar = ch; cur += ch; i++; continue; }
        if (inStr && ch === strChar) {
            if (sql[i+1] === strChar) { cur += ch + ch; i += 2; continue; }
            inStr = false; strChar = ''; cur += ch; i++; continue;
        }
        if (!inStr && ch === ';') { var s = cur.trim(); if (s) stmts.push(s); cur = ''; i++; continue; }
        cur += ch; i++;
    }
    var last = cur.trim(); if (last) stmts.push(last);
    return stmts;
}

/* ── Run ─────────────────────────────────────────────────────── */
function runSQL() {
    if (!sqEditor) return;
    var code = sqEditor.getValue().trim();
    if (!code) {
        var body = $id('mlp-sq-results-body');
        if (body) body.innerHTML = '<div class="sq-results-msg sq-warn">⚠ Nothing to run</div>';
        return;
    }
    var runBtn = $id('mlp-sq-run');
    if (runBtn) { runBtn.innerHTML = '<span class="sq-spinner"></span> Running…'; runBtn.disabled = true; }
    setSqStatus('Loading sql.js…');
    ensureSqlJS()
        .then(function(SQL) {
            var db = getOrCreateDB(SQL);
            var stmts = splitStatements(code);
            var allResults = [], totalChanges = 0, t0 = Date.now();
            var lastNonSelect = '';
            var hadSelect = false;
            for (var i = 0; i < stmts.length; i++) {
                try {
                    var res = db.exec(stmts[i]);
                    if (res.length > 0) { allResults = allResults.concat(res); hadSelect = true; }
                    else {
                        var ch = db.getRowsModified();
                        totalChanges += ch;
                        lastNonSelect = ch + ' row' + (ch !== 1 ? 's' : '') + ' affected';
                    }
                } catch(err) {
                    renderError(err.message || String(err));
                    if (runBtn) { runBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run'; runBtn.disabled = false; }
                    return;
                }
            }
            var ms = Date.now() - t0;
            var timeStr = ms + 'ms';
            if (hadSelect) {
                renderResults(allResults, timeStr);
            } else {
                renderResults(null, totalChanges + ' row' + (totalChanges !== 1 ? 's' : '') + ' affected · ' + timeStr);
            }
            updateSchema();
            setSqStatus('✓ Done in ' + timeStr);
            if (runBtn) { runBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run'; runBtn.disabled = false; }
        })
        .catch(function(err) {
            renderError((err && err.message) ? err.message : String(err));
            setSqStatus('Failed to load sql.js');
            if (runBtn) { runBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run'; runBtn.disabled = false; }
        });
}

/* ── Save ────────────────────────────────────────────────────── */
function saveSQLProject() {
    if (!_sqActiveId) return;
    var code = sqEditor ? sqEditor.getValue() : '';
    updateProject(_sqActiveId, { sql: code, type: 'sql', updatedAt: new Date().toISOString() });
    _unsaved = false;
    setSqSave('Saved ' + new Date().toLocaleTimeString());
    sqToast('Project saved', 'ok', 1800);
}

/* ── Export .db ──────────────────────────────────────────────── */
function exportSQLProject() {
    var code = sqEditor ? sqEditor.getValue() : '';
    var p    = _sqActiveId ? getProject(_sqActiveId) : null;
    var name = (p && p.name) ? p.name.replace(/[^a-z0-9_\-]/gi, '_') : 'sql_project';
    var blob = new Blob([code], { type: 'text/plain' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a');
    a.href = url; a.download = name + '.db';
    document.body.appendChild(a); a.click();
    setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(url); }, 500);
    sqToast('Exported ' + name + '.db', 'ok', 2200);
}

/* ── Monaco ──────────────────────────────────────────────────── */
function mountSqMonaco(code) {
    if (!window.monaco) return;
    var container = $id('mlp-sq-editor'); if (!container) return;
    if (sqEditor) { sqEditor.setValue(code); return; }
    sqEditor = window.monaco.editor.create(container, {
        value:    code,
        language: 'sql',
        theme:    'vs-dark',
        fontSize: 14, lineHeight: 22,
        fontFamily: "'JetBrains Mono','Fira Code','Consolas',monospace",
        minimap:  { enabled: false },
        scrollBeyondLastLine: false,
        automaticLayout: true,
        wordWrap: 'off',
        renderLineHighlight: 'line',
        cursorBlinking: 'smooth',
        smoothScrolling: true,
        folding: true,
        suggestOnTriggerCharacters: true,
        quickSuggestions: { other: true, comments: false, strings: false },
        bracketPairColorization: { enabled: true },
        padding: { top: 10, bottom: 10 },
    });
    sqEditor.onDidChangeCursorPosition(function(e) {
        var el = $id('mlp-sq-status-pos');
        if (el) el.textContent = 'Ln ' + e.position.lineNumber + ', Col ' + e.position.column;
    });
    sqEditor.onDidChangeModelContent(function() { _unsaved = true; setSqSave('● Unsaved'); });
    sqEditor.addCommand(window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.Enter, runSQL);
    sqEditor.addCommand(window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.KeyS, saveSQLProject);
}

function waitForMonacoThenMountSq(code) {
    var tries = 0;
    var t = setInterval(function() {
        if (window.monaco) { clearInterval(t); monacoReady = true; mountSqMonaco(code); return; }
        if (++tries > 60) clearInterval(t);
    }, 200);
}

/* ── Open / Close ─────────────────────────────────────────────── */
function openSQLEditor(projectId) {
    var p = getProject(projectId);
    if (!p || p.type !== 'sql') return;
    _sqActiveId = projectId;
    _unsaved    = false;
    resetDB();

    var nameEl = $id('mlp-sq-name'); if (nameEl) nameEl.textContent = p.name || 'Untitled';
    var overlay = $id('mlp-sql-overlay'); if (overlay) overlay.classList.add('mlp-sq-active');
    document.documentElement.classList.add('mlp-sq-editor-active');

    setSqSave(''); setSqStatus('Ready'); setSqMeta('');
    var body = $id('mlp-sq-results-body');
    if (body) body.innerHTML = '<div class="sq-results-empty">Press ▶ Run or Ctrl+Enter to execute your queries</div>';
    var tree = $id('mlp-sq-schema-tree');
    if (tree) tree.innerHTML = '<div class="sq-tree-empty">Run a query to see tables</div>';

    var code = p.sql || '';
    if (monacoReady && window.monaco) { mountSqMonaco(code); }
    else { waitForMonacoThenMountSq(code); }

    /* Wire FAB and chat */
    var fab = $id('mlp-sq-chat-fab');
    if (fab) {
        fab.classList.remove('mlp-sq-fab-hidden');
        if (!fab._sqWired) { fab.addEventListener('click', _openSqChat); fab._sqWired = true; }
    }
    var chatClose   = $id('mlp-sq-chat-close');
    var chatSend    = $id('mlp-sq-chat-send');
    var chatInput   = $id('mlp-sq-chat-input');
    var chatOverlay = $id('mlp-sq-chat-overlay');
    if (chatClose)   chatClose.addEventListener('click', _closeSqChat);
    if (chatSend)    chatSend.addEventListener('click', _sendSqChat);
    if (chatOverlay) chatOverlay.addEventListener('click', _closeSqChat);
    if (chatInput) {
        chatInput.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); _sendSqChat(); }
        });
    }
}

function closeSQLEditor() {
    if (_unsaved && !confirm('You have unsaved changes. Leave without saving?')) return;
    if (_db) { try { _db.close(); } catch(e){} _db = null; }
    var overlay = $id('mlp-sql-overlay');
    if (overlay) overlay.classList.remove('mlp-sq-active');
    _closeSqChat();
    var fab = $id('mlp-sq-chat-fab');
    if (fab) fab.classList.add('mlp-sq-fab-hidden');
    document.documentElement.classList.remove('mlp-sq-editor-active');
    _sqActiveId = null;
    if (typeof window.mlpProjectsOpen === 'function') {
        window.mlpProjectsOpen();
    } else {
        var po = document.getElementById('mlp-projects-overlay');
        if (po) { po.classList.remove('mlp-proj-hidden'); po.style.display = ''; document.body.style.overflow = 'hidden'; }
    }
}

/* ── Resizers ────────────────────────────────────────────────── */
(function() {
    /* Vertical: schema ↔ center */
    var vr = $id('mlp-sq-v-resizer'), schema = $id('mlp-sq-schema'), body = $id('mlp-sq-body');
    if (vr && schema && body) {
        var drag = false, sx = 0, sw = 0;
        vr.addEventListener('mousedown', function(e) { drag = true; sx = e.clientX; sw = schema.getBoundingClientRect().width; vr.classList.add('sq-dragging'); document.body.style.cursor = 'col-resize'; document.body.style.userSelect = 'none'; e.preventDefault(); });
        document.addEventListener('mousemove', function(e) { if (!drag) return; var bw = body.getBoundingClientRect().width; schema.style.width = Math.max(100, Math.min(bw * 0.4, sw + e.clientX - sx)) + 'px'; });
        document.addEventListener('mouseup', function() { if (!drag) return; drag = false; vr.classList.remove('sq-dragging'); document.body.style.cursor = ''; document.body.style.userSelect = ''; if (sqEditor) sqEditor.layout(); });
    }
    /* Horizontal: editor ↔ results */
    var hr = $id('mlp-sq-h-resizer'), ep = $id('mlp-sq-editor-pane'), center = $id('mlp-sq-center');
    if (hr && ep && center) {
        var hdrag = false, hy = 0, hh = 0;
        hr.addEventListener('mousedown', function(e) { hdrag = true; hy = e.clientY; hh = ep.getBoundingClientRect().height; hr.classList.add('sq-dragging'); document.body.style.cursor = 'row-resize'; document.body.style.userSelect = 'none'; e.preventDefault(); });
        document.addEventListener('mousemove', function(e) { if (!hdrag) return; var ch = center.getBoundingClientRect().height; var newH = Math.max(80, Math.min(ch * 0.85, hh + e.clientY - hy)); ep.style.flex = 'none'; ep.style.height = newH + 'px'; });
        document.addEventListener('mouseup', function() { if (!hdrag) return; hdrag = false; hr.classList.remove('sq-dragging'); document.body.style.cursor = ''; document.body.style.userSelect = ''; if (sqEditor) sqEditor.layout(); });
    }
})();

/* ── Fullscreen ──────────────────────────────────────────────── */
function toggleSqFullscreen() {
    var ov = $id('mlp-sql-overlay'); if (!ov) return;
    var fs = ov.classList.toggle('mlp-sq-fullscreen');
    var btn = $id('mlp-sq-fs-btn');
    if (btn) btn.innerHTML = fs
        ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="10" y1="14" x2="3" y2="21"/><line x1="21" y1="3" x2="14" y2="10"/></svg>'
        : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>';
    if (sqEditor) setTimeout(function(){ sqEditor.layout(); }, 50);
}

/* ── Wire buttons ────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
    var runBtn    = $id('mlp-sq-run');
    var saveBtn   = $id('mlp-sq-save');
    var expBtn    = $id('mlp-sq-export');
    var clrBtn    = $id('mlp-sq-clear-db');
    var fsBtn     = $id('mlp-sq-fs-btn');
    var backBtn   = $id('mlp-sq-back');
    if (runBtn)  runBtn.addEventListener('click',  runSQL);
    if (saveBtn) saveBtn.addEventListener('click', saveSQLProject);
    if (expBtn)  expBtn.addEventListener('click',  exportSQLProject);
    if (fsBtn)   fsBtn.addEventListener('click',   toggleSqFullscreen);
    if (backBtn) backBtn.addEventListener('click', closeSQLEditor);
    if (clrBtn)  clrBtn.addEventListener('click', function() {
        if (!confirm('Reset the in-memory database? All tables and data will be lost (your SQL code is kept).')) return;
        resetDB();
        var tree = $id('mlp-sq-schema-tree'); if (tree) tree.innerHTML = '<div class="sq-tree-empty">Database cleared</div>';
        var body = $id('mlp-sq-results-body'); if (body) body.innerHTML = '<div class="sq-results-msg">🗑 Database cleared</div>';
        setSqMeta(''); setSqStatus('Database cleared');
        sqToast('Database cleared', 'ok', 2000);
    });
    document.addEventListener('keydown', function(e) {
        var ov = $id('mlp-sql-overlay');
        if (!ov || !ov.classList.contains('mlp-sq-active')) return;
        if (e.key === 'Escape') { e.preventDefault(); if (ov.classList.contains('mlp-sq-fullscreen')) toggleSqFullscreen(); else closeSQLEditor(); }
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'F' || e.key === 'f')) { e.preventDefault(); toggleSqFullscreen(); }
    });
});

/* ── Public API ──────────────────────────────────────────────── */
window.mlpOpenSQLEditor  = openSQLEditor;
window.mlpCloseSQLEditor = closeSQLEditor;

/* ── Hook into mlpOpenProjectInEditor ────────────────────────── */
(function hookProjectOpen() {
    var tries = 0;
    var t = setInterval(function() {
        if (typeof window.mlpOpenProjectInEditor === 'function' && !window._mlpSqlHooked) {
            var _prev = window.mlpOpenProjectInEditor;
            window.mlpOpenProjectInEditor = function(p) {
                if (p && p.type === 'sql') {
                    var po = document.getElementById('mlp-projects-overlay');
                    if (po) po.style.display = 'none';
                    openSQLEditor(p.id);
                } else { _prev(p); }
            };
            window._mlpSqlHooked = true;
            clearInterval(t);
        }
        if (++tries > 120) clearInterval(t);
    }, 200);
})();

})();
</script>
        <?php
    }
}
