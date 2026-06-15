<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class MLP_Lua {
    public static function init() {
        add_action( 'wp_head',   [ __CLASS__, 'output_styles' ], 99 );
        add_action( 'wp_footer', [ __CLASS__, 'output_editor' ],  7 );
    }

    public static function output_styles() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) return;
        ?>
<style id="mlp-lua-styles">
/* ── Lua Editor Overlay ──────────────────────────────────────── */
:root {
    --lu-bg:        #0b1a0f;
    --lu-surface:   #0f2214;
    --lu-surface2:  #163020;
    --lu-border:    #1e4a28;
    --lu-accent:    #22c55e;
    --lu-accent2:   #4ade80;
    --lu-text:      #dcfce7;
    --lu-muted:     #4a8060;
    --lu-success:   #22c55e;
    --lu-error:     #f87171;
    --lu-warn:      #fbbf24;
    --lu-font:      'JetBrains Mono','Fira Code','Consolas',monospace;
}
#mlp-lua-overlay {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 99999;
    background: var(--lu-bg);
    flex-direction: column;
    font-family: var(--lu-font);
    overflow: hidden;
}
#mlp-lua-overlay.mlp-lu-active { display: flex; }

/* Topbar */
#mlp-lu-topbar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 14px;
    height: 46px;
    background: var(--lu-surface);
    border-bottom: 1px solid var(--lu-border);
    flex-shrink: 0;
    overflow-x: auto;
    overflow-y: hidden;
}
#mlp-lu-back {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 11px;
    background: transparent;
    border: 1px solid var(--lu-border);
    border-radius: 6px;
    color: var(--lu-muted);
    font-size: .75rem;
    font-weight: 600;
    cursor: pointer;
    font-family: inherit;
    transition: border-color .15s, color .15s;
    white-space: nowrap;
    flex-shrink: 0;
}
#mlp-lu-back:hover { border-color: var(--lu-accent); color: var(--lu-accent); }
#mlp-lu-title {
    flex: 1;
    font-size: .83rem;
    font-weight: 700;
    color: var(--lu-text);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
}
#mlp-lu-title span {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    background: rgba(34,197,94,.15);
    color: var(--lu-accent2);
    border-radius: 4px;
    font-size: .62rem;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    margin-left: 8px;
}
.mlp-lu-btn {
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
.mlp-lu-btn:disabled { opacity: .45; cursor: not-allowed; }
#mlp-lu-run {
    background: linear-gradient(135deg, #16a34a, #15803d);
    color: #fff;
    box-shadow: 0 1px 8px rgba(34,197,94,.35);
}
#mlp-lu-run:hover:not(:disabled) { opacity: .88; }
#mlp-lu-save, #mlp-lu-export, #mlp-lu-clear-out, #mlp-lu-fs-btn {
    background: transparent;
    border-color: var(--lu-border);
    color: var(--lu-muted);
}
#mlp-lu-save:hover:not(:disabled)      { border-color: var(--lu-accent);  color: var(--lu-accent); }
#mlp-lu-export:hover:not(:disabled)    { border-color: var(--lu-accent2); color: var(--lu-accent2); }
#mlp-lu-clear-out:hover:not(:disabled) { border-color: var(--lu-error);   color: var(--lu-error); }
#mlp-lu-fs-btn:hover { border-color: var(--lu-accent); color: var(--lu-accent); }
#mlp-lu-fs-btn { padding: 5px 9px; }

/* Floating AI Chat FAB */
#mlp-lu-chat-fab {
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
    font-family: var(--lu-font);
    font-size: .75rem;
    font-weight: 700;
    letter-spacing: .02em;
    white-space: nowrap;
    box-shadow: 0 4px 18px rgba(34,197,94,.45), 0 1px 4px rgba(0,0,0,.4);
    transition: opacity .18s, transform .18s;
}
#mlp-lu-chat-fab:hover { opacity: .9; transform: translateY(-2px); }
#mlp-lu-chat-fab.mlp-lu-fab-hidden { opacity: 0; pointer-events: none; transform: translateY(6px); }

/* Fullscreen */
#mlp-lua-overlay.mlp-lu-fullscreen #mlp-lu-topbar,
#mlp-lua-overlay.mlp-lu-fullscreen #mlp-lu-statusbar { display: none !important; }
#mlp-lua-overlay.mlp-lu-fullscreen #mlp-lu-output-pane { display: none !important; }
#mlp-lua-overlay.mlp-lu-fullscreen #mlp-lu-h-resizer   { display: none !important; }

/* ── Main body ───────────────────────────────────────────────── */
#mlp-lu-body {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    min-height: 0;
}
#mlp-lu-editor-pane {
    flex: 0 0 60%;
    min-height: 80px;
    overflow: hidden;
}
#mlp-lu-editor { width: 100%; height: 100%; }

/* Horizontal resizer */
#mlp-lu-h-resizer {
    height: 6px;
    cursor: row-resize;
    background: var(--lu-border);
    flex-shrink: 0;
    transition: background .15s;
    position: relative;
}
#mlp-lu-h-resizer::after {
    content: '';
    position: absolute;
    left: 50%; top: 50%;
    transform: translate(-50%, -50%);
    width: 32px; height: 2px;
    background: var(--lu-muted);
    border-radius: 1px;
}
#mlp-lu-h-resizer:hover, #mlp-lu-h-resizer.lu-dragging { background: var(--lu-accent); }

/* Output pane */
#mlp-lu-output-pane {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    min-height: 60px;
}
#mlp-lu-output-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 14px;
    height: 30px;
    background: var(--lu-surface2);
    border-top: 1px solid var(--lu-border);
    flex-shrink: 0;
}
#mlp-lu-output-title {
    font-size: .65rem;
    font-weight: 700;
    color: var(--lu-muted);
    text-transform: uppercase;
    letter-spacing: .08em;
    display: flex;
    align-items: center;
    gap: 6px;
}
#mlp-lu-output-meta {
    font-size: .65rem;
    color: var(--lu-muted);
}
#mlp-lu-output-body {
    flex: 1;
    overflow-y: auto;
    padding: 10px 14px;
    font-family: var(--lu-font);
    font-size: .78rem;
    line-height: 1.6;
    background: var(--lu-bg);
}
.lu-out-empty {
    color: var(--lu-muted);
    font-style: italic;
    font-size: .75rem;
}
.lu-out-line {
    color: var(--lu-text);
    white-space: pre-wrap;
    word-break: break-all;
}
.lu-out-error {
    color: var(--lu-error);
    white-space: pre-wrap;
    word-break: break-all;
}
.lu-out-info {
    color: var(--lu-muted);
    font-style: italic;
}
.lu-out-time {
    color: var(--lu-muted);
    font-size: .65rem;
    margin-top: 4px;
}

/* Status bar */
#mlp-lu-statusbar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 0 14px;
    height: 24px;
    background: var(--lu-surface2);
    border-top: 1px solid var(--lu-border);
    flex-shrink: 0;
    font-size: .65rem;
    color: var(--lu-muted);
}
#mlp-lu-status-lang { display: flex; align-items: center; gap: 5px; color: var(--lu-accent); }
#mlp-lu-status-msg  { flex: 1; }
#mlp-lu-status-pos  { margin-left: auto; }
#mlp-lu-status-save { color: var(--lu-warn); }

/* Toast */
#mlp-lu-toast {
    position: fixed;
    bottom: 24px; left: 50%; transform: translateX(-50%) translateY(12px);
    background: var(--lu-surface2);
    color: var(--lu-text);
    border: 1px solid var(--lu-border);
    border-radius: 8px;
    padding: 8px 18px;
    font-size: .75rem;
    font-weight: 600;
    font-family: var(--lu-font);
    z-index: 9999999;
    opacity: 0;
    pointer-events: none;
    transition: opacity .2s, transform .2s;
    white-space: nowrap;
}
#mlp-lu-toast.lu-show { opacity: 1; transform: translateX(-50%) translateY(0); }
#mlp-lu-toast.lu-err  { border-color: var(--lu-error); }
#mlp-lu-toast.lu-ok   { border-color: var(--lu-success); }

/* Spinner */
.lu-spinner {
    width: 12px; height: 12px;
    border: 2px solid rgba(255,255,255,.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: lu-spin .7s linear infinite;
    display: inline-block;
    flex-shrink: 0;
}
@keyframes lu-spin { to { transform: rotate(360deg); } }

/* ── AI Chat Sidebar ─────────────────────────────────────────── */
#mlp-lu-chat-sidebar {
    position: fixed;
    top: 56px; right: 12px; bottom: 20px;
    width: 360px;
    max-width: calc(96vw - 12px);
    z-index: 999991;
    background: var(--lu-bg);
    border: 1px solid var(--lu-border);
    border-radius: 10px;
    display: flex;
    flex-direction: column;
    font-family: var(--lu-font);
    transform: translateX(400px);
    transition: transform 0.25s cubic-bezier(0.4,0,0.2,1);
    box-shadow: -4px 8px 40px rgba(0,0,0,.55), 0 0 0 1px rgba(34,197,94,.12), -8px 0 40px rgba(34,197,94,.1);
    overflow: hidden;
}
#mlp-lu-chat-sidebar.lu-chat-open { transform: translateX(0); }
#mlp-lu-chat-overlay {
    position: fixed; inset: 0;
    background: rgba(0,0,0,.3);
    z-index: 999990;
    opacity: 0; pointer-events: none;
    transition: opacity 0.25s cubic-bezier(0.4,0,0.2,1);
}
#mlp-lu-chat-overlay.lu-chat-open { opacity: 1; pointer-events: auto; }
#mlp-lu-chat-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 14px;
    background: var(--lu-surface);
    border-bottom: 1px solid var(--lu-border);
    flex-shrink: 0;
}
#mlp-lu-chat-title { font-size: .83rem; font-weight: 700; color: var(--lu-text); }
#mlp-lu-chat-close {
    background: none; border: none; color: var(--lu-muted);
    cursor: pointer; padding: 4px; display: flex; align-items: center;
    transition: color .15s;
}
#mlp-lu-chat-close:hover { color: var(--lu-text); }
#mlp-lu-chat-messages {
    flex: 1; overflow-y: auto;
    padding: 12px; display: flex; flex-direction: column; gap: 10px;
}
.lu-chat-msg {
    padding: 8px 10px; border-radius: 6px;
    font-size: .75rem; line-height: 1.5;
    max-width: 95%; word-wrap: break-word;
}
.lu-chat-msg.user      { background: #0c2a16; color: #86efac; align-self: flex-end; margin-left: auto; }
.lu-chat-msg.assistant { background: #0f2214; color: #d4d4d4; align-self: flex-start; }
.lu-chat-empty {
    display: flex; align-items: center; justify-content: center;
    height: 100%; color: var(--lu-muted);
    font-size: .73rem; text-align: center; padding: 20px;
}
#mlp-lu-chat-input-area {
    display: flex; flex-direction: column; gap: 8px;
    padding: 10px;
    background: var(--lu-surface);
    border-top: 1px solid var(--lu-border);
    flex-shrink: 0;
}
#mlp-lu-chat-input {
    width: 100%; padding: 8px;
    background: rgba(0,0,0,.3);
    border: 1px solid var(--lu-border);
    border-radius: 4px; color: var(--lu-text);
    font-family: inherit; font-size: .75rem;
    resize: none; max-height: 80px;
    transition: border-color .15s;
}
#mlp-lu-chat-input:focus { outline: none; border-color: var(--lu-accent); }
#mlp-lu-chat-send {
    align-self: flex-end; padding: 5px 12px;
    background: #16a34a; color: #fff;
    border: none; border-radius: 4px;
    cursor: pointer; font-size: .73rem; font-weight: 600;
    transition: opacity .15s; font-family: inherit;
}
#mlp-lu-chat-send:hover:not(:disabled) { opacity: .88; }
#mlp-lu-chat-send:disabled { opacity: .5; cursor: not-allowed; }

/* Chat code blocks */
.lu-chat-code-wrap   { margin: 6px 0 0; border-radius: 6px; overflow: hidden; border: 1px solid var(--lu-border); background: #050d0a; max-width: 100%; }
.lu-chat-code-header { display: flex; align-items: center; justify-content: space-between; padding: 4px 10px; background: var(--lu-surface2); border-bottom: 1px solid var(--lu-border); }
.lu-chat-code-lang   { font-size: .62rem; font-weight: 700; color: var(--lu-accent2); letter-spacing: .06em; text-transform: uppercase; }
.lu-chat-code-actions { display: flex; gap: 5px; }
.lu-chat-code-apply, .lu-chat-code-copy {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 4px;
    font-family: inherit; font-size: .65rem; font-weight: 700;
    cursor: pointer; border: 1px solid transparent;
    transition: opacity .15s, background .15s;
}
.lu-chat-code-apply { background: #16a34a; color: #fff; }
.lu-chat-code-apply:hover { opacity: .85; }
.lu-chat-code-apply.lu-applied { background: #15803d; }
.lu-chat-code-copy  { background: transparent; border-color: #2a3a2e; color: #888; }
.lu-chat-code-copy:hover { color: #d4d4d4; border-color: #445; }
.lu-chat-code-pre   { margin: 0; padding: 10px 12px; overflow-x: auto; font-family: var(--lu-font); font-size: .73rem; line-height: 1.6; color: #d4d4d4; white-space: pre; background: transparent; }
.lu-chat-undo-btn {
    display: inline-flex; align-items: center; gap: 4px; margin-top: 4px;
    padding: 2px 8px; background: transparent; border: 1px solid #3a3a3a;
    border-radius: 4px; color: var(--lu-warn);
    font-family: inherit; font-size: .65rem; font-weight: 700; cursor: pointer;
    transition: opacity .15s;
}
.lu-chat-undo-btn:hover { opacity: .8; }

/* Markdown */
.lu-chat-msg.assistant .lu-md-code { font-family: var(--lu-font); font-size: .72rem; background: rgba(0,0,0,.35); border: 1px solid var(--lu-border); border-radius: 3px; padding: 0 4px; color: var(--lu-warn); }
.lu-chat-msg.assistant .lu-md-h2   { display: block; font-size: .85rem; font-weight: 700; color: #86efac; margin: 8px 0 3px; padding-bottom: 3px; border-bottom: 1px solid #1a2e1e; }
.lu-chat-msg.assistant .lu-md-h3   { display: block; font-size: .78rem; font-weight: 700; color: #a7f3d0; margin: 6px 0 2px; }
.lu-chat-msg.assistant strong { color: var(--lu-text); font-weight: 700; }
.lu-chat-msg.assistant em     { color: #d1d5db; font-style: italic; }

/* Thinking animation */
.lu-thinking-bubble { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: #0f2214; border-radius: 6px; border: 1px solid rgba(34,197,94,.15); align-self: flex-start; max-width: 95%; }
.lu-thinking-label  { font-size: .68rem; color: var(--lu-muted); font-style: italic; white-space: nowrap; }
@keyframes lu-dot-wave { 0%,100%{transform:translateY(0);opacity:.35} 50%{transform:translateY(-6px);opacity:1} }
@keyframes lu-dot-glow { 0%,100%{filter:drop-shadow(0 0 0px #22c55e)} 50%{filter:drop-shadow(0 0 5px #22c55e)} }
.lu-think-dot { animation: lu-dot-wave 1.3s ease-in-out infinite, lu-dot-glow 1.3s ease-in-out infinite; }
.lu-think-dot:nth-child(2) { animation-delay: .22s; }
.lu-think-dot:nth-child(3) { animation-delay: .44s; }
@keyframes lu-ring-pulse { 0%,100%{opacity:.18;r:14} 50%{opacity:.45;r:16} }
.lu-think-ring { animation: lu-ring-pulse 1.3s ease-in-out infinite; transform-origin: center; }

/* Hide HTML chat / Python FAB when Lua editor is active */
html.mlp-lu-editor-active #mlpChatToggle,
html.mlp-lu-editor-active #mlpChatSidebar,
html.mlp-lu-editor-active #mlp-py-chat-fab,
html.mlp-lu-editor-active #mlp-sq-chat-fab { display: none !important; }
</style>
        <?php
    }

    public static function output_editor() {
        global $post;
        if ( ! is_a( $post, 'WP_Post' ) || ! has_shortcode( $post->post_content, 'mobile_live_preview' ) ) return;
        ?>
<!-- ── Lua Editor Overlay ─────────────────────────────────────── -->
<div id="mlp-lua-overlay" role="dialog" aria-modal="true" aria-label="Lua Editor">

  <!-- Topbar -->
  <div id="mlp-lu-topbar">
    <button id="mlp-lu-back" type="button" aria-label="Back to projects">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      Projects
    </button>
    <div id="mlp-lu-title">
      <span id="mlp-lu-name">Untitled</span>
      <span>
        <svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor" style="opacity:.8"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15v-4H7l5-8v4h4l-5 8z"/></svg>
        Lua
      </span>
    </div>
    <button id="mlp-lu-run" class="mlp-lu-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
      Run
    </button>
    <button id="mlp-lu-save" class="mlp-lu-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
      Save
    </button>
    <button id="mlp-lu-export" class="mlp-lu-btn" type="button">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Export .lua
    </button>
    <button id="mlp-lu-clear-out" class="mlp-lu-btn" type="button" title="Clear the output console">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-4.66"/></svg>
      Clear
    </button>
    <button id="mlp-lu-fs-btn" class="mlp-lu-btn" type="button" title="Toggle fullscreen (Ctrl+Shift+F)">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
    </button>
  </div>

  <!-- Body: editor + output -->
  <div id="mlp-lu-body">
    <div id="mlp-lu-editor-pane">
      <div id="mlp-lu-editor"></div>
    </div>
    <div id="mlp-lu-h-resizer" role="separator" aria-orientation="horizontal" aria-label="Resize output panel"></div>
    <div id="mlp-lu-output-pane">
      <div id="mlp-lu-output-header">
        <span id="mlp-lu-output-title">
          <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline;margin-right:3px;vertical-align:middle;"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          Output
        </span>
        <span id="mlp-lu-output-meta"></span>
      </div>
      <div id="mlp-lu-output-body">
        <div class="lu-out-empty">Press ▶ Run or Ctrl+Enter to run your Lua script</div>
      </div>
    </div>
  </div>

  <!-- Status bar -->
  <div id="mlp-lu-statusbar">
    <span id="mlp-lu-status-lang">
      <svg width="8" height="8" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>
      Lua 5.4
    </span>
    <span id="mlp-lu-status-msg"></span>
    <span id="mlp-lu-status-pos">Ln 1, Col 1</span>
    <span id="mlp-lu-status-save"></span>
  </div>
</div>

<!-- Lua AI Chat Sidebar -->
<div id="mlp-lu-chat-overlay"></div>
<div id="mlp-lu-chat-sidebar">
  <div id="mlp-lu-chat-header">
    <div id="mlp-lu-chat-title">Lua AI Chat</div>
    <button id="mlp-lu-chat-close" type="button" title="Close chat">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>
  <div id="mlp-lu-chat-messages">
    <div class="lu-chat-empty">Ask the Lua AI assistant about your scripts</div>
  </div>
  <div id="mlp-lu-chat-input-area">
    <textarea id="mlp-lu-chat-input" placeholder="Ask about Lua, tables, coroutines, metatables…" rows="2"></textarea>
    <button id="mlp-lu-chat-send" type="button">Send</button>
  </div>
</div>

<!-- Toast -->
<div id="mlp-lu-toast"></div>

<!-- Floating AI Chat FAB -->
<button id="mlp-lu-chat-fab" class="mlp-lu-fab-hidden" type="button" aria-label="Open Lua AI Chat">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
  AI Chat
</button>

<script>
(function(){
'use strict';

/* ── Config ──────────────────────────────────────────────────── */
var FENGARI_URL    = 'https://cdn.jsdelivr.net/npm/fengari-web@0.1.4/dist/fengari-web.js';
var MLP_LS         = 'mlp_projects';
var MLP_LU_TS_KEY  = <?php echo json_encode( defined( 'MLP_TURNSTILE_SITE_KEY' ) ? MLP_TURNSTILE_SITE_KEY : '' ); ?>;

/* ── Lua AI Chat ─────────────────────────────────────────────── */
var _luChatHistories = {};
var _luChatBusy      = false;
var _luChatAbort     = null;
var _luTsToken       = '';
var _luTsVerified    = false;
var _luTsPending     = '';
var _luTsWidgetId    = null;
var _luTsWidgetEl    = null;
var _luUndoStack     = [];
var _luThinkingEl    = null;

function _getLuChatKey(id) { return 'mlp_lu_chat_' + (id || 'default'); }

function _getLuChatHistory(key) {
    if (!_luChatHistories[key]) {
        try { _luChatHistories[key] = JSON.parse(localStorage.getItem(key)) || []; }
        catch(e) { _luChatHistories[key] = []; }
    }
    return _luChatHistories[key];
}
function _saveLuChatHistory(key, h) {
    _luChatHistories[key] = h;
    try { localStorage.setItem(key, JSON.stringify(h)); } catch(e) {}
}

function _openLuChat() {
    var s = $id('mlp-lu-chat-sidebar'), o = $id('mlp-lu-chat-overlay'), f = $id('mlp-lu-chat-fab');
    if (s) s.classList.add('lu-chat-open');
    if (o) o.classList.add('lu-chat-open');
    if (f) f.classList.add('mlp-lu-fab-hidden');
    var inp = $id('mlp-lu-chat-input');
    if (inp) setTimeout(function(){ inp.focus(); }, 100);
}
function _closeLuChat() {
    var s = $id('mlp-lu-chat-sidebar'), o = $id('mlp-lu-chat-overlay'), f = $id('mlp-lu-chat-fab');
    if (s) s.classList.remove('lu-chat-open');
    if (o) o.classList.remove('lu-chat-open');
    if (f) f.classList.remove('mlp-lu-fab-hidden');
}

function _applyLuaToEditor(code, btn) {
    if (!luEditor) return;
    var prev = luEditor.getValue();
    _luUndoStack.push(prev);
    luEditor.setValue(code);
    luEditor.setScrollPosition({ scrollTop: 0 });
    _luUnsaved = true;
    setLuSave('● Unsaved');
    if (btn) {
        btn.textContent = '✓ Applied';
        btn.classList.add('lu-applied');
        if (btn.parentNode && !btn.parentNode.querySelector('.lu-chat-undo-btn')) {
            var u = document.createElement('button');
            u.className = 'lu-chat-undo-btn'; u.type = 'button'; u.innerHTML = '↩ Undo';
            u.addEventListener('click', function() {
                var prev2 = _luUndoStack.pop();
                if (prev2 !== undefined) { luEditor.setValue(prev2); luEditor.setScrollPosition({ scrollTop: 0 }); _luUnsaved = true; setLuSave('● Unsaved'); }
                btn.textContent = '▶ Apply'; btn.classList.remove('lu-applied');
                u.parentNode && u.parentNode.removeChild(u);
            });
            btn.parentNode.appendChild(u);
        }
    }
}

function _buildLuCodeBlock(lang, code) {
    var wrap = document.createElement('div'); wrap.className = 'lu-chat-code-wrap';
    var hdr  = document.createElement('div'); hdr.className  = 'lu-chat-code-header';
    var lbl  = document.createElement('span'); lbl.className = 'lu-chat-code-lang'; lbl.textContent = lang || 'lua';
    var acts = document.createElement('div'); acts.className = 'lu-chat-code-actions';
    var cp   = document.createElement('button'); cp.className = 'lu-chat-code-copy'; cp.type = 'button'; cp.textContent = 'Copy';
    cp.addEventListener('click', function() {
        navigator.clipboard && navigator.clipboard.writeText(code).then(function(){ cp.textContent = '✓ Copied'; setTimeout(function(){ cp.textContent = 'Copy'; }, 1800); });
    });
    var ap = document.createElement('button'); ap.className = 'lu-chat-code-apply'; ap.type = 'button'; ap.textContent = '▶ Apply';
    ap.addEventListener('click', function() { _applyLuaToEditor(code, ap); });
    acts.appendChild(cp); acts.appendChild(ap);
    hdr.appendChild(lbl); hdr.appendChild(acts);
    var pre = document.createElement('pre'); pre.className = 'lu-chat-code-pre'; pre.textContent = code;
    wrap.appendChild(hdr); wrap.appendChild(pre);
    return wrap;
}

function _showLuThinking() {
    _hideLuThinking();
    var msgs = $id('mlp-lu-chat-messages');
    if (!msgs) return;
    var em = msgs.querySelector('.lu-chat-empty'); if (em) msgs.innerHTML = '';
    var b = document.createElement('div'); b.className = 'lu-thinking-bubble';
    b.innerHTML = '<svg width="38" height="16" viewBox="0 0 38 16" fill="none"><defs><radialGradient id="lu-tg1" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="#4ade80"/><stop offset="100%" stop-color="#22c55e"/></radialGradient></defs><circle class="lu-think-ring" cx="7" cy="8" r="14" fill="#22c55e"/><circle class="lu-think-dot" cx="7" cy="8" r="3.5" fill="url(#lu-tg1)"/><circle class="lu-think-dot" cx="19" cy="8" r="3.5" fill="url(#lu-tg1)"/><circle class="lu-think-dot" cx="31" cy="8" r="3.5" fill="url(#lu-tg1)"/></svg><span class="lu-thinking-label">AI is thinking…</span>';
    msgs.appendChild(b); msgs.scrollTop = msgs.scrollHeight;
    _luThinkingEl = b;
}
function _hideLuThinking() {
    if (_luThinkingEl && _luThinkingEl.parentNode) _luThinkingEl.parentNode.removeChild(_luThinkingEl);
    _luThinkingEl = null;
}

function _renderMdInlineLu(text) {
    var frag = document.createDocumentFragment();
    var re = /(`[^`]+`|\*\*[\s\S]+?\*\*|\*[^*\n]+?\*)/g;
    var last = 0, m;
    while ((m = re.exec(text)) !== null) {
        if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        var tok = m[0];
        if (tok.startsWith('**')) { var s = document.createElement('strong'); s.textContent = tok.slice(2,-2); frag.appendChild(s); }
        else if (tok.startsWith('`')) { var c = document.createElement('code'); c.className = 'lu-md-code'; c.textContent = tok.slice(1,-1); frag.appendChild(c); }
        else { var e = document.createElement('em'); e.textContent = tok.slice(1,-1); frag.appendChild(e); }
        last = m.index + tok.length;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    return frag;
}

function _appendLuChatMsg(role, text) {
    var msgs = $id('mlp-lu-chat-messages');
    if (!msgs) return;
    var em = msgs.querySelector('.lu-chat-empty'); if (em) msgs.innerHTML = '';
    var b = document.createElement('div'); b.className = 'lu-chat-msg ' + role;
    if (role === 'assistant') {
        var parts = text.split(/(```[\w]*\n[\s\S]*?```)/g);
        parts.forEach(function(part) {
            var fence = part.match(/^```([\w]*)\n([\s\S]*?)```$/);
            if (fence) {
                b.appendChild(_buildLuCodeBlock(fence[1] || 'lua', fence[2].replace(/\n$/, '')));
            } else if (part.trim()) {
                var lines = part.split('\n');
                lines.forEach(function(line, i) {
                    if (/^### /.test(line))      { var h = document.createElement('span'); h.className = 'lu-md-h3'; h.appendChild(_renderMdInlineLu(line.slice(4))); b.appendChild(h); }
                    else if (/^## /.test(line))  { var h = document.createElement('span'); h.className = 'lu-md-h2'; h.appendChild(_renderMdInlineLu(line.slice(3))); b.appendChild(h); }
                    else if (/^# /.test(line))   { var h = document.createElement('span'); h.className = 'lu-md-h2'; h.appendChild(_renderMdInlineLu(line.slice(2))); b.appendChild(h); }
                    else if (line)               { var sp = document.createElement('span'); sp.appendChild(_renderMdInlineLu(line)); b.appendChild(sp); }
                    if (i < lines.length - 1) b.appendChild(document.createElement('br'));
                });
            }
        });
    } else { b.textContent = text; }
    msgs.appendChild(b); msgs.scrollTop = msgs.scrollHeight;
}

function _sendLuChat() {
    if (_luChatBusy) return;
    var inp  = $id('mlp-lu-chat-input');
    var text = _luTsPending || (inp && inp.value.trim());
    if (!text) return;
    _luTsPending = '';
    if (inp) inp.value = '';
    if (!_luTsVerified) {
        _luTsPending = text;
        _appendLuChatMsg('user', text);
        _appendLuChatMsg('assistant', 'Please complete the verification to continue.');
        _renderLuTurnstile();
        return;
    }
    var key = _getLuChatKey(_luActiveId);
    var hist = _getLuChatHistory(key);
    hist.push({ role: 'user', content: text });
    _saveLuChatHistory(key, hist);
    _appendLuChatMsg('user', text);
    _luChatBusy = true;
    _showLuThinking();
    var luaCode = luEditor ? luEditor.getValue() : '';
    var fd = new FormData();
    fd.append('action', 'mlp_ai_chat_lua');
    fd.append('nonce', (window.mlp_ajax && window.mlp_ajax.nonce) ? window.mlp_ajax.nonce : '');
    fd.append('message', text);
    fd.append('lua_code', luaCode);
    fd.append('turnstile_token', _luTsToken);
    fd.append('history', JSON.stringify(hist.slice(-12, -1)));
    var url = (window.mlp_ajax && window.mlp_ajax.ajaxurl) ? window.mlp_ajax.ajaxurl : '/wp-admin/admin-ajax.php';
    _luChatAbort = new AbortController();
    fetch(url, { method: 'POST', body: fd, signal: _luChatAbort.signal })
        .then(function(r){ return r.json(); })
        .then(function(data) {
            _hideLuThinking();
            var h = _getLuChatHistory(key);
            if (data.success && data.data && data.data.reply) {
                h.push({ role: 'assistant', content: data.data.reply });
                _saveLuChatHistory(key, h);
                _appendLuChatMsg('assistant', data.data.reply);
            } else {
                var err = (data.data && data.data.message) ? data.data.message : 'AI unavailable. Try again later.';
                _appendLuChatMsg('assistant', '⚠ ' + err);
            }
        })
        .catch(function(err) {
            _hideLuThinking();
            if (err.name !== 'AbortError') _appendLuChatMsg('assistant', '⚠ Network error: ' + err.message);
        })
        .finally(function() { _luChatBusy = false; _hideLuThinking(); _removeLuTsWidget(); });
}

function _removeLuTsWidget() {
    if (_luTsWidgetId !== null && window.turnstile) { try { window.turnstile.remove(_luTsWidgetId); } catch(e){} _luTsWidgetId = null; }
    if (_luTsWidgetEl && _luTsWidgetEl.parentNode) _luTsWidgetEl.parentNode.removeChild(_luTsWidgetEl);
    _luTsWidgetEl = null;
}

function _renderLuTurnstile() {
    if (!MLP_LU_TS_KEY) return;
    _removeLuTsWidget();
    var msgs = $id('mlp-lu-chat-messages'); if (!msgs) return;
    var cont = document.createElement('div'); cont.style.cssText = 'padding:6px 0;display:flex;justify-content:center;';
    var wd = document.createElement('div'); cont.appendChild(wd); msgs.appendChild(cont); msgs.scrollTop = msgs.scrollHeight;
    _luTsWidgetEl = cont;
    function doRender() {
        if (!window.turnstile || !window.turnstile.render) return;
        _luTsWidgetId = window.turnstile.render(wd, {
            sitekey: MLP_LU_TS_KEY, theme: 'dark',
            callback: function(tok){ _luTsToken = tok; _luTsVerified = true; setTimeout(_sendLuChat, 300); },
            'error-callback': function(){ _luTsVerified = false; _luTsToken = ''; }
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
var luEditor      = null;
var luMonacoReady = false;
var _luActiveId   = null;
var _luUnsaved    = false;
var _fengari      = null;
var _fengariProm  = null;

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
var _luToastT = null;
function luToast(msg, type, ms) {
    var el = $id('mlp-lu-toast'); if (!el) return;
    el.textContent = msg;
    el.className = 'lu-show' + (type === 'err' ? ' lu-err' : type === 'ok' ? ' lu-ok' : '');
    clearTimeout(_luToastT);
    _luToastT = setTimeout(function(){ el.className = ''; }, ms || 2500);
}

/* ── Status helpers ──────────────────────────────────────────── */
function setLuStatus(m) { var el = $id('mlp-lu-status-msg');    if (el) el.textContent = m || ''; }
function setLuSave(m)   { var el = $id('mlp-lu-status-save');   if (el) el.textContent = m || ''; }
function setLuMeta(m)   { var el = $id('mlp-lu-output-meta');   if (el) el.textContent = m || ''; }

/* ── Ensure Fengari loaded ───────────────────────────────────── */
function ensureFengari() {
    if (_fengari) return Promise.resolve(_fengari);
    if (_fengariProm) return _fengariProm;
    _fengariProm = new Promise(function(resolve, reject) {
        var sc = document.createElement('script');
        sc.src = FENGARI_URL;
        /* WordPress / RequireJS sites expose window.define with define.amd=true.
         * fengari-web's UMD bundle detects this and registers via AMD instead of
         * setting window.fengari, so the global is never created.
         * Fix: temporarily remove define before loading, restore it after. */
        var _savedDefine = (typeof window.define === 'function' && window.define.amd) ? window.define : null;
        if (_savedDefine) window.define = undefined;
        function _restoreDefine() { if (_savedDefine) window.define = _savedDefine; }
        function _resolveFg() {
            _restoreDefine();
            /* Try window.fengari first, then bare global as fallback */
            var fg = window.fengari;
            if (!fg) { try { fg = fengari; } catch(e) {} } // eslint-disable-line no-undef
            if (fg && fg.lua && fg.lauxlib) {
                _fengari = fg;
                window.fengari = fg; /* ensure it's on window for future checks */
                resolve(_fengari);
            } else {
                _fengariProm = null;
                reject(new Error('Fengari loaded but window.fengari not found. Check CDN.'));
            }
        }
        sc.onload  = _resolveFg;
        sc.onerror = function() { _restoreDefine(); _fengariProm = null; reject(new Error('Failed to load Fengari. Check your internet connection.')); };
        document.head.appendChild(sc);
    });
    return _fengariProm;
}

/* ── Render output ───────────────────────────────────────────── */
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function renderLuaOutput(lines, errorMsg, timeMs) {
    var body = $id('mlp-lu-output-body'); if (!body) return;
    body.innerHTML = '';
    if (errorMsg) {
        var errDiv = document.createElement('div'); errDiv.className = 'lu-out-error';
        errDiv.textContent = '✗ ' + errorMsg;
        body.appendChild(errDiv);
        setLuMeta('Error');
        setLuStatus('Error');
        return;
    }
    if (lines.length === 0) {
        var info = document.createElement('div'); info.className = 'lu-out-info';
        info.textContent = '(no output)';
        body.appendChild(info);
    } else {
        lines.forEach(function(line) {
            var d = document.createElement('div'); d.className = 'lu-out-line';
            d.textContent = line;
            body.appendChild(d);
        });
    }
    if (timeMs !== undefined) {
        var t = document.createElement('div'); t.className = 'lu-out-time';
        t.textContent = '✓ Done in ' + timeMs + 'ms';
        body.appendChild(t);
        setLuMeta(timeMs + 'ms');
        setLuStatus('✓ Done in ' + timeMs + 'ms');
    }
    body.scrollTop = body.scrollHeight;
}

/* ── Run ─────────────────────────────────────────────────────── */
function runLua() {
    if (!luEditor) return;
    var code = luEditor.getValue().trim();
    if (!code) {
        var body = $id('mlp-lu-output-body');
        if (body) body.innerHTML = '<div class="lu-out-info">⚠ Nothing to run</div>';
        return;
    }
    var runBtn = $id('mlp-lu-run');
    if (runBtn) { runBtn.innerHTML = '<span class="lu-spinner"></span> Running…'; runBtn.disabled = true; }
    setLuStatus('Loading Fengari…');

    ensureFengari()
        .then(function(fg) {
            var t0 = Date.now();
            var outputLines = [];
            var errorMsg    = null;

            try {
                var L = fg.lauxlib.luaL_newstate();
                fg.lualib.luaL_openlibs(L);

                /* Override print to capture output */
                fg.lua.lua_register(L, fg.to_luastring('print'), function(L2) {
                    var n = fg.lua.lua_gettop(L2);
                    var parts = [];
                    for (var i = 1; i <= n; i++) {
                        try {
                            fg.lauxlib.luaL_tolstring(L2, i, null);
                            var s = fg.lua.lua_tojsstring(L2, -1);
                            parts.push(s !== null && s !== undefined ? s : '');
                            fg.lua.lua_pop(L2, 1);
                        } catch(e) { parts.push('?'); }
                    }
                    outputLines.push(parts.join('\t'));
                    return 0;
                });

                /* Override io.write to capture output */
                fg.lua.lua_getglobal(L, fg.to_luastring('io'));
                if (fg.lua.lua_istable(L, -1)) {
                    fg.lua.lua_pushstring(L, fg.to_luastring('write'));
                    fg.lua.lua_pushcfunction(L, function(L2) {
                        var n = fg.lua.lua_gettop(L2);
                        var parts = [];
                        for (var i = 1; i <= n; i++) {
                            var s = fg.lua.lua_tojsstring(L2, i);
                            parts.push(s !== null && s !== undefined ? s : '');
                        }
                        var joined = parts.join('');
                        if (outputLines.length > 0 && !outputLines[outputLines.length-1].endsWith('\n')) {
                            outputLines[outputLines.length-1] += joined;
                        } else {
                            outputLines.push(joined);
                        }
                        return 0;
                    });
                    fg.lua.lua_settable(L, -3);
                }
                fg.lua.lua_pop(L, 1);

                var ok = fg.lauxlib.luaL_dostring(L, fg.to_luastring(code));
                if (ok !== fg.lua.LUA_OK) {
                    errorMsg = fg.lua.lua_tojsstring(L, -1) || 'Runtime error';
                }
                fg.lua.lua_close(L);
            } catch(e) {
                errorMsg = (e && e.message) ? e.message : String(e);
            }

            /* Split any lines that contain embedded newlines */
            var flatLines = [];
            outputLines.forEach(function(line) {
                line.split('\n').forEach(function(l) { flatLines.push(l); });
            });
            /* Remove trailing empty line from io.write patterns */
            while (flatLines.length > 0 && flatLines[flatLines.length-1] === '') flatLines.pop();

            var ms = Date.now() - t0;
            renderLuaOutput(flatLines, errorMsg, errorMsg ? undefined : ms);
            if (runBtn) { runBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run'; runBtn.disabled = false; }
        })
        .catch(function(err) {
            var body = $id('mlp-lu-output-body');
            if (body) { body.innerHTML = ''; var d = document.createElement('div'); d.className = 'lu-out-error'; d.textContent = '✗ ' + ((err && err.message) ? err.message : String(err)); body.appendChild(d); }
            setLuStatus('Failed to load Fengari');
            if (runBtn) { runBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Run'; runBtn.disabled = false; }
        });
}

/* ── Save ────────────────────────────────────────────────────── */
function saveLuaProject() {
    if (!_luActiveId) return;
    var code = luEditor ? luEditor.getValue() : '';
    updateProject(_luActiveId, { lua: code, type: 'lua', updatedAt: new Date().toISOString() });
    _luUnsaved = false;
    setLuSave('Saved ' + new Date().toLocaleTimeString());
    luToast('Project saved', 'ok', 1800);
}

/* ── Export .lua ─────────────────────────────────────────────── */
function exportLuaProject() {
    var code = luEditor ? luEditor.getValue() : '';
    var p    = _luActiveId ? getProject(_luActiveId) : null;
    var name = (p && p.name) ? p.name.replace(/[^a-z0-9_\-]/gi, '_') : 'lua_project';
    var blob = new Blob([code], { type: 'text/plain' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a');
    a.href = url; a.download = name + '.lua';
    document.body.appendChild(a); a.click();
    setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(url); }, 500);
    luToast('Exported ' + name + '.lua', 'ok', 2200);
}

/* ── Monaco ──────────────────────────────────────────────────── */
function mountLuMonaco(code) {
    if (!window.monaco) return;
    var container = $id('mlp-lu-editor'); if (!container) return;
    if (luEditor) { luEditor.setValue(code); return; }
    luEditor = window.monaco.editor.create(container, {
        value:    code,
        language: 'lua',
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
    luEditor.onDidChangeCursorPosition(function(e) {
        var el = $id('mlp-lu-status-pos');
        if (el) el.textContent = 'Ln ' + e.position.lineNumber + ', Col ' + e.position.column;
    });
    luEditor.onDidChangeModelContent(function() { _luUnsaved = true; setLuSave('● Unsaved'); });
    luEditor.addCommand(window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.Enter, runLua);
    luEditor.addCommand(window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.KeyS, saveLuaProject);
}

function waitForMonacoThenMountLu(code) {
    var tries = 0;
    var t = setInterval(function() {
        if (window.monaco) { clearInterval(t); luMonacoReady = true; mountLuMonaco(code); return; }
        if (++tries > 60) clearInterval(t);
    }, 200);
}

/* ── Open / Close ─────────────────────────────────────────────── */
function openLuaEditor(projectId) {
    var p = getProject(projectId);
    if (!p || p.type !== 'lua') return;
    _luActiveId = projectId;
    _luUnsaved  = false;

    var nameEl = $id('mlp-lu-name'); if (nameEl) nameEl.textContent = p.name || 'Untitled';
    var overlay = $id('mlp-lua-overlay'); if (overlay) overlay.classList.add('mlp-lu-active');
    document.documentElement.classList.add('mlp-lu-editor-active');

    setLuSave(''); setLuStatus('Ready'); setLuMeta('');
    var body = $id('mlp-lu-output-body');
    if (body) body.innerHTML = '<div class="lu-out-empty">Press ▶ Run or Ctrl+Enter to run your Lua script</div>';

    var code = p.lua || '';
    if (luMonacoReady && window.monaco) { mountLuMonaco(code); }
    else { waitForMonacoThenMountLu(code); }

    /* Wire FAB and chat */
    var fab = $id('mlp-lu-chat-fab');
    if (fab) {
        fab.classList.remove('mlp-lu-fab-hidden');
        if (!fab._luWired) { fab.addEventListener('click', _openLuChat); fab._luWired = true; }
    }
    var chatClose   = $id('mlp-lu-chat-close');
    var chatSend    = $id('mlp-lu-chat-send');
    var chatInput   = $id('mlp-lu-chat-input');
    var chatOverlay = $id('mlp-lu-chat-overlay');
    if (chatClose)   chatClose.addEventListener('click', _closeLuChat);
    if (chatSend)    chatSend.addEventListener('click', _sendLuChat);
    if (chatOverlay) chatOverlay.addEventListener('click', _closeLuChat);
    if (chatInput) {
        chatInput.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); _sendLuChat(); }
        });
    }
}

function closeLuaEditor() {
    if (_luUnsaved && !confirm('You have unsaved changes. Leave without saving?')) return;
    var overlay = $id('mlp-lua-overlay');
    if (overlay) overlay.classList.remove('mlp-lu-active');
    _closeLuChat();
    var fab = $id('mlp-lu-chat-fab');
    if (fab) fab.classList.add('mlp-lu-fab-hidden');
    document.documentElement.classList.remove('mlp-lu-editor-active');
    _luActiveId = null;
    if (typeof window.mlpProjectsOpen === 'function') {
        window.mlpProjectsOpen();
    } else {
        var po = document.getElementById('mlp-projects-overlay');
        if (po) { po.classList.remove('mlp-proj-hidden'); po.style.display = ''; document.body.style.overflow = 'hidden'; }
    }
}

/* ── Resizer: editor ↔ output ────────────────────────────────── */
(function() {
    var hr = $id('mlp-lu-h-resizer'), ep = $id('mlp-lu-editor-pane'), body = $id('mlp-lu-body');
    if (hr && ep && body) {
        var hdrag = false, hy = 0, hh = 0;
        hr.addEventListener('mousedown', function(e) { hdrag = true; hy = e.clientY; hh = ep.getBoundingClientRect().height; hr.classList.add('lu-dragging'); document.body.style.cursor = 'row-resize'; document.body.style.userSelect = 'none'; e.preventDefault(); });
        document.addEventListener('mousemove', function(e) { if (!hdrag) return; var bh = body.getBoundingClientRect().height; var newH = Math.max(80, Math.min(bh * 0.85, hh + e.clientY - hy)); ep.style.flex = 'none'; ep.style.height = newH + 'px'; if (luEditor) luEditor.layout(); });
        document.addEventListener('mouseup', function() { if (!hdrag) return; hdrag = false; hr.classList.remove('lu-dragging'); document.body.style.cursor = ''; document.body.style.userSelect = ''; if (luEditor) luEditor.layout(); });
    }
})();

/* ── Fullscreen ──────────────────────────────────────────────── */
function toggleLuFullscreen() {
    var ov = $id('mlp-lua-overlay'); if (!ov) return;
    var fs = ov.classList.toggle('mlp-lu-fullscreen');
    var btn = $id('mlp-lu-fs-btn');
    if (btn) btn.innerHTML = fs
        ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="10" y1="14" x2="3" y2="21"/><line x1="21" y1="3" x2="14" y2="10"/></svg>'
        : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>';
    if (luEditor) setTimeout(function(){ luEditor.layout(); }, 50);
}

/* ── Wire buttons ────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
    var runBtn  = $id('mlp-lu-run');
    var saveBtn = $id('mlp-lu-save');
    var expBtn  = $id('mlp-lu-export');
    var clrBtn  = $id('mlp-lu-clear-out');
    var fsBtn   = $id('mlp-lu-fs-btn');
    var backBtn = $id('mlp-lu-back');
    if (runBtn)  runBtn.addEventListener('click',  runLua);
    if (saveBtn) saveBtn.addEventListener('click', saveLuaProject);
    if (expBtn)  expBtn.addEventListener('click',  exportLuaProject);
    if (fsBtn)   fsBtn.addEventListener('click',   toggleLuFullscreen);
    if (backBtn) backBtn.addEventListener('click', closeLuaEditor);
    if (clrBtn)  clrBtn.addEventListener('click', function() {
        var body = $id('mlp-lu-output-body');
        if (body) body.innerHTML = '<div class="lu-out-empty">Output cleared</div>';
        setLuMeta(''); setLuStatus('Output cleared');
        luToast('Output cleared', 'ok', 1800);
    });
    document.addEventListener('keydown', function(e) {
        var ov = $id('mlp-lua-overlay');
        if (!ov || !ov.classList.contains('mlp-lu-active')) return;
        if (e.key === 'Escape') { e.preventDefault(); if (ov.classList.contains('mlp-lu-fullscreen')) toggleLuFullscreen(); else closeLuaEditor(); }
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'F' || e.key === 'f')) { e.preventDefault(); toggleLuFullscreen(); }
    });
});

/* ── Public API ──────────────────────────────────────────────── */
window.mlpOpenLuaEditor  = openLuaEditor;
window.mlpCloseLuaEditor = closeLuaEditor;

/* ── Hook into mlpOpenProjectInEditor ────────────────────────── */
(function hookProjectOpen() {
    var tries = 0;
    var t = setInterval(function() {
        if (typeof window.mlpOpenProjectInEditor === 'function' && !window._mlpLuaHooked) {
            var _prev = window.mlpOpenProjectInEditor;
            window.mlpOpenProjectInEditor = function(p) {
                if (p && p.type === 'lua') {
                    var po = document.getElementById('mlp-projects-overlay');
                    if (po) po.style.display = 'none';
                    openLuaEditor(p.id);
                } else { _prev(p); }
            };
            window._mlpLuaHooked = true;
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
