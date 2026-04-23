<?php
if (!defined('ABSPATH')) {
    exit;
}

function mlp_render_console_html($instance_id) {
    $iid = esc_attr($instance_id);
    ?>
    <div class="mlp-console-modal" id="mlp-console-modal-<?php echo $iid; ?>" role="dialog" aria-label="Developer Console">
        <div class="mlp-console-panel" id="mlp-console-panel-<?php echo $iid; ?>">

            <!-- Resize handle (top edge) -->
            <div class="mlp-con-resize-handle" id="mlp-con-resize-<?php echo $iid; ?>"></div>

            <!-- Title bar -->
            <div class="mlp-con-titlebar" id="mlp-console-drag-handle-<?php echo $iid; ?>">
                <div class="mlp-con-titlebar-left">
                    <svg class="mlp-con-title-icon" xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                    <span class="mlp-con-title-text">Console</span>
                </div>
                <div class="mlp-con-titlebar-right">
                    <button class="mlp-con-tb-btn mlp-con-minimize-btn" id="mlp-con-minimize-<?php echo $iid; ?>" title="Minimize" data-instance="<?php echo $iid; ?>">
                        <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="5" y1="12" x2="19" y2="12"/></svg>
                    </button>
                    <button class="mlp-con-tb-btn mlp-modal-close-btn" data-instance="<?php echo $iid; ?>" title="Close">
                        <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                </div>
            </div>

            <!-- Toolbar: filter tabs + action buttons -->
            <div class="mlp-con-toolbar">
                <div class="mlp-con-filter-tabs" id="mlp-con-tabs-<?php echo $iid; ?>">
                    <button class="mlp-con-tab active" data-filter="all" data-instance="<?php echo $iid; ?>">
                        All
                        <span class="mlp-con-tab-count" id="mlp-con-count-all-<?php echo $iid; ?>"></span>
                    </button>
                    <button class="mlp-con-tab mlp-con-tab-error" data-filter="error" data-instance="<?php echo $iid; ?>">
                        Errors
                        <span class="mlp-con-tab-count" id="mlp-con-count-error-<?php echo $iid; ?>"></span>
                    </button>
                    <button class="mlp-con-tab mlp-con-tab-warn" data-filter="warn" data-instance="<?php echo $iid; ?>">
                        Warnings
                        <span class="mlp-con-tab-count" id="mlp-con-count-warn-<?php echo $iid; ?>"></span>
                    </button>
                    <button class="mlp-con-tab mlp-con-tab-info" data-filter="info" data-instance="<?php echo $iid; ?>">
                        Info
                        <span class="mlp-con-tab-count" id="mlp-con-count-info-<?php echo $iid; ?>"></span>
                    </button>
                    <button class="mlp-con-tab" data-filter="log" data-instance="<?php echo $iid; ?>">
                        Log
                        <span class="mlp-con-tab-count" id="mlp-con-count-log-<?php echo $iid; ?>"></span>
                    </button>
                </div>
                <div class="mlp-con-actions">
                    <button class="mlp-con-action-btn mlp-console-pause-btn" data-instance="<?php echo $iid; ?>" title="Pause logging">
                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>
                    </button>
                    <button class="mlp-con-action-btn mlp-console-copy-btn" data-instance="<?php echo $iid; ?>" title="Copy all output">
                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                    </button>
                    <div class="mlp-con-divider"></div>
                    <button class="mlp-con-action-btn mlp-console-clear-btn" data-instance="<?php echo $iid; ?>" title="Clear console">
                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
                    </button>
                </div>
            </div>

            <!-- Output area -->
            <div class="mlp-con-output" id="mlp-console-output-<?php echo $iid; ?>" tabindex="0">
                <div class="mlp-con-welcome" id="mlp-con-welcome-<?php echo $iid; ?>">
                    <div class="mlp-con-welcome-inner">
                        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                        <span>Console ready — run your code or type a command below</span>
                    </div>
                </div>
            </div>

            <!-- Status bar -->
            <div class="mlp-con-statusbar">
                <span class="mlp-con-status-counts" id="mlp-con-status-<?php echo $iid; ?>">No messages</span>
                <span class="mlp-con-status-hint">↑↓ history &nbsp;·&nbsp; Enter to run</span>
            </div>

            <!-- REPL Input -->
            <div class="mlp-con-repl" id="mlp-con-repl-<?php echo $iid; ?>">
                <div class="mlp-con-repl-prompt">
                    <svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <div class="mlp-con-repl-input-wrap">
                    <input
                        type="text"
                        class="mlp-con-repl-input"
                        id="mlp-console-input-<?php echo $iid; ?>"
                        placeholder="JavaScript expression…"
                        autocomplete="off"
                        spellcheck="false"
                        autocorrect="off"
                        autocapitalize="off"
                    >
                </div>
                <button class="mlp-con-run-btn" id="mlp-console-input-btn-<?php echo $iid; ?>" title="Run (Enter)">
                    Run
                    <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                </button>
            </div>

        </div>
    </div>
    <?php
}

function mlp_render_console_styles() {
    ?>
    <style id="mlp-console-styles">
    /* ── Overlay shell ─────────────────────────────────────────── */
    .mlp-console-modal {
        display: none;
        position: fixed;
        inset: 0;
        z-index: 100005;
        pointer-events: none;
    }
    .mlp-console-modal.active { display: block; }

    /* ── Main panel ────────────────────────────────────────────── */
    .mlp-console-panel {
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        height: 320px;
        min-height: 120px;
        max-height: 80vh;
        display: flex;
        flex-direction: column;
        background: #1e1e1e;
        border-top: 1px solid #3c3c3c;
        font-family: 'Consolas', 'Menlo', 'Monaco', 'Courier New', monospace;
        font-size: 12px;
        color: #d4d4d4;
        pointer-events: all;
        animation: mlp-con-fadein 0.18s ease;
        overflow: hidden;
    }
    @keyframes mlp-con-fadein {
        from { opacity: 0; transform: translateY(12px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    .mlp-console-panel.mlp-con-dragging { animation: none !important; }
    .mlp-console-panel.mlp-con-floating {
        bottom: 24px;
        left: 50%;
        right: auto;
        transform: translateX(-50%);
        width: 780px;
        max-width: 96vw;
        border: 1px solid #3c3c3c;
        border-radius: 6px;
        box-shadow: 0 16px 48px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.04);
    }
    .mlp-console-panel.mlp-con-minimised {
        height: auto !important;
        min-height: unset !important;
    }
    .mlp-console-panel.mlp-con-minimised .mlp-con-toolbar,
    .mlp-console-panel.mlp-con-minimised .mlp-con-output,
    .mlp-console-panel.mlp-con-minimised .mlp-con-statusbar,
    .mlp-console-panel.mlp-con-minimised .mlp-con-repl,
    .mlp-console-panel.mlp-con-minimised .mlp-con-resize-handle { display: none !important; }

    /* ── Resize handle ─────────────────────────────────────────── */
    .mlp-con-resize-handle {
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 4px;
        cursor: ns-resize;
        z-index: 10;
        background: transparent;
    }
    .mlp-con-resize-handle:hover { background: rgba(86,156,214,0.4); }

    /* ── Title bar ─────────────────────────────────────────────── */
    .mlp-con-titlebar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0 8px;
        height: 28px;
        background: #252526;
        border-bottom: 1px solid #3c3c3c;
        cursor: grab;
        user-select: none;
        -webkit-user-select: none;
        flex-shrink: 0;
    }
    .mlp-con-titlebar:active { cursor: grabbing; }
    .mlp-con-titlebar-left {
        display: flex;
        align-items: center;
        gap: 6px;
        color: #9d9d9d;
    }
    .mlp-con-title-icon { color: #9d9d9d; flex-shrink: 0; }
    .mlp-con-title-text {
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        color: #cccccc;
    }
    .mlp-con-titlebar-right { display: flex; align-items: center; gap: 2px; }
    .mlp-con-tb-btn {
        display: flex; align-items: center; justify-content: center;
        width: 22px; height: 22px;
        background: none; border: none; border-radius: 4px;
        color: #9d9d9d; cursor: pointer;
        transition: background 0.1s, color 0.1s;
        padding: 0;
    }
    .mlp-con-tb-btn:hover { background: rgba(255,255,255,0.08); color: #ffffff; }
    .mlp-modal-close-btn.mlp-con-tb-btn:hover { background: #c42b1c; color: #ffffff; }

    /* ── Toolbar (tabs + actions) ──────────────────────────────── */
    .mlp-con-toolbar {
        display: flex;
        align-items: stretch;
        justify-content: space-between;
        background: #252526;
        border-bottom: 1px solid #3c3c3c;
        flex-shrink: 0;
        height: 30px;
    }
    .mlp-con-filter-tabs { display: flex; align-items: stretch; }
    .mlp-con-tab {
        display: inline-flex; align-items: center; gap: 5px;
        padding: 0 12px;
        background: none; border: none; border-bottom: 2px solid transparent;
        color: #9d9d9d; font-size: 11.5px; font-family: inherit;
        cursor: pointer; white-space: nowrap;
        transition: color 0.15s, border-color 0.15s;
        position: relative;
    }
    .mlp-con-tab:hover { color: #d4d4d4; background: rgba(255,255,255,0.04); }
    .mlp-con-tab.active { color: #ffffff; border-bottom-color: #569cd6; }
    .mlp-con-tab-error { }
    .mlp-con-tab-error.active { border-bottom-color: #f14c4c; }
    .mlp-con-tab-warn.active  { border-bottom-color: #cca700; }
    .mlp-con-tab-info.active  { border-bottom-color: #75beff; }
    .mlp-con-tab-count {
        display: inline-flex; align-items: center; justify-content: center;
        min-width: 16px; height: 16px; padding: 0 4px;
        background: rgba(255,255,255,0.08);
        border-radius: 8px;
        font-size: 10px; font-weight: 700; line-height: 1;
        color: #9d9d9d;
        display: none;
    }
    .mlp-con-tab-count.has-count { display: inline-flex; }
    .mlp-con-tab-error .mlp-con-tab-count.has-count { background: rgba(241,76,76,0.2); color: #f14c4c; }
    .mlp-con-tab-warn  .mlp-con-tab-count.has-count { background: rgba(204,167,0,0.2); color: #cca700; }
    .mlp-con-tab-info  .mlp-con-tab-count.has-count { background: rgba(117,190,255,0.2); color: #75beff; }

    .mlp-con-actions {
        display: flex; align-items: center; gap: 1px;
        padding: 0 6px;
    }
    .mlp-con-action-btn {
        display: flex; align-items: center; justify-content: center;
        width: 24px; height: 24px;
        background: none; border: none; border-radius: 4px;
        color: #9d9d9d; cursor: pointer;
        transition: background 0.1s, color 0.1s;
        padding: 0;
    }
    .mlp-con-action-btn:hover { background: rgba(255,255,255,0.08); color: #cccccc; }
    .mlp-con-action-btn.paused { color: #569cd6; }
    .mlp-con-divider {
        width: 1px; height: 16px;
        background: #3c3c3c;
        margin: 0 3px;
    }

    /* ── Output area ───────────────────────────────────────────── */
    .mlp-con-output {
        flex: 1; overflow-y: auto; overflow-x: hidden;
        background: #1e1e1e;
        outline: none;
        scrollbar-width: thin;
        scrollbar-color: #424242 transparent;
    }
    .mlp-con-output::-webkit-scrollbar { width: 8px; }
    .mlp-con-output::-webkit-scrollbar-track { background: transparent; }
    .mlp-con-output::-webkit-scrollbar-thumb { background: #424242; border-radius: 4px; }
    .mlp-con-output::-webkit-scrollbar-thumb:hover { background: #555; }

    /* Welcome state */
    .mlp-con-welcome {
        display: flex; align-items: center; justify-content: center;
        height: 100%; min-height: 80px;
    }
    .mlp-con-welcome-inner {
        display: flex; align-items: center; gap: 10px;
        color: #4d4d4d; font-size: 12px;
    }
    .mlp-con-welcome-inner svg { color: #3a3a3a; flex-shrink: 0; }

    /* ── Log rows ──────────────────────────────────────────────── */
    .mlp-con-row {
        display: flex;
        align-items: flex-start;
        min-height: 20px;
        padding: 1px 8px 1px 0;
        border-bottom: 1px solid rgba(255,255,255,0.04);
        position: relative;
        cursor: default;
    }
    .mlp-con-row:hover { background: rgba(255,255,255,0.03); }

    /* Left severity stripe */
    .mlp-con-row::before {
        content: '';
        display: block;
        width: 3px;
        min-height: 100%;
        flex-shrink: 0;
        align-self: stretch;
        margin-right: 6px;
    }
    .mlp-con-row.mlp-row-error { background: rgba(241,76,76,0.07); }
    .mlp-con-row.mlp-row-error::before { background: #f14c4c; }
    .mlp-con-row.mlp-row-warn  { background: rgba(204,167,0,0.07); }
    .mlp-con-row.mlp-row-warn::before  { background: #cca700; }
    .mlp-con-row.mlp-row-info::before  { background: #569cd6; }
    .mlp-con-row.mlp-row-log::before   { background: transparent; }
    .mlp-con-row.mlp-row-input { background: rgba(255,255,255,0.025); }
    .mlp-con-row.mlp-row-input::before { background: #9d9d9d; }
    .mlp-con-row.mlp-row-result::before { background: #4ec9b0; }

    /* Icon */
    .mlp-con-row-icon {
        flex-shrink: 0; width: 14px; height: 20px;
        display: flex; align-items: center; justify-content: center;
        margin-right: 6px;
    }
    .mlp-con-row-icon svg { display: block; }
    .mlp-row-error .mlp-con-row-icon { color: #f14c4c; }
    .mlp-row-warn  .mlp-con-row-icon { color: #cca700; }
    .mlp-row-info  .mlp-con-row-icon { color: #75beff; }
    .mlp-row-log   .mlp-con-row-icon { color: #6a6a6a; }
    .mlp-row-input .mlp-con-row-icon { color: #9d9d9d; }
    .mlp-row-result .mlp-con-row-icon { color: #4ec9b0; }

    /* Content + timestamp */
    .mlp-con-row-body {
        flex: 1; min-width: 0;
        display: flex; align-items: baseline;
        gap: 8px;
        padding: 2px 0;
    }
    .mlp-con-row-msg {
        flex: 1; word-break: break-word;
        white-space: pre-wrap;
        line-height: 1.5;
        color: #d4d4d4;
    }
    .mlp-row-error .mlp-con-row-msg { color: #f88070; }
    .mlp-row-warn  .mlp-con-row-msg { color: #ddbf6a; }
    .mlp-row-info  .mlp-con-row-msg { color: #9cdcfe; }
    .mlp-row-input .mlp-con-row-msg { color: #c8c8c8; font-style: italic; }
    .mlp-row-result .mlp-con-row-msg { color: #4ec9b0; }
    .mlp-con-row-time {
        flex-shrink: 0;
        font-size: 10px; color: #555; line-height: 1.5;
        white-space: nowrap;
    }

    /* Repeat badge */
    .mlp-con-row-repeat {
        flex-shrink: 0;
        font-size: 10px; font-weight: 700;
        background: rgba(255,255,255,0.1);
        border-radius: 8px;
        padding: 0 5px; height: 16px; line-height: 16px;
        color: #9d9d9d; margin-left: 4px;
        display: none;
    }
    .mlp-con-row-repeat.visible { display: inline-block; }

    /* Filter-empty state */
    .mlp-con-filter-empty {
        padding: 20px 12px;
        color: #555; font-style: italic; text-align: center; font-size: 12px;
    }

    /* ── Status bar ────────────────────────────────────────────── */
    .mlp-con-statusbar {
        display: flex; align-items: center; justify-content: space-between;
        padding: 0 10px;
        height: 20px;
        background: #007acc;
        font-size: 10.5px; color: rgba(255,255,255,0.85);
        flex-shrink: 0;
    }
    .mlp-con-statusbar.has-errors { background: #c72e0f; }
    .mlp-con-statusbar.has-warnings:not(.has-errors) { background: #7d6608; }
    .mlp-con-status-hint { opacity: 0.65; font-size: 10px; }

    /* ── REPL input ────────────────────────────────────────────── */
    .mlp-con-repl {
        display: flex; align-items: center;
        background: #1e1e1e;
        border-top: 1px solid #3c3c3c;
        padding: 0 8px;
        min-height: 34px;
        flex-shrink: 0;
        gap: 6px;
    }
    .mlp-con-repl-prompt {
        flex-shrink: 0; color: #569cd6;
        display: flex; align-items: center;
    }
    .mlp-con-repl-input-wrap { flex: 1; display: flex; align-items: center; }
    .mlp-con-repl-input {
        width: 100%; background: none; border: none; outline: none;
        color: #d4d4d4; font-family: inherit; font-size: 12.5px;
        padding: 6px 0; caret-color: #569cd6;
    }
    .mlp-con-repl-input::placeholder { color: #4a4a4a; }
    .mlp-con-run-btn {
        flex-shrink: 0;
        display: inline-flex; align-items: center; gap: 5px;
        padding: 4px 10px;
        background: #0e639c; border: none; border-radius: 3px;
        color: #ffffff; font-size: 11px; font-family: inherit;
        font-weight: 600; cursor: pointer; letter-spacing: 0.02em;
        transition: background 0.15s;
    }
    .mlp-con-run-btn:hover { background: #1177bb; }
    .mlp-con-run-btn:active { background: #0a5280; }

    /* ── Minimised pill ────────────────────────────────────────── */
    .mlp-console-panel.mlp-con-minimised {
        bottom: 0; left: 0; right: 0;
        height: 28px !important;
        border-radius: 0;
        border-top: 1px solid #3c3c3c;
    }
    .mlp-console-panel.mlp-con-floating.mlp-con-minimised {
        left: 50%; right: auto;
        transform: translateX(-50%);
        width: 260px; border-radius: 14px;
        bottom: 24px;
    }

    /* ── Mobile ────────────────────────────────────────────────── */
    @media (max-width: 600px) {
        .mlp-console-panel { font-size: 11px; }
        .mlp-con-repl-input { font-size: 12px; }
        .mlp-con-tab { padding: 0 8px; font-size: 10.5px; }
        .mlp-con-status-hint { display: none; }
    }
    </style>
    <?php
}

/**
 * Schedules mlp_print_console_scripts() in wp_footer at priority 101
 * (after mlp-main.js at priority 100) so our openConsoleModal / closeConsoleModal
 * always win over any stale definitions in a cached mlp-main.js.
 * Idempotent — safe to call from multiple shortcode instances on one page.
 */
function mlp_render_console_scripts() {
    static $hooked = false;
    if ( $hooked ) return;
    $hooked = true;
    add_action( 'wp_footer', 'mlp_print_console_scripts', 101 );
}

function mlp_print_console_scripts() {
    ?>
    <script id="mlp-console-scripts">
    (function($) {
        "use strict";

        /* ── Icon helpers ──────────────────────────────────────────── */
        var ICONS = {
            error:  '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
            warn:   '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            info:   '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="8"/><polyline points="11 12 12 12 12 16"/></svg>',
            log:    '<svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>',
            input:  '<svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>',
            result: '<svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>'
        };

        function getIcon(type) {
            return ICONS[type] || ICONS.log;
        }

        /* ── Escape HTML ───────────────────────────────────────────── */
        function escHtml(text) {
            var d = document.createElement("div");
            d.textContent = text;
            return d.innerHTML;
        }
        window.escapeHtml = escHtml;

        /* ── Format any value nicely ───────────────────────────────── */
        function formatValue(v) {
            if (v === null) return '<span style="color:#569cd6">null</span>';
            if (v === undefined) return '<span style="color:#9d9d9d">undefined</span>';
            if (typeof v === "boolean") return '<span style="color:#569cd6">' + v + '</span>';
            if (typeof v === "number") return '<span style="color:#b5cea8">' + v + '</span>';
            if (typeof v === "string") return '<span style="color:#ce9178">"' + escHtml(v) + '"</span>';
            if (typeof v === "function") return '<span style="color:#dcdcaa">ƒ ' + escHtml(v.name || '(anonymous)') + '()</span>';
            if (typeof v === "object") {
                try {
                    var s = JSON.stringify(v, null, 2);
                    if (s && s.length < 500) {
                        return '<span style="color:#9d9d9d">' + escHtml(s) + '</span>';
                    }
                } catch(e) {}
                return '<span style="color:#9d9d9d">[Object]</span>';
            }
            return escHtml(String(v));
        }

        /* ── Format arguments array ────────────────────────────────── */
        function formatArgs(args) {
            return args.map(function(a) { return formatValue(a); }).join(' ');
        }

        /* ── Counts per instance ───────────────────────────────────── */
        var mlpCounts = {};
        function getCounts(iid) {
            if (!mlpCounts[iid]) mlpCounts[iid] = { all: 0, error: 0, warn: 0, info: 0, log: 0 };
            return mlpCounts[iid];
        }

        /* ── Update tab counts + statusbar ─────────────────────────── */
        function updateCounts(instanceId) {
            var c = getCounts(instanceId);
            var types = ['all','error','warn','info','log'];
            types.forEach(function(t) {
                var el = document.getElementById('mlp-con-count-' + t + '-' + instanceId);
                if (!el) return;
                if (c[t] > 0) {
                    el.textContent = c[t] > 99 ? '99+' : c[t];
                    el.classList.add('has-count');
                } else {
                    el.textContent = '';
                    el.classList.remove('has-count');
                }
            });
            var sb = document.getElementById('mlp-con-status-' + instanceId);
            if (sb) {
                var panel = sb.closest('.mlp-con-statusbar');
                if (c.all === 0) {
                    sb.textContent = 'No messages';
                    if (panel) { panel.classList.remove('has-errors','has-warnings'); }
                } else {
                    var parts = [];
                    if (c.error) parts.push(c.error + ' error' + (c.error !== 1 ? 's' : ''));
                    if (c.warn)  parts.push(c.warn  + ' warning' + (c.warn  !== 1 ? 's' : ''));
                    if (c.info)  parts.push(c.info  + ' info');
                    if (c.log)   parts.push(c.log   + ' log' + (c.log !== 1 ? 's' : ''));
                    sb.textContent = parts.join(' · ') || c.all + ' message' + (c.all !== 1 ? 's' : '');
                    if (panel) {
                        panel.classList.toggle('has-errors', c.error > 0);
                        panel.classList.toggle('has-warnings', c.warn > 0 && c.error === 0);
                    }
                }
            }
        }

        /* ── addMessage (public API) ────────────────────────────────── */
        window.mlpConsoleAddMessage = function(instanceId, type, messageOrArgs, displayType) {
            var output = document.getElementById('mlp-console-output-' + instanceId);
            if (!output) return;

            // Remove welcome banner
            var welcome = document.getElementById('mlp-con-welcome-' + instanceId);
            if (welcome) welcome.remove();

            var rowType = displayType || type || 'log';
            var now = new Date();
            var ts = now.toTimeString().slice(0,8) + '.' + String(now.getMilliseconds()).padStart(3,'0');

            var formatted;
            if (Array.isArray(messageOrArgs)) {
                formatted = formatArgs(messageOrArgs);
            } else {
                formatted = escHtml(String(messageOrArgs));
            }

            var row = document.createElement('div');
            row.className = 'mlp-con-row mlp-row-' + rowType;
            row.dataset.type = rowType;
            row.innerHTML =
                '<div class="mlp-con-row-icon">' + getIcon(rowType) + '</div>' +
                '<div class="mlp-con-row-body">' +
                  '<div class="mlp-con-row-msg">' + formatted + '</div>' +
                  '<div class="mlp-con-row-time">' + escHtml(ts) + '</div>' +
                '</div>';

            output.appendChild(row);
            output.scrollTop = output.scrollHeight;

            // Update counts
            var c = getCounts(instanceId);
            c.all++;
            if (rowType === 'error' || rowType === 'warn' || rowType === 'info' || rowType === 'log') {
                c[rowType] = (c[rowType] || 0) + 1;
            }
            updateCounts(instanceId);

            // Re-apply active filter
            var activeTab = document.querySelector('#mlp-con-tabs-' + instanceId + ' .mlp-con-tab.active');
            if (activeTab) {
                var f = activeTab.dataset.filter;
                if (f && f !== 'all' && rowType !== f) row.style.display = 'none';
            }
        };
        window.addConsoleMessage = window.mlpConsoleAddMessage;

        /* ── openConsoleModal / closeConsoleModal ───────────────────── */
        window.openConsoleModal = function(instanceId) {
            var modal = document.getElementById('mlp-console-modal-' + instanceId);
            if (!modal) return;
            modal.classList.add('active');
            mlpConsoleInit(instanceId);
            var input = document.getElementById('mlp-console-input-' + instanceId);
            if (input) setTimeout(function(){ input.focus(); }, 60);
        };

        window.closeConsoleModal = function(instanceId) {
            var modal = document.getElementById('mlp-console-modal-' + instanceId);
            if (modal) modal.classList.remove('active');
        };

        /* ── Console init (runs each time panel opens) ──────────────── */
        function mlpConsoleInit(instanceId) {
            var instances = window.monacoInstances && window.monacoInstances[instanceId];
            mlpConsoleHookPreview(instanceId);
            mlpConsoleInitDrag(instanceId);
            mlpConsoleInitResize(instanceId);
            mlpConsoleInitMinimize(instanceId);
            mlpConsoleInitTabs(instanceId);
            mlpConsoleInitActions(instanceId);
            mlpConsoleInitREPL(instanceId);
        }
        window.initConsole = mlpConsoleInit;

        /* ── Tab filter ─────────────────────────────────────────────── */
        function mlpConsoleInitTabs(instanceId) {
            var tabs = document.querySelectorAll('#mlp-con-tabs-' + instanceId + ' .mlp-con-tab');
            tabs.forEach(function(tab) {
                if (tab.dataset.mlpTabInit) return;
                tab.dataset.mlpTabInit = '1';
                tab.addEventListener('click', function() {
                    tabs.forEach(function(t){ t.classList.remove('active'); });
                    tab.classList.add('active');
                    applyFilter(instanceId, tab.dataset.filter || 'all');
                });
            });
        }

        function applyFilter(instanceId, filter) {
            var output = document.getElementById('mlp-console-output-' + instanceId);
            if (!output) return;
            var rows = output.querySelectorAll('.mlp-con-row');
            var visible = 0;
            rows.forEach(function(row) {
                var t = row.dataset.type;
                var show = (filter === 'all' || t === filter);
                row.style.display = show ? '' : 'none';
                if (show) visible++;
            });
            // empty state
            var existing = output.querySelector('.mlp-con-filter-empty');
            if (existing) existing.remove();
            if (visible === 0 && rows.length > 0) {
                var em = document.createElement('div');
                em.className = 'mlp-con-filter-empty';
                em.textContent = 'No ' + filter + ' messages';
                output.appendChild(em);
            }
        }
        window.filterConsoleMessages = applyFilter;

        /* ── Action buttons ─────────────────────────────────────────── */
        function mlpConsoleInitActions(instanceId) {
            // Clear
            var clearBtn = document.querySelector('#mlp-console-modal-' + instanceId + ' .mlp-console-clear-btn');
            if (clearBtn && !clearBtn.dataset.mlpInit) {
                clearBtn.dataset.mlpInit = '1';
                clearBtn.addEventListener('click', function(e) {
                    e.preventDefault(); e.stopPropagation();
                    mlpConsoleClear(instanceId);
                });
            }
            // Pause
            var pauseBtn = document.querySelector('#mlp-console-modal-' + instanceId + ' .mlp-console-pause-btn');
            if (pauseBtn && !pauseBtn.dataset.mlpInit) {
                pauseBtn.dataset.mlpInit = '1';
                pauseBtn.addEventListener('click', function(e) {
                    e.preventDefault(); e.stopPropagation();
                    mlpConsoleTogglePause(instanceId, pauseBtn);
                });
            }
            // Copy
            var copyBtn = document.querySelector('#mlp-console-modal-' + instanceId + ' .mlp-console-copy-btn');
            if (copyBtn && !copyBtn.dataset.mlpInit) {
                copyBtn.dataset.mlpInit = '1';
                copyBtn.addEventListener('click', function(e) {
                    e.preventDefault(); e.stopPropagation();
                    mlpConsoleCopy(instanceId);
                });
            }
            // Close (X in title bar)
            var closeBtn = document.querySelector('#mlp-console-modal-' + instanceId + ' .mlp-modal-close-btn');
            if (closeBtn && !closeBtn.dataset.mlpInit) {
                closeBtn.dataset.mlpInit = '1';
                closeBtn.addEventListener('click', function(e) {
                    e.preventDefault(); e.stopPropagation();
                    window.closeConsoleModal(instanceId);
                });
            }
        }

        /* ── REPL input ─────────────────────────────────────────────── */
        var cmdHistory = {};
        var historyPos = {};

        function mlpConsoleInitREPL(instanceId) {
            var input = document.getElementById('mlp-console-input-' + instanceId);
            var runBtn = document.getElementById('mlp-console-input-btn-' + instanceId);
            if (!input || input.dataset.mlpReplInit) return;
            input.dataset.mlpReplInit = '1';
            if (!cmdHistory[instanceId]) cmdHistory[instanceId] = [];
            if (historyPos[instanceId] === undefined) historyPos[instanceId] = -1;

            input.addEventListener('keydown', function(e) {
                var hist = cmdHistory[instanceId];
                if (e.key === 'Enter') {
                    e.preventDefault();
                    mlpConsoleExec(instanceId);
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    var pos = historyPos[instanceId];
                    if (pos < hist.length - 1) {
                        pos++;
                        historyPos[instanceId] = pos;
                        input.value = hist[hist.length - 1 - pos] || '';
                        setTimeout(function(){ input.selectionStart = input.selectionEnd = input.value.length; }, 0);
                    }
                } else if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    var pos2 = historyPos[instanceId];
                    if (pos2 > 0) {
                        pos2--;
                        historyPos[instanceId] = pos2;
                        input.value = hist[hist.length - 1 - pos2] || '';
                    } else {
                        historyPos[instanceId] = -1;
                        input.value = '';
                    }
                } else if (e.key === 'l' && e.ctrlKey) {
                    e.preventDefault();
                    mlpConsoleClear(instanceId);
                }
            });

            if (runBtn && !runBtn.dataset.mlpReplInit) {
                runBtn.dataset.mlpReplInit = '1';
                runBtn.addEventListener('click', function(e) {
                    e.preventDefault(); e.stopPropagation();
                    mlpConsoleExec(instanceId);
                    input.focus();
                });
            }
        }

        function mlpConsoleExec(instanceId) {
            var input = document.getElementById('mlp-console-input-' + instanceId);
            if (!input) return;
            var code = input.value.trim();
            if (!code) return;

            // Record history
            var hist = cmdHistory[instanceId] || (cmdHistory[instanceId] = []);
            if (hist[hist.length - 1] !== code) hist.push(code);
            if (hist.length > 100) hist.shift();
            historyPos[instanceId] = -1;

            window.mlpConsoleAddMessage(instanceId, 'input', [code], 'input');

            try {
                var previewFrame = document.getElementById('mlp-preview-frame-main-' + instanceId);
                var result;
                if (previewFrame && previewFrame.contentWindow) {
                    result = previewFrame.contentWindow.eval(code);
                } else {
                    result = eval(code);
                }
                window.mlpConsoleAddMessage(instanceId, 'result', [result], 'result');
            } catch (err) {
                window.mlpConsoleAddMessage(instanceId, 'error', [err.message], 'error');
            }

            input.value = '';
        }
        window.executeConsoleInput = mlpConsoleExec;

        /* ── Clear ──────────────────────────────────────────────────── */
        function mlpConsoleClear(instanceId) {
            var output = document.getElementById('mlp-console-output-' + instanceId);
            if (!output) return;
            output.innerHTML = '';
            // Reset counts
            mlpCounts[instanceId] = { all: 0, error: 0, warn: 0, info: 0, log: 0 };
            updateCounts(instanceId);
            if (typeof showNotification === "function") showNotification(instanceId, "Console cleared", "success");
        }
        window.clearConsole = mlpConsoleClear;

        /* ── Pause ──────────────────────────────────────────────────── */
        function mlpConsoleTogglePause(instanceId, btn) {
            var instances = window.monacoInstances && window.monacoInstances[instanceId];
            if (!instances) return;
            instances.consolePaused = !instances.consolePaused;
            if (btn) btn.classList.toggle('paused', instances.consolePaused);
            var label = instances.consolePaused ? "Logging paused" : "Logging resumed";
            if (typeof showNotification === "function") showNotification(instanceId, label, "info");
        }
        window.toggleConsolePause = mlpConsoleTogglePause;

        /* ── Copy ───────────────────────────────────────────────────── */
        function mlpConsoleCopy(instanceId) {
            var output = document.getElementById('mlp-console-output-' + instanceId);
            if (!output) return;
            var lines = [];
            output.querySelectorAll('.mlp-con-row').forEach(function(row) {
                var ts   = row.querySelector('.mlp-con-row-time');
                var msg  = row.querySelector('.mlp-con-row-msg');
                var type = row.dataset.type || '';
                lines.push('[' + (ts ? ts.textContent : '') + '] [' + type.toUpperCase() + '] ' + (msg ? msg.textContent : ''));
            });
            if (!lines.length) {
                if (typeof showNotification === "function") showNotification(instanceId, "No output to copy", "error");
                return;
            }
            navigator.clipboard.writeText(lines.join('\n')).then(function() {
                if (typeof showNotification === "function") showNotification(instanceId, "Copied to clipboard!", "success");
            }).catch(function() {
                if (typeof showNotification === "function") showNotification(instanceId, "Copy failed", "error");
            });
        }
        window.copyConsoleOutput = mlpConsoleCopy;

        /* ── Hook into preview iframe console ───────────────────────── */
        function mlpConsoleHookPreview(instanceId) {
            var previewFrame = document.getElementById('mlp-preview-frame-main-' + instanceId);
            var instances = window.monacoInstances && window.monacoInstances[instanceId];
            if (!previewFrame || !instances || instances._consoleHooked) return;
            instances._consoleHooked = true;

            function captureConsole(type) {
                return function() {
                    var args = Array.prototype.slice.call(arguments);
                    if (instances.consolePaused) return;
                    window.mlpConsoleAddMessage(instanceId, type, args, type);
                };
            }

            function hookFrame() {
                try {
                    var cw = previewFrame.contentWindow;
                    if (cw && cw.console) {
                        ['log','error','warn','info'].forEach(function(t) {
                            var orig = cw.console[t].bind(cw.console);
                            cw.console[t] = (function(origFn, tp) {
                                return function() {
                                    origFn.apply(cw.console, arguments);
                                    if (instances.consolePaused) return;
                                    window.mlpConsoleAddMessage(instanceId, tp, Array.prototype.slice.call(arguments), tp);
                                };
                            })(orig, t);
                        });
                    }
                } catch(e) {}
            }

            previewFrame.addEventListener('load', hookFrame);
        }
        window.hookIntoPreviewConsole = mlpConsoleHookPreview;

        /* ── Drag (title bar) ───────────────────────────────────────── */
        function mlpConsoleInitDrag(instanceId) {
            var panel  = document.getElementById('mlp-console-panel-' + instanceId);
            var handle = document.getElementById('mlp-console-drag-handle-' + instanceId);
            if (!panel || !handle || handle.dataset.mlpDragInit) return;
            handle.dataset.mlpDragInit = '1';

            var dragging = false, startX, startY, origLeft, origTop;

            handle.addEventListener('mousedown', function(e) {
                if (e.target.closest('button')) return;
                e.preventDefault();
                // Switch to floating mode for dragging
                if (!panel.classList.contains('mlp-con-floating')) {
                    var rect = panel.getBoundingClientRect();
                    panel.classList.add('mlp-con-floating');
                    panel.style.left   = rect.left + 'px';
                    panel.style.top    = rect.top  + 'px';
                    panel.style.bottom = 'auto';
                    panel.style.right  = 'auto';
                    panel.style.transform = 'none';
                    panel.style.width  = rect.width + 'px';
                }
                var prect = panel.getBoundingClientRect();
                dragging = true;
                startX = e.clientX; startY = e.clientY;
                origLeft = prect.left; origTop = prect.top;
                panel.classList.add('mlp-con-dragging');

                function onMove(ev) {
                    if (!dragging) return;
                    var dx = ev.clientX - startX;
                    var dy = ev.clientY - startY;
                    var nl = Math.max(0, Math.min(window.innerWidth  - panel.offsetWidth,  origLeft + dx));
                    var nt = Math.max(0, Math.min(window.innerHeight - panel.offsetHeight, origTop  + dy));
                    panel.style.left = nl + 'px';
                    panel.style.top  = nt + 'px';
                }
                function onUp() {
                    dragging = false;
                    panel.classList.remove('mlp-con-dragging');
                    document.removeEventListener('mousemove', onMove);
                    document.removeEventListener('mouseup', onUp);
                }
                document.addEventListener('mousemove', onMove);
                document.addEventListener('mouseup', onUp);
            });
        }

        /* ── Resize (top edge of panel) ─────────────────────────────── */
        function mlpConsoleInitResize(instanceId) {
            var panel  = document.getElementById('mlp-console-panel-' + instanceId);
            var handle = document.getElementById('mlp-con-resize-' + instanceId);
            if (!panel || !handle || handle.dataset.mlpResizeInit) return;
            handle.dataset.mlpResizeInit = '1';

            var resizing = false, startY, startH;

            handle.addEventListener('mousedown', function(e) {
                e.preventDefault();
                resizing = true;
                startY = e.clientY;
                startH = panel.offsetHeight;
                document.body.style.cursor = 'ns-resize';
                document.body.style.userSelect = 'none';

                function onMove(ev) {
                    if (!resizing) return;
                    var dy  = startY - ev.clientY; // drag up = bigger
                    var nh  = Math.min(Math.max(startH + dy, 120), window.innerHeight * 0.85);
                    panel.style.height = nh + 'px';
                }
                function onUp() {
                    resizing = false;
                    document.body.style.cursor = '';
                    document.body.style.userSelect = '';
                    document.removeEventListener('mousemove', onMove);
                    document.removeEventListener('mouseup', onUp);
                }
                document.addEventListener('mousemove', onMove);
                document.addEventListener('mouseup', onUp);
            });
        }

        /* ── Minimize ───────────────────────────────────────────────── */
        function mlpConsoleInitMinimize(instanceId) {
            var panel = document.getElementById('mlp-console-panel-' + instanceId);
            var btn   = document.getElementById('mlp-con-minimize-' + instanceId);
            if (!btn || btn.dataset.mlpMinInit) return;
            btn.dataset.mlpMinInit = '1';
            btn.addEventListener('click', function(e) {
                e.stopPropagation(); e.preventDefault();
                var isMin = panel.classList.toggle('mlp-con-minimised');
                btn.title = isMin ? 'Restore' : 'Minimize';
            });
        }

    })(jQuery);
    </script>
    <?php
}
