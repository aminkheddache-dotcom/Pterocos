<?php
if (!defined('ABSPATH')) {
    exit;
}

class MLP_Community_Builds {

    // ──────────────────────────────────────────────
    //  WP ADMIN: Register menu page
    // ──────────────────────────────────────────────
    public static function register_admin_menu() {
        add_menu_page(
            'Community Builds',
            'Community Builds',
            'manage_options',
            'mlp-community-builds',
            array('MLP_Community_Builds', 'render_admin_page'),
            'dashicons-layout',
            30
        );
        add_submenu_page(
            'mlp-community-builds',
            'Community Authors',
            '&#128100; Authors',
            'manage_options',
            'mlp-community-authors',
            array('MLP_Community_Builds', 'render_authors_page')
        );
    }

    // ──────────────────────────────────────────────
    //  AUTHORS: Get / Save helpers
    // ──────────────────────────────────────────────
    public static function get_saved_authors() {
        $authors = get_option('mlp_community_authors', array());
        return is_array($authors) ? $authors : array();
    }

    public static function get_author_by_name($name) {
        foreach (self::get_saved_authors() as $a) {
            if ($a['name'] === $name) return $a;
        }
        return null;
    }

    public static function get_author_by_id($id) {
        foreach (self::get_saved_authors() as $a) {
            if ($a['id'] === $id) return $a;
        }
        return null;
    }

    // ──────────────────────────────────────────────
    //  AUTHORS: Handle form submissions
    // ──────────────────────────────────────────────
    public static function handle_author_actions() {
        if (!isset($_POST['mlp_author_action']) || !current_user_can('manage_options')) return;
        check_admin_referer('mlp_authors_nonce');
        $authors = self::get_saved_authors();

        if ($_POST['mlp_author_action'] === 'add' || $_POST['mlp_author_action'] === 'edit') {
            $editing_id = sanitize_text_field($_POST['mlp_editing_id'] ?? '');
            $name = sanitize_text_field($_POST['mlp_aname'] ?? '');
            if (!$name) {
                wp_redirect(add_query_arg(array('page' => 'mlp-community-authors', 'error' => 'noname'), admin_url('admin.php')));
                exit;
            }
            $avatar_url = sanitize_text_field($_POST['mlp_avatar_existing'] ?? '');
            if (!empty($_FILES['mlp_avatar']['name'])) {
                $uploaded = self::handle_image_upload($_FILES['mlp_avatar']);
                if ($uploaded) $avatar_url = $uploaded;
            }
            // Handle password (only set if provided; keep existing on edit)
            $raw_pw = $_POST['mlp_apassword'] ?? '';
            $existing_pw = '';
            if ($editing_id) {
                $existing = self::get_author_by_id($editing_id);
                $existing_pw = $existing['password'] ?? '';
            }
            $hashed_pw = $raw_pw ? wp_hash_password($raw_pw) : $existing_pw;

            $record = array(
                'id'       => $editing_id ?: uniqid('mlpa_'),
                'name'     => $name,
                'bio'      => sanitize_textarea_field($_POST['mlp_abio'] ?? ''),
                'avatar'   => $avatar_url,
                'discord'  => sanitize_text_field($_POST['mlp_discord'] ?? ''),
                'youtube'  => esc_url_raw($_POST['mlp_youtube'] ?? ''),
                'twitter'  => esc_url_raw($_POST['mlp_twitter'] ?? ''),
                'github'   => esc_url_raw($_POST['mlp_github']  ?? ''),
                'website'  => esc_url_raw($_POST['mlp_website'] ?? ''),
                'joined'   => date('M Y'),
                'password' => $hashed_pw,
            );
            if ($editing_id) {
                foreach ($authors as &$a) {
                    if ($a['id'] === $editing_id) {
                        $record['joined'] = $a['joined'];
                        $a = $record;
                        break;
                    }
                }
                unset($a);
            } else {
                array_unshift($authors, $record);
            }
            update_option('mlp_community_authors', $authors);
            wp_redirect(add_query_arg(array('page' => 'mlp-community-authors', 'saved' => '1'), admin_url('admin.php')));
            exit;
        }

        if ($_POST['mlp_author_action'] === 'delete') {
            $del_id = sanitize_text_field($_POST['mlp_delete_author_id'] ?? '');
            $authors = array_filter($authors, function($a) use ($del_id) { return $a['id'] !== $del_id; });
            update_option('mlp_community_authors', array_values($authors));
            wp_redirect(add_query_arg(array('page' => 'mlp-community-authors', 'deleted' => '1'), admin_url('admin.php')));
            exit;
        }
    }

    // ──────────────────────────────────────────────
    //  AUTHORS: Render admin page
    // ──────────────────────────────────────────────
    public static function render_authors_page() {
        $authors = self::get_saved_authors();
        $saved   = isset($_GET['saved']);
        $deleted = isset($_GET['deleted']);
        $edit_id = isset($_GET['edit']) ? sanitize_text_field($_GET['edit']) : '';
        $editing = $edit_id ? self::get_author_by_id($edit_id) : null;
        $all_builds = self::get_saved_builds();
        ?>
        <div class="wrap mlp-cb-admin-wrap">
            <div class="mlp-cb-header" style="background:linear-gradient(135deg,#1a1a2e,#2d1b4e);">
                <div class="mlp-cb-header-title">
                    <span class="dashicons dashicons-admin-users" style="color:#a78bfa;"></span>
                    <h1 style="background:linear-gradient(135deg,#fff,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">Community Authors</h1>
                </div>
                <p class="mlp-cb-header-desc">Create and manage builder profiles. These appear on template pages and in the author popup.</p>
            </div>

            <?php if ($saved): ?><div class="notice notice-success is-dismissible"><p>&#10003; Author saved!</p></div><?php endif; ?>
            <?php if ($deleted): ?><div class="notice notice-warning is-dismissible"><p>&#128465; Author deleted.</p></div><?php endif; ?>

            <div class="mlp-cb-admin-layout">

                <div class="mlp-cb-admin-card form-card">
                    <div class="card-header">
                        <span class="dashicons <?php echo $editing ? 'dashicons-edit' : 'dashicons-plus-alt'; ?>"></span>
                        <h2><?php echo $editing ? 'Edit: ' . esc_html($editing['name']) : 'Add New Author'; ?></h2>
                        <?php if ($editing): ?><a href="<?php echo admin_url('admin.php?page=mlp-community-authors'); ?>" class="button button-secondary" style="margin-left:auto;">+ New Author</a><?php endif; ?>
                    </div>
                    <form method="post" action="" enctype="multipart/form-data">
                        <?php wp_nonce_field('mlp_authors_nonce'); ?>
                        <input type="hidden" name="mlp_author_action" value="<?php echo $editing ? 'edit' : 'add'; ?>" />
                        <input type="hidden" name="mlp_editing_id" value="<?php echo esc_attr($editing['id'] ?? ''); ?>" />
                        <input type="hidden" name="mlp_avatar_existing" value="<?php echo esc_attr($editing['avatar'] ?? ''); ?>" />

                        <div class="mlp-cb-form-grid mlp-authors-grid">
                            <div class="mlp-cb-form-col">
                                <div class="mlp-cb-field-group">
                                    <label>Display Name <span class="required">*</span></label>
                                    <input type="text" name="mlp_aname" required value="<?php echo esc_attr($editing['name'] ?? ''); ?>" placeholder="e.g. xXCoolBuilderXx" />
                                </div>
                                <div class="mlp-cb-field-group">
                                    <label>Bio <small>(optional)</small></label>
                                    <textarea name="mlp_abio" rows="3" placeholder="Short bio shown on their profile..."><?php echo esc_textarea($editing['bio'] ?? ''); ?></textarea>
                                </div>
                                <div class="mlp-cb-field-group">
                                    <label>Avatar <small>(optional)</small></label>
                                    <?php if (!empty($editing['avatar'])): ?>
                                        <img src="<?php echo esc_url($editing['avatar']); ?>" class="mlp-author-avatar-preview" />
                                    <?php endif; ?>
                                    <input type="file" name="mlp_avatar" accept="image/*" />
                                    <p class="field-hint">Recommended: 200x200px square</p>
                                </div>
                                <div class="mlp-cb-field-group">
                                    <label>Login Password <span class="required">*</span> <small><?php echo $editing ? '(leave blank to keep current)' : ''; ?></small></label>
                                    <input type="password" name="mlp_apassword" <?php echo $editing ? '' : 'required'; ?> placeholder="<?php echo $editing ? 'Leave blank to keep current password' : 'Set a login password'; ?>" autocomplete="new-password" />
                                    <p class="field-hint">Authors use this to log in and manage their templates on the frontend.</p>
                                </div>
                            </div>

                            <div class="mlp-cb-form-col">
                                <p class="mlp-socials-heading">Social Links <small>(leave blank to hide)</small></p>
                                <div class="mlp-cb-field-group">
                                    <label><span class="mlp-social-icon discord">&#xf392;</span> Discord Username</label>
                                    <input type="text" name="mlp_discord" value="<?php echo esc_attr($editing['discord'] ?? ''); ?>" placeholder="username or user#1234" />
                                </div>
                                <div class="mlp-cb-field-group">
                                    <label><span class="mlp-social-icon youtube">&#xf167;</span> YouTube URL</label>
                                    <input type="url" name="mlp_youtube" value="<?php echo esc_attr($editing['youtube'] ?? ''); ?>" placeholder="https://youtube.com/@channel" />
                                </div>
                                <div class="mlp-cb-field-group">
                                    <label><span class="mlp-social-icon twitter">&#xf099;</span> Twitter / X URL</label>
                                    <input type="url" name="mlp_twitter" value="<?php echo esc_attr($editing['twitter'] ?? ''); ?>" placeholder="https://x.com/handle" />
                                </div>
                            </div>

                            <div class="mlp-cb-form-col">
                                <p class="mlp-socials-heading">&nbsp;</p>
                                <div class="mlp-cb-field-group">
                                    <label><span class="mlp-social-icon github">&#xf09b;</span> GitHub URL</label>
                                    <input type="url" name="mlp_github" value="<?php echo esc_attr($editing['github'] ?? ''); ?>" placeholder="https://github.com/username" />
                                </div>
                                <div class="mlp-cb-field-group">
                                    <label><span class="mlp-social-icon website">&#xf0ac;</span> Website URL</label>
                                    <input type="url" name="mlp_website" value="<?php echo esc_attr($editing['website'] ?? ''); ?>" placeholder="https://yoursite.com" />
                                </div>
                            </div>
                        </div>

                        <div class="form-actions">
                            <button type="submit" class="button button-primary mlp-cb-submit-btn">
                                <span class="dashicons dashicons-saved"></span>
                                <?php echo $editing ? 'Update Author' : 'Create Author'; ?>
                            </button>
                        </div>
                    </form>
                </div>

                <div class="mlp-cb-admin-card templates-card">
                    <div class="card-header">
                        <span class="dashicons dashicons-list-view"></span>
                        <h2>Registered Authors</h2>
                        <span class="mlp-cb-count"><?php echo count($authors); ?></span>
                    </div>
                    <?php if (empty($authors)): ?>
                        <div class="mlp-cb-empty-state"><span class="dashicons dashicons-admin-users"></span><p>No authors yet. Add one above!</p></div>
                    <?php else: ?>
                        <div class="mlp-cb-table-wrapper">
                            <table class="wp-list-table widefat fixed striped">
                                <thead><tr><th width="54">Avatar</th><th>Name</th><th>Socials</th><th>Joined</th><th>Builds</th><th width="110">Actions</th></tr></thead>
                                <tbody>
                                <?php foreach ($authors as $auth):
                                    $bc = count(array_filter($all_builds, function($b) use ($auth) { return ($b['author'] ?? '') === $auth['name']; }));
                                    $has_socials = array_filter(array($auth['discord'] ?? '', $auth['youtube'] ?? '', $auth['twitter'] ?? '', $auth['github'] ?? '', $auth['website'] ?? ''));
                                ?>
                                <tr>
                                    <td><?php if (!empty($auth['avatar'])): ?><img src="<?php echo esc_url($auth['avatar']); ?>" style="width:38px;height:38px;object-fit:cover;border-radius:50%;" /><?php else: ?><div class="mlp-author-initials"><?php echo mb_strtoupper(mb_substr($auth['name'],0,1)); ?></div><?php endif; ?></td>
                                    <td><strong><?php echo esc_html($auth['name']); ?></strong><?php if (!empty($auth['bio'])): ?><div class="mlp-cb-author-meta"><?php echo esc_html(mb_strimwidth($auth['bio'],0,60,'…')); ?></div><?php endif; ?></td>
                                    <td>
                                        <div style="display:flex;gap:10px;align-items:center;">
                                        <?php if (!empty($auth['discord'])): ?><span title="Discord: <?php echo esc_attr($auth['discord']); ?>" class="mlp-si-discord">D</span><?php endif; ?>
                                        <?php if (!empty($auth['youtube'])): ?><a href="<?php echo esc_url($auth['youtube']); ?>" target="_blank" class="mlp-si-youtube" title="YouTube">YT</a><?php endif; ?>
                                        <?php if (!empty($auth['twitter'])): ?><a href="<?php echo esc_url($auth['twitter']); ?>" target="_blank" class="mlp-si-twitter" title="Twitter/X">X</a><?php endif; ?>
                                        <?php if (!empty($auth['github'])): ?><a href="<?php echo esc_url($auth['github']); ?>" target="_blank" class="mlp-si-github" title="GitHub">GH</a><?php endif; ?>
                                        <?php if (!empty($auth['website'])): ?><a href="<?php echo esc_url($auth['website']); ?>" target="_blank" class="mlp-si-web" title="Website">&#x1f310;</a><?php endif; ?>
                                        <?php if (!$has_socials): ?><span style="color:#cbd5e1;font-size:0.72rem;">—</span><?php endif; ?>
                                        </div>
                                    </td>
                                    <td><?php echo esc_html($auth['joined']); ?></td>
                                    <td><span class="mlp-cb-badge"><?php echo $bc; ?></span></td>
                                    <td>
                                        <a href="<?php echo admin_url('admin.php?page=mlp-community-authors&edit=' . esc_attr($auth['id'])); ?>" class="button button-small" style="margin-right:4px;"><span class="dashicons dashicons-edit" style="margin-top:3px;"></span></a>
                                        <form method="post" style="display:inline;" onsubmit="return confirm('Delete this author?');">
                                            <?php wp_nonce_field('mlp_authors_nonce'); ?>
                                            <input type="hidden" name="mlp_author_action" value="delete" />
                                            <input type="hidden" name="mlp_delete_author_id" value="<?php echo esc_attr($auth['id']); ?>" />
                                            <button type="submit" class="button button-small mlp-cb-delete-btn"><span class="dashicons dashicons-trash" style="margin-top:3px;"></span></button>
                                        </form>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <style>
        .mlp-authors-grid{grid-template-columns:1fr 1fr 1fr !important;}
        .mlp-author-avatar-preview{width:60px;height:60px;object-fit:cover;border-radius:50%;margin-bottom:6px;display:block;}
        .mlp-socials-heading{font-weight:700;font-size:0.75rem;color:#334155;text-transform:uppercase;margin:0 0 8px;}
        .mlp-author-initials{width:38px;height:38px;background:linear-gradient(135deg,#4dccff,#a78bfa);border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:1rem;}
        .mlp-si-discord{background:#5865f2;color:#fff;border-radius:4px;padding:2px 6px;font-size:0.65rem;font-weight:700;text-decoration:none;cursor:default;}
        .mlp-si-youtube{background:#ff0000;color:#fff;border-radius:4px;padding:2px 6px;font-size:0.65rem;font-weight:700;text-decoration:none;}
        .mlp-si-twitter{background:#1da1f2;color:#fff;border-radius:4px;padding:2px 6px;font-size:0.65rem;font-weight:700;text-decoration:none;}
        .mlp-si-github{background:#24292e;color:#fff;border-radius:4px;padding:2px 6px;font-size:0.65rem;font-weight:700;text-decoration:none;}
        .mlp-si-web{color:#4dccff;font-size:1rem;text-decoration:none;}
        </style>
        <?php
    }

    // ──────────────────────────────────────────────
    //  WP ADMIN: Handle form submissions
    // ──────────────────────────────────────────────
    public static function handle_admin_actions() {
        if (!isset($_POST['mlp_cb_action']) || !current_user_can('manage_options')) return;
        check_admin_referer('mlp_cb_nonce');

        $builds = self::get_saved_builds();

        if ($_POST['mlp_cb_action'] === 'add') {
            // Handle image upload
            $image_url = '';
            if (!empty($_FILES['mlp_image']['name'])) {
                $uploaded = self::handle_image_upload($_FILES['mlp_image']);
                if ($uploaded) {
                    $image_url = $uploaded;
                }
            }

            $new = array(
                'id'          => uniqid('mlp_'),
                'title'       => sanitize_text_field($_POST['mlp_title']   ?? ''),
                'author'      => sanitize_text_field($_POST['mlp_author']  ?? ''),
                'description' => sanitize_textarea_field($_POST['mlp_desc']    ?? ''),
                'category'    => sanitize_text_field($_POST['mlp_category']?? 'websites'),
                'icon'        => sanitize_text_field($_POST['mlp_icon']    ?? 'fas fa-code'),
                'color'       => sanitize_hex_color($_POST['mlp_color']    ?? '#4dccff') ?: '#4dccff',
                'date'        => date('M Y'),
                'timestamp'   => time(),
                'image_url'   => $image_url,
                'html'        => wp_unslash($_POST['mlp_html'] ?? ''),
                'css'         => wp_unslash($_POST['mlp_css']  ?? ''),
                'js'          => wp_unslash($_POST['mlp_js']   ?? ''),
            );
            if ($new['title'] && $new['author']) {
                array_unshift($builds, $new);
                update_option('mlp_community_builds', $builds);
                wp_redirect(add_query_arg(array('page' => 'mlp-community-builds', 'saved' => '1'), admin_url('admin.php')));
                exit;
            }
        }

        if ($_POST['mlp_cb_action'] === 'delete') {
            $del_id = sanitize_text_field($_POST['mlp_delete_id'] ?? '');
            $builds = array_filter($builds, function($b) use ($del_id) { return $b['id'] !== $del_id; });
            update_option('mlp_community_builds', array_values($builds));
            self::purge_cloudflare_cache();
            wp_redirect(add_query_arg(array('page' => 'mlp-community-builds', 'deleted' => '1'), admin_url('admin.php')));
            exit;
        }

        if ($_POST['mlp_cb_action'] === 'save_cf_settings') {
            update_option('mlp_cf_zone_id',   sanitize_text_field($_POST['mlp_cf_zone_id']   ?? ''));
            update_option('mlp_cf_api_token', sanitize_text_field($_POST['mlp_cf_api_token'] ?? ''));
            update_option('mlp_cf_page_url',  esc_url_raw($_POST['mlp_cf_page_url']          ?? home_url('/')));
            wp_redirect(add_query_arg(array('page' => 'mlp-community-builds', 'cf_saved' => '1'), admin_url('admin.php')));
            exit;
        }
    }

    // ──────────────────────────────────────────────
    //  Handle image upload
    // ──────────────────────────────────────────────
    private static function handle_image_upload($file) {
        if (!function_exists('wp_handle_upload')) {
            require_once(ABSPATH . 'wp-admin/includes/file.php');
        }
        
        $upload_overrides = array('test_form' => false);
        $uploaded = wp_handle_upload($file, $upload_overrides);
        
        if ($uploaded && !isset($uploaded['error'])) {
            return $uploaded['url'];
        }
        return false;
    }

    // ──────────────────────────────────────────────
    //  Cloudflare: Purge page cache after changes
    // ──────────────────────────────────────────────
    public static function purge_cloudflare_cache() {
        $zone_id  = get_option('mlp_cf_zone_id', '');
        $api_token = get_option('mlp_cf_api_token', '');
        if (!$zone_id || !$api_token) return; // not configured, skip silently

        $page_url = get_option('mlp_cf_page_url', home_url('/'));

        wp_remote_post(
            'https://api.cloudflare.com/client/v4/zones/' . $zone_id . '/purge_cache',
            array(
                'timeout' => 10,
                'headers' => array(
                    'Authorization' => 'Bearer ' . $api_token,
                    'Content-Type'  => 'application/json',
                ),
                'body' => wp_json_encode(array(
                    'files' => array( $page_url ),
                )),
            )
        );
    }

    // ──────────────────────────────────────────────
    //  WP ADMIN: Render the admin page
    // ──────────────────────────────────────────────
    public static function render_admin_page() {
        $builds = self::get_saved_builds();
        $saved   = isset($_GET['saved']);
        $deleted = isset($_GET['deleted']);
        ?>
        <div class="wrap mlp-cb-admin-wrap">
            <div class="mlp-cb-header">
                <div class="mlp-cb-header-title">
                    <span class="dashicons dashicons-layout"></span>
                    <h1>Community Builds Manager</h1>
                </div>
                <p class="mlp-cb-header-desc">Curate and manage HTML/CSS/JS templates submitted by the community.</p>
            </div>

            <?php if ($saved): ?>
                <div class="notice notice-success is-dismissible"><p>✅ Template added successfully!</p></div>
            <?php endif; ?>
            <?php if ($deleted): ?>
                <div class="notice notice-warning is-dismissible"><p>🗑️ Template deleted.</p></div>
            <?php endif; ?>

            <div class="mlp-cb-admin-layout">
                <!-- Add Template Form -->
                <div class="mlp-cb-admin-card form-card">
                    <div class="card-header">
                        <span class="dashicons dashicons-plus-alt"></span>
                        <h2>Submit New Build</h2>
                    </div>
                    <form method="post" action="" enctype="multipart/form-data">
                        <?php wp_nonce_field('mlp_cb_nonce'); ?>
                        <input type="hidden" name="mlp_cb_action" value="add" />

                        <div class="mlp-cb-form-grid">
                            <div class="mlp-cb-form-col">
                                <div class="mlp-cb-field-group">
                                    <label>Build Title <span class="required">*</span></label>
                                    <input type="text" name="mlp_title" required placeholder="e.g., Cyberpunk Dashboard" />
                                </div>
                                <div class="mlp-cb-field-group">
                                    <label>Author <span class="required">*</span></label>
                                    <?php
                                    $registered_authors = self::get_saved_authors();
                                    ?>
                                    <?php if (empty($registered_authors)): ?>
                                        <p style="color:#ef4444;font-size:0.78rem;margin:0;">&#9888; No authors yet. <a href="<?php echo admin_url('admin.php?page=mlp-community-authors'); ?>">Create an author first.</a></p>
                                        <input type="text" name="mlp_author" required placeholder="Or type a name manually" />
                                    <?php else: ?>
                                        <div class="mlp-author-select-wrap">
                                            <div class="mlp-author-search-box" style="position:relative;"><span style="position:absolute;left:12px;top:50%;transform:translateY(-50%);color:#9ca3af;pointer-events:none;">🔍</span>
                                                <input type="text" id="mlp_author_search" autocomplete="off" placeholder="Search author..." style="padding-left:34px;" />
                                            </div>
                                            <div class="mlp-author-dropdown" id="mlp_author_dropdown">
                                                <?php foreach ($registered_authors as $ra): ?>
                                                <div class="mlp-author-option" data-name="<?php echo esc_attr($ra['name']); ?>">
                                                    <?php if (!empty($ra['avatar'])): ?>
                                                        <img src="<?php echo esc_url($ra['avatar']); ?>" class="mlp-author-opt-avatar" />
                                                    <?php else: ?>
                                                        <div class="mlp-author-opt-initials"><?php echo mb_strtoupper(mb_substr($ra['name'],0,1)); ?></div>
                                                    <?php endif; ?>
                                                    <span><?php echo esc_html($ra['name']); ?></span>
                                                </div>
                                                <?php endforeach; ?>
                                            </div>
                                        </div>
                                        <input type="hidden" name="mlp_author" id="mlp_author_value" required />
                                        <p class="mlp-author-selected-label" id="mlp_author_selected_label" style="display:none;margin:6px 0 0;font-size:0.78rem;color:#22c55e;">&#10003; Selected: <strong id="mlp_author_selected_name"></strong> <button type="button" onclick="document.getElementById('mlp_author_value').value='';document.getElementById('mlp_author_selected_label').style.display='none';document.getElementById('mlp_author_search').value='';document.getElementById('mlp_author_dropdown').style.display='block';" style="background:none;border:none;color:#ef4444;cursor:pointer;font-size:0.7rem;">&#10007; Change</button></p>
                                    <?php endif; ?>
                                </div>
                                <div class="mlp-cb-field-group">
                                    <label>Short Description</label>
                                    <textarea name="mlp_desc" rows="2" placeholder="Briefly describe what this template does..."></textarea>
                                </div>
                                <div class="mlp-cb-field-group">
                                    <label>Category</label>
                                    <select name="mlp_category">
                                        <option value="websites">🌐 Websites</option>
                                        <option value="games">🎮 Games</option>
                                        <option value="animations">✨ Animations</option>
                                        <option value="ui-components">🧩 UI Components</option>
                                        <option value="utilities">⚙️ Utilities</option>
                                        <option value="ai">🤖 AI</option>
                                    </select>
                                </div>
                            </div>

                            <div class="mlp-cb-form-col">
                                <div class="mlp-cb-field-group">
                                    <label>Icon Class <small>(FontAwesome)</small></label>
                                    <input type="text" name="mlp_icon" value="fas fa-code" placeholder="fas fa-rocket" />
                                </div>
                                <div class="mlp-cb-field-group">
                                    <label>Accent Color</label>
                                    <input type="color" name="mlp_color" value="#4dccff" />
                                </div>
                                <div class="mlp-cb-field-group">
                                    <label>Screenshot Image</label>
                                    <input type="file" name="mlp_image" accept="image/jpeg,image/png,image/gif,image/webp" />
                                    <p class="field-hint">Recommended size: 600x400px</p>
                                </div>
                            </div>
                        </div>

                        <div class="mlp-cb-code-section">
                            <div class="code-header">
                                <span class="dashicons dashicons-editor-code"></span>
                                <span>Build Code</span>
                            </div>
                            <div class="mlp-cb-tabs" id="mlp-cb-tabs">
                                <button type="button" class="mlp-cb-tab active" data-pane="html">HTML</button>
                                <button type="button" class="mlp-cb-tab" data-pane="css">CSS</button>
                                <button type="button" class="mlp-cb-tab" data-pane="js">JS</button>
                            </div>
                            <div class="mlp-cb-pane" id="mlp-cb-pane-html">
                                <textarea name="mlp_html" class="mlp-cb-code" rows="10" placeholder="<!-- Your HTML here -->"></textarea>
                            </div>
                            <div class="mlp-cb-pane" id="mlp-cb-pane-css" style="display:none;">
                                <textarea name="mlp_css" class="mlp-cb-code" rows="10" placeholder="/* Your CSS here */"></textarea>
                            </div>
                            <div class="mlp-cb-pane" id="mlp-cb-pane-js" style="display:none;">
                                <textarea name="mlp_js" class="mlp-cb-code" rows="10" placeholder="// Your JavaScript here"></textarea>
                            </div>
                        </div>

                        <div class="form-actions">
                            <button type="submit" class="button button-primary mlp-cb-submit-btn">
                                <span class="dashicons dashicons-saved"></span>
                                Publish Build
                            </button>
                        </div>
                    </form>
                </div>

                <!-- Existing Templates Table -->
                <div class="mlp-cb-admin-card templates-card">
                    <div class="card-header">
                        <span class="dashicons dashicons-list-view"></span>
                        <h2>Existing Builds</h2>
                        <span class="mlp-cb-count"><?php echo count($builds); ?></span>
                    </div>

                    <?php if (empty($builds)): ?>
                        <div class="mlp-cb-empty-state">
                            <span class="dashicons dashicons-inbox"></span>
                            <p>No builds yet. Submit your first template above!</p>
                        </div>
                    <?php else: ?>
                        <div class="mlp-cb-table-wrapper">
                            <table class="wp-list-table widefat fixed striped">
                                <thead>
                                    <tr><th>Preview</th><th>Title / Author</th><th>Category</th><th>Date</th><th>Actions</th></tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($builds as $build): ?>
                                    <tr>
                                        <td>
                                            <?php if (!empty($build['image_url'])): ?>
                                                <img src="<?php echo esc_url($build['image_url']); ?>" class="mlp-cb-thumbnail" />
                                            <?php else: ?>
                                                <div class="mlp-cb-thumbnail-placeholder"><span class="dashicons dashicons-format-image"></span></div>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <strong><?php echo esc_html($build['title']); ?></strong>
                                            <div class="mlp-cb-author-meta"><span class="dashicons dashicons-admin-users"></span> <?php echo esc_html($build['author']); ?></div>
                                        </td>
                                        <td><span class="mlp-cb-badge"><?php echo esc_html(ucwords(str_replace('-', ' ', $build['category']))); ?></span></td>
                                        <td><?php echo esc_html($build['date']); ?></td>
                                        <td>
                                            <form method="post" style="display:inline;" onsubmit="return confirm('Delete this template?');">
                                                <?php wp_nonce_field('mlp_cb_nonce'); ?>
                                                <input type="hidden" name="mlp_cb_action" value="delete" />
                                                <input type="hidden" name="mlp_delete_id" value="<?php echo esc_attr($build['id']); ?>" />
                                                <button type="submit" class="button button-small mlp-cb-delete-btn"><span class="dashicons dashicons-trash"></span></button>
                                            </form>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Cloudflare Cache Settings -->
            <div class="mlp-cb-admin-card" style="margin-top:30px;">
                <div class="card-header">
                    <span class="dashicons dashicons-cloud" style="color:#f6821f;font-size:22px;width:22px;height:22px;"></span>
                    <h2>Cloudflare Cache Settings</h2>
                </div>
                <form method="post" action="" style="padding:24px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;align-items:end;">
                    <?php wp_nonce_field('mlp_cb_nonce'); ?>
                    <input type="hidden" name="mlp_cb_action" value="save_cf_settings" />
                    <div class="mlp-cb-field-group">
                        <label>Cloudflare Zone ID</label>
                        <input type="text" name="mlp_cf_zone_id" value="<?php echo esc_attr(get_option('mlp_cf_zone_id','')); ?>" placeholder="e.g. a1b2c3d4e5f6..." />
                        <p class="field-hint" style="font-size:0.72rem;color:#64748b;margin:4px 0 0;">Found in your domain's Overview page on Cloudflare.</p>
                    </div>
                    <div class="mlp-cb-field-group">
                        <label>Cloudflare API Token</label>
                        <input type="password" name="mlp_cf_api_token" value="<?php echo esc_attr(get_option('mlp_cf_api_token','')); ?>" placeholder="Your CF API token" />
                        <p class="field-hint" style="font-size:0.72rem;color:#64748b;margin:4px 0 0;">Needs <strong>Cache Purge</strong> permission. Create at cloudflare.com → Profile → API Tokens.</p>
                    </div>
                    <div class="mlp-cb-field-group">
                        <label>Page URL to Purge</label>
                        <input type="url" name="mlp_cf_page_url" value="<?php echo esc_attr(get_option('mlp_cf_page_url', home_url('/'))); ?>" placeholder="<?php echo esc_attr(home_url('/')); ?>" />
                        <p class="field-hint" style="font-size:0.72rem;color:#64748b;margin:4px 0 0;">URL of the page where the Community Builds shortcode lives.</p>
                    </div>
                    <div style="grid-column:1/-1;">
                        <button type="submit" class="button button-primary mlp-cb-submit-btn">
                            <span class="dashicons dashicons-saved"></span> Save Cloudflare Settings
                        </button>
                        <?php if (isset($_GET['cf_saved'])): ?>
                            <span style="color:#22c55e;margin-left:12px;font-size:0.85rem;">&#10003; Settings saved!</span>
                        <?php endif; ?>
                    </div>
                </form>
            </div>
        </div>

        <style>
        .mlp-cb-admin-wrap{max-width:1300px;margin:20px 20px 0 0;}
        .mlp-cb-header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:24px 30px;border-radius:12px;margin-bottom:25px;color:#fff;}
        .mlp-cb-header-title{display:flex;align-items:center;gap:12px;}
        .mlp-cb-header-title .dashicons{font-size:32px;width:32px;height:32px;color:#4dccff;}
        .mlp-cb-header-title h1{margin:0;font-size:1.8rem;font-weight:600;background:linear-gradient(135deg,#fff,#4dccff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
        .mlp-cb-header-desc{margin:8px 0 0 44px;opacity:0.8;}
        .mlp-cb-admin-layout{display:flex;flex-direction:column;gap:30px;}
        .mlp-cb-admin-card{background:#fff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.06);border:1px solid #e2e8f0;}
        .card-header{display:flex;align-items:center;gap:10px;padding:18px 24px;background:#f8fafc;border-bottom:1px solid #e2e8f0;}
        .card-header .dashicons{font-size:22px;color:#4dccff;}
        .card-header h2{margin:0;font-size:1.2rem;font-weight:600;color:#1e293b;}
        .mlp-cb-count{background:#4dccff;color:#fff;border-radius:30px;padding:2px 10px;font-size:0.75rem;font-weight:700;margin-left:auto;}
        .mlp-cb-form-grid{display:grid;grid-template-columns:1fr 1fr;gap:28px;padding:24px;}
        .mlp-cb-form-col{display:flex;flex-direction:column;gap:18px;}
        .mlp-cb-field-group{display:flex;flex-direction:column;gap:6px;}
        .mlp-cb-field-group label{font-weight:600;font-size:0.8rem;color:#334155;text-transform:uppercase;}
        .mlp-cb-field-group input:not([type="color"]),.mlp-cb-field-group select,.mlp-cb-field-group textarea{padding:10px 12px;border:1.5px solid #e2e8f0;border-radius:8px;}
        .mlp-cb-field-group input:focus,.mlp-cb-field-group select:focus,.mlp-cb-field-group textarea:focus{border-color:#4dccff;outline:none;box-shadow:0 0 0 3px rgba(77,204,255,0.1);}
        .mlp-cb-field-group input[type="color"]{width:60px;height:40px;border-radius:8px;}
        .required{color:#ef4444;margin-left:3px;}
        .field-hint{font-size:0.7rem;color:#64748b;margin:0;}
        .mlp-cb-code-section{margin:0 24px 24px;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;}
        .code-header{background:#f8fafc;padding:12px 18px;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;gap:8px;font-weight:600;}
        .mlp-cb-tabs{display:flex;background:#fff;border-bottom:1px solid #e2e8f0;padding:0 12px;}
        .mlp-cb-tab{background:none;border:none;padding:12px 20px;cursor:pointer;font-weight:600;color:#64748b;}
        .mlp-cb-tab.active{color:#4dccff;border-bottom:2px solid #4dccff;}
        .mlp-cb-code{width:100%;border:none;font-family:monospace;font-size:0.8rem;padding:18px;background:#0f172a;color:#e2e8f0;resize:vertical;}
        .form-actions{padding:16px 24px 24px;border-top:1px solid #e2e8f0;background:#f8fafc;}
        .mlp-cb-submit-btn{background:#4dccff !important;border-color:#3ab5e8 !important;color:#fff !important;padding:8px 24px !important;border-radius:6px !important;}
        .mlp-cb-thumbnail{width:50px;height:40px;object-fit:cover;border-radius:6px;}
        .mlp-cb-thumbnail-placeholder{width:50px;height:40px;background:#f1f5f9;border-radius:6px;display:flex;align-items:center;justify-content:center;color:#cbd5e1;}
        .mlp-cb-author-meta{display:flex;align-items:center;gap:6px;font-size:0.7rem;color:#64748b;margin-top:4px;}
        .mlp-cb-badge{display:inline-block;padding:4px 12px;border-radius:30px;font-size:0.7rem;font-weight:600;background:#4dccff20;color:#4dccff;}
        .mlp-cb-delete-btn{color:#ef4444 !important;border-color:#fecaca !important;}
        .mlp-cb-empty-state{text-align:center;padding:50px;color:#94a3b8;}
        @media(max-width:900px){.mlp-cb-form-grid{grid-template-columns:1fr;}}
        /* Author searchable dropdown */
        .mlp-author-select-wrap{position:relative;}
        .mlp-author-search-box input{width:100%;padding:10px 12px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:0.85rem;}
        .mlp-author-search-box input:focus{border-color:#4dccff;outline:none;box-shadow:0 0 0 3px rgba(77,204,255,0.1);}
        .mlp-author-dropdown{background:#fff;border:1.5px solid #e2e8f0;border-radius:8px;max-height:200px;overflow-y:auto;margin-top:4px;}
        .mlp-author-option{display:flex;align-items:center;gap:10px;padding:8px 12px;cursor:pointer;transition:background 0.12s;}
        .mlp-author-option:hover{background:#f0f9ff;}
        .mlp-author-option.hidden{display:none;}
        .mlp-author-opt-avatar{width:28px;height:28px;border-radius:50%;object-fit:cover;flex-shrink:0;}
        .mlp-author-opt-initials{width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,#4dccff,#a78bfa);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:0.8rem;flex-shrink:0;}
        .mlp-author-option span{font-size:0.85rem;color:#1e293b;font-weight:500;}
        </style>
        <script>
        (function(){
            var searchInput = document.getElementById('mlp_author_search');
            var dropdown = document.getElementById('mlp_author_dropdown');
            var hiddenInput = document.getElementById('mlp_author_value');
            var selectedLabel = document.getElementById('mlp_author_selected_label');
            var selectedName = document.getElementById('mlp_author_selected_name');
            if (!searchInput || !dropdown) return;
            searchInput.addEventListener('input', function() {
                var q = this.value.toLowerCase();
                dropdown.style.display = 'block';
                dropdown.querySelectorAll('.mlp-author-option').forEach(function(opt) {
                    var name = opt.dataset.name.toLowerCase();
                    opt.classList.toggle('hidden', q.length > 0 && name.indexOf(q) === -1);
                });
            });
            dropdown.querySelectorAll('.mlp-author-option').forEach(function(opt) {
                opt.addEventListener('click', function() {
                    var name = this.dataset.name;
                    hiddenInput.value = name;
                    searchInput.value = name;
                    if (selectedLabel) { selectedLabel.style.display = 'block'; selectedName.textContent = name; }
                    dropdown.style.display = 'none';
                });
            });
            document.addEventListener('click', function(e) {
                if (!searchInput.contains(e.target) && !dropdown.contains(e.target)) {
                    if (hiddenInput && hiddenInput.value) dropdown.style.display = 'none';
                }
            });
            // Tab-support for admin code tabs (html/css/js)
            var tabs = document.querySelectorAll('.mlp-cb-tab');
            tabs.forEach(function(tab) {
                tab.addEventListener('click', function() {
                    tabs.forEach(function(t){ t.classList.remove('active'); });
                    this.classList.add('active');
                    var pane = this.dataset.pane;
                    ['html','css','js'].forEach(function(p) {
                        var el = document.getElementById('mlp-cb-pane-' + p);
                        if (el) el.style.display = (p === pane) ? '' : 'none';
                    });
                });
            });
        })();
        </script>
        <?php
    }

    // ──────────────────────────────────────────────
    //  FRONTEND OVERLAY - Professional View Modal
    // ──────────────────────────────────────────────
    public static function render_overlay($instance_id) {
        ?>
        <div class="mlp-community-overlay" id="mlp-community-overlay-<?php echo esc_attr($instance_id); ?>" style="display:none;">

                <!-- ── NEW BRANDED HEADER (full width, outside container) ── -->
                <div class="mlp-brand-header">
                    <div class="mlp-brand-header-left">
                        <img src="http://pterocos.eu.org/wp-content/uploads/2026/04/Logo_numerique_de_pterocos.eu_.org-removebg-preview.png" alt="Pterocos Logo" class="mlp-brand-logo" />
                    </div>
                    <div class="mlp-brand-header-right">
                        <span class="mlp-brand-site">pterocos.eu.org</span>
                    </div>
                </div>

            <div class="mlp-community-container">
                <div class="mlp-community-topbar">
                    <button class="mlp-community-back-btn" data-instance="<?php echo esc_attr($instance_id); ?>">
                        <i class="fas fa-arrow-left"></i>
                        <span>Back to Editor</span>
                    </button>
                    <div class="mlp-community-topbar-center">
                    </div>
                    <div class="mlp-community-topbar-right">
                        <?php if (current_user_can('manage_options')): ?>
                        <a href="<?php echo esc_url(admin_url('admin.php?page=mlp-community-builds')); ?>" target="_blank" class="mlp-community-add-btn">
                            <i class="fas fa-cog"></i> Manage
                        </a>
                        <?php else: ?>
                        <!-- Author session buttons — state managed by JS -->
                        <div id="mlp-author-session-btns" style="display:flex;gap:8px;align-items:center;">
                            <button id="mlp-author-login-btn" class="mlp-community-add-btn" style="cursor:pointer;border:1px solid #d1d5db;display:flex;background:#fff;color:#374151;">
                                <i class="fas fa-sign-in-alt"></i> Log In
                            </button>
                            <button id="mlp-add-template-btn" class="mlp-community-add-btn" style="cursor:pointer;border:1px solid #2563eb;background:#2563eb;color:#fff;display:flex;align-items:center;gap:6px;font-weight:700;" onclick="document.getElementById('mlp-add-template-modal').style.display='flex'">
                                <i class="fas fa-plus"></i> Add Template
                            </button>
                            <button id="mlp-author-manager-btn" class="mlp-community-add-btn" style="cursor:pointer;border:1px solid #7c3aed;display:none;background:rgba(124,58,237,0.08);color:#7c3aed;">
                                <i class="fas fa-layer-group"></i> My Templates
                            </button>
                            <button id="mlp-author-logout-btn" class="mlp-community-add-btn" style="cursor:pointer;border:1px solid #dc2626;display:none;background:rgba(220,38,38,0.06);color:#dc2626;">
                                <i class="fas fa-sign-out-alt"></i> Log Out
                            </button>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="mlp-community-hero">
                    <h1 class="mlp-community-hero-title">Explore Community Builds</h1>
                    <p class="mlp-community-hero-desc">Discover templates, projects, and creative builds shared by the community.</p>
                    <div class="mlp-community-search-wrap">
                        <i class="fas fa-search mlp-community-search-icon"></i>
                        <input type="text" class="mlp-community-search" data-instance="<?php echo esc_attr($instance_id); ?>" placeholder="Search builds..." />
                    </div>
                    <div class="mlp-community-filters" data-instance="<?php echo esc_attr($instance_id); ?>">
                        <button class="mlp-community-filter active" data-filter="all">All</button>
                        <button class="mlp-community-filter" data-filter="websites">Websites</button>
                        <button class="mlp-community-filter" data-filter="games">Games</button>
                        <button class="mlp-community-filter" data-filter="animations">Animations</button>
                        <button class="mlp-community-filter" data-filter="ui-components">UI Components</button>
                        <button class="mlp-community-filter" data-filter="utilities">Utilities</button>
                        <button class="mlp-community-filter" data-filter="ai">AI</button>
                    </div>
                </div>

                <?php
                $all_builds = self::get_community_builds();
                $now = time();
                $one_day = 86400;
                $new_builds = array_filter($all_builds, function($b) use ($now, $one_day) {
                    $ts = isset($b['timestamp']) ? intval($b['timestamp']) : 0;
                    return $ts > 0 && ($now - $ts) <= $one_day;
                });
                $new_builds = array_values($new_builds);
                $new_initial = 15;
                $explore_initial = 30;
                ?>

                <?php if (!empty($new_builds)): ?>
                <div class="mlp-section-header" id="mlp-new-section-<?php echo esc_attr($instance_id); ?>">
                    <div class="mlp-section-title-row">
                        <i class="fas fa-sparkles" style="color:#f59e0b;"></i>
                        <h2 class="mlp-section-title">New Templates</h2>
                        <span class="mlp-section-count"><?php echo count($new_builds); ?></span>
                    </div>
                </div>
                <div class="mlp-community-grid mlp-grid-rows" id="mlp-new-grid-<?php echo esc_attr($instance_id); ?>">
                    <?php
                    foreach ($new_builds as $idx => $build) {
                        $hidden = $idx >= $new_initial ? ' style="display:none;"' : '';
                        self::render_single_card($build, $hidden, true);
                    }
                    ?>
                </div>
                <?php if (count($new_builds) > $new_initial): ?>
                <div class="mlp-more-wrap" id="mlp-new-more-<?php echo esc_attr($instance_id); ?>">
                    <button class="mlp-more-btn" data-section="new" data-instance="<?php echo esc_attr($instance_id); ?>">
                        <i class="fas fa-plus-circle"></i> More New Templates (<?php echo count($new_builds) - $new_initial; ?> more)
                    </button>
                </div>
                <?php endif; ?>
                <?php endif; ?>

                <div class="mlp-section-header" id="mlp-explore-section-<?php echo esc_attr($instance_id); ?>">
                    <div class="mlp-section-title-row">
                        <i class="fas fa-compass" style="color:#2563eb;"></i>
                        <h2 class="mlp-section-title">Explore Templates</h2>
                        <span class="mlp-section-count"><?php echo count($all_builds); ?></span>
                    </div>
                </div>
                <div class="mlp-community-grid mlp-grid-rows" id="mlp-community-grid-<?php echo esc_attr($instance_id); ?>">
                    <?php
                    foreach ($all_builds as $idx => $build) {
                        $hidden = $idx >= $explore_initial ? ' style="display:none;"' : '';
                        self::render_single_card($build, $hidden, false);
                    }
                    ?>
                </div>
                <?php if (count($all_builds) > $explore_initial): ?>
                <div class="mlp-more-wrap" id="mlp-explore-more-<?php echo esc_attr($instance_id); ?>">
                    <button class="mlp-more-btn" data-section="explore" data-instance="<?php echo esc_attr($instance_id); ?>">
                        <i class="fas fa-plus-circle"></i> More Templates (<?php echo count($all_builds) - $explore_initial; ?> more)
                    </button>
                </div>
                <?php endif; ?>

                <div class="mlp-community-empty" id="mlp-community-empty-<?php echo esc_attr($instance_id); ?>" style="display:none;">
                    <i class="fas fa-box-open"></i>
                    <p>No builds found matching your search.</p>
                </div>

                <div class="mlp-community-footer">
                    <p>Want to share your build? Join our Discord server and submit under the rules channel.</p>
                    <a href="https://discord.com" target="_blank" rel="noopener noreferrer" class="mlp-brand-discord-link" style="display:inline-flex;margin-top:10px;"><i class="fab fa-discord"></i> Join Discord Server</a>
                </div>
            </div>
        </div>

        <!-- Spigot-Style Fullscreen View Modal (outside overlay so it can be truly fullscreen) -->
        <div id="mlp-view-modal" style="display:none;">
            <div class="mlp-modal-overlay">

                <!-- ── ORANGE BREADCRUMB HEADER ── -->
                <div class="mlp-modal-topbar">
                    <div class="mlp-topbar-breadcrumb">
                        <button class="mlp-modal-back-btn" id="mlp-modal-back-btn">
                            <i class="fas fa-arrow-left"></i> Back
                        </button>
                        <i class="fas fa-chevron-right mlp-bc-sep"></i>
                        <span class="mlp-bc-item mlp-bc-active" id="modal-topbar-title"></span>
                    </div>
                </div>

                <!-- ── PAGE BODY ── -->
                <div class="mlp-modal-body">

                    <!-- MAIN CONTENT -->
                    <div class="mlp-modal-main">

                        <!-- Plugin title row -->
                        <div class="mlp-plugin-header">
                            <div class="mlp-plugin-icon" id="modal-plugin-icon">
                                <i class="fas fa-code"></i>
                            </div>
                            <div class="mlp-plugin-title-col">
                                <h1 class="mlp-plugin-name">
                                    <span id="modal-title"></span>
                                </h1>
                                <p class="mlp-plugin-tagline" id="modal-description-short"></p>
                            </div>
                            <button id="modal-load-btn" class="mlp-load-now-btn">
                                <i class="fas fa-upload"></i>
                                Load Now
                            </button>
                        </div>

                        <!-- Tabs -->
                        <div class="mlp-page-tabs">
                            <button class="mlp-page-tab active" data-tab="overview">Overview</button>
                            <button class="mlp-page-tab" data-tab="code">Code</button>
                            <button class="mlp-page-tab" data-tab="preview">Preview</button>
                        </div>

                        <!-- Tab: Overview -->
                        <div class="mlp-tab-pane active" id="mlp-tab-overview">
                            <div class="mlp-overview-meta-rows">
                                <div class="mlp-overview-meta-row">
                                    <span class="mlp-ovm-label">Author:</span>
                                    <span class="mlp-ovm-value mlp-ovm-accent mlp-author-link" id="modal-author-overview" style="cursor:pointer;text-decoration:underline;"></span>
                                </div>
                                <div class="mlp-overview-meta-row">
                                    <span class="mlp-ovm-label">Category:</span>
                                    <span class="mlp-ovm-value mlp-ovm-accent" id="modal-category-overview"></span>
                                </div>
                                <div class="mlp-overview-meta-row">
                                    <span class="mlp-ovm-label">Released:</span>
                                    <span class="mlp-ovm-value" id="modal-date-overview"></span>
                                </div>
                            </div>
                            <div class="mlp-overview-banner">
                                <img id="modal-preview-img" src="" alt="Preview" style="display:none;" />
                                <div class="mlp-modal-preview-placeholder" id="modal-preview-placeholder">
                                    <i class="fas fa-code"></i>
                                    <span>No preview image</span>
                                </div>
                            </div>
                            <div class="mlp-overview-desc">
                                <h3>About this Build</h3>
                                <p id="modal-description"></p>
                            </div>
                            <div class="mlp-overview-actions-row">
                                <button id="modal-run-live" class="mlp-live-btn">
                                    <i class="fas fa-play"></i> Run Live Preview
                                </button>
                                <button id="modal-report-btn" class="mlp-report-inline-btn">
                                    <i class="fas fa-flag"></i> Report
                                </button>
                            </div>
                        </div>

                        <!-- Tab: Code -->
                        <div class="mlp-tab-pane" id="mlp-tab-code" style="display:none;">
                            <div class="mlp-code-toolbar">
                                <div class="mlp-code-tabs">
                                    <button class="mlp-code-tab active" data-code="html"><i class="fab fa-html5"></i> HTML</button>
                                    <button class="mlp-code-tab" data-code="css"><i class="fab fa-css3-alt"></i> CSS</button>
                                    <button class="mlp-code-tab" data-code="js"><i class="fab fa-js-square"></i> JS</button>
                                </div>
                            </div>
                            <pre id="modal-code-display" class="mlp-code-display"></pre>
                        </div>

                        <!-- Tab: Preview -->
                        <div class="mlp-tab-pane" id="mlp-tab-preview" style="display:none;">
                            <div class="mlp-preview-iframe-wrap">
                                <iframe id="modal-preview-frame" class="mlp-preview-iframe" sandbox="allow-scripts"></iframe>
                                <div class="mlp-preview-notice"><i class="fas fa-info-circle"></i> Live render of the build's HTML/CSS/JS</div>
                            </div>
                        </div>

                    </div>

                    <!-- SIDEBAR -->
                    <div class="mlp-modal-sidebar">

                        <div class="mlp-sidebar-box">
                            <div class="mlp-sidebar-box-header">
                                <i class="fas fa-info-circle"></i> INFORMATION
                            </div>
                            <div class="mlp-sidebar-box-body">
                                <div class="mlp-sb-row"><span>Author</span><span id="sb-author" class="mlp-author-link" style="cursor:pointer;color:#e8821a;text-decoration:underline;"></span></div>
                                <div class="mlp-sb-row"><span>Released</span><span id="sb-date"></span></div>
                                <div class="mlp-sb-row"><span>Category</span><span id="sb-category"></span></div>
                            </div>
                        </div>

                    </div>

                </div>
            </div>
        </div>

        <!-- Author Builds Fullscreen Popup -->
        <div id="mlp-author-modal" style="display:none;">
            <div class="mlp-modal-overlay">
                <div class="mlp-modal-topbar">
                    <div class="mlp-topbar-breadcrumb">
                        <button class="mlp-modal-back-btn" id="mlp-author-back-btn">
                            <i class="fas fa-arrow-left"></i> Back
                        </button>
                        <i class="fas fa-chevron-right mlp-bc-sep"></i>
                        <span class="mlp-bc-item mlp-bc-active">Author: <span id="mlp-author-modal-name"></span></span>
                    </div>
                </div>
                <div class="mlp-author-modal-body">
                    <div class="mlp-author-modal-header">
                        <div class="mlp-author-avatar-wrap" id="mlp-author-avatar-wrap">
                            <img id="mlp-author-avatar-img" src="" alt="" style="display:none;" class="mlp-author-avatar-img" />
                            <div id="mlp-author-avatar-icon" class="mlp-author-avatar"><i class="fas fa-user-circle"></i></div>
                        </div>
                        <div style="flex:1;min-width:0;">
                            <h2 id="mlp-author-modal-title"></h2>
                            <p id="mlp-author-modal-bio" style="color:#555;font-size:0.82rem;margin:4px 0 6px;line-height:1.5;"></p>
                            <p id="mlp-author-modal-count" style="color:#888;font-size:0.78rem;margin:0;"></p>
                            <div id="mlp-author-modal-socials" class="mlp-author-socials-row" style="margin-top:10px;display:none;"></div>
                        </div>
                    </div>
                    <div class="mlp-author-grid" id="mlp-author-grid"></div>
                </div>
                <?php
                // Emit all author data as JS so frontend can read socials/bio/avatar
                $all_authors = self::get_saved_authors();
                ?>
                <script>
                window.mlpAuthorsData = <?php echo json_encode(array_values($all_authors)); ?>;
                </script>
            </div>
        </div>

        <!-- Author Login Modal -->
        <div id="mlp-author-login-modal" style="display:none;">
            <div class="mlp-report-overlay" style="z-index:1000002;">
                <div class="mlp-report-container" style="max-width:380px;">
                    <div class="mlp-report-header">
                        <strong><i class="fas fa-user-circle" style="color:#2563eb;margin-right:6px;"></i> Author Login</strong>
                        <button class="mlp-report-close" id="mlp-login-modal-close">&times;</button>
                    </div>
                    <div class="mlp-report-content">
                        <div id="mlp-login-error" style="display:none;background:#fef2f2;border:1px solid #fecaca;color:#dc2626;padding:9px 14px;border-radius:8px;font-size:0.82rem;margin-bottom:14px;"></div>
                        <div class="mlp-cb-field-group" style="margin-bottom:14px;">
                            <label style="font-size:0.75rem;font-weight:700;color:#374151;text-transform:uppercase;display:block;margin-bottom:6px;">Author Name</label>
                            <input type="text" id="mlp-login-author-name" placeholder="Type your author name" style="width:100%;background:#f9fafb;border:1px solid #d1d5db;color:#111827;padding:10px 12px;border-radius:8px;font-size:0.85rem;box-sizing:border-box;" autocomplete="off" />
                        </div>
                        <div class="mlp-cb-field-group" style="margin-bottom:20px;">
                            <label style="font-size:0.75rem;font-weight:700;color:#374151;text-transform:uppercase;display:block;margin-bottom:6px;">Password</label>
                            <input type="password" id="mlp-login-password" placeholder="Your password" style="width:100%;background:#f9fafb;border:1px solid #d1d5db;color:#111827;padding:10px 12px;border-radius:8px;font-size:0.85rem;box-sizing:border-box;" />
                        </div>
                        <div class="mlp-report-actions">
                            <button id="mlp-login-submit-btn" class="mlp-login-submit-btn" style="background:#2563eb;border:1px solid #1d4ed8;color:#fff;font-weight:700;padding:9px 20px;border-radius:8px;cursor:pointer;font-size:0.85rem;display:flex;align-items:center;gap:6px;">
                                <i class="fas fa-sign-in-alt"></i> Log In
                            </button>
                            <button class="mlp-report-cancel" id="mlp-login-cancel-btn">Cancel</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Add Template Modal -->
        <div id="mlp-add-template-modal" style="display:none;position:fixed;inset:0;z-index:1000010;align-items:center;justify-content:center;background:rgba(0,0,0,0.4);backdrop-filter:blur(6px);">
            <div style="background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;max-width:460px;width:90%;padding:0;overflow:hidden;box-shadow:0 25px 60px rgba(0,0,0,0.15),0 0 0 1px rgba(0,0,0,0.04);">
                <!-- Header -->
                <div style="background:linear-gradient(135deg,#f8fafc,#eef2ff);border-bottom:1px solid #e5e7eb;padding:22px 26px 18px;display:flex;align-items:center;justify-content:space-between;">
                    <div style="display:flex;align-items:center;gap:12px;">
                        <div style="width:38px;height:38px;background:#2563eb;border-radius:10px;display:flex;align-items:center;justify-content:center;">
                            <i class="fas fa-plus" style="color:#fff;font-size:0.9rem;"></i>
                        </div>
                        <div>
                            <div style="color:#111827;font-weight:800;font-size:1rem;letter-spacing:-0.01em;">Add Your Template</div>
                            <div style="color:#6b7280;font-size:0.72rem;margin-top:1px;">Share your build with the community</div>
                        </div>
                    </div>
                    <button onclick="document.getElementById('mlp-add-template-modal').style.display='none'" style="background:#f3f4f6;border:1px solid #e5e7eb;color:#6b7280;width:30px;height:30px;border-radius:8px;cursor:pointer;font-size:1.1rem;display:flex;align-items:center;justify-content:center;transition:all .2s;" onmouseover="this.style.background='#fee2e2';this.style.color='#dc2626'" onmouseout="this.style.background='#f3f4f6';this.style.color='#6b7280'">&times;</button>
                </div>
                <!-- Body -->
                <div style="padding:26px 26px 10px;">
                    <!-- Step indicator -->
                    <div style="display:flex;align-items:center;gap:10px;margin-bottom:22px;">
                        <div style="display:flex;align-items:center;gap:6px;background:#eef2ff;border:1px solid #c7d2fe;border-radius:20px;padding:5px 12px;">
                            <i class="fab fa-discord" style="color:#5865f2;font-size:0.85rem;"></i>
                            <span style="color:#4338ca;font-size:0.75rem;font-weight:600;">Via Discord</span>
                        </div>
                        <div style="flex:1;height:1px;background:linear-gradient(90deg,#c7d2fe,transparent);"></div>
                    </div>
                    <!-- Instructions -->
                    <p style="color:#4b5563;font-size:0.82rem;line-height:1.65;margin:0 0 20px;">To submit your template to the Community Builds library, join our Discord server and contact a staff member in the <strong style="color:#111827;">#support</strong> channel. Our team will review and add it for you.</p>
                    <!-- Steps -->
                    <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:24px;">
                        <div style="display:flex;align-items:flex-start;gap:12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:12px 14px;">
                            <div style="min-width:24px;height:24px;background:#2563eb;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:0.7rem;font-weight:800;color:#fff;">1</div>
                            <div>
                                <div style="color:#111827;font-size:0.8rem;font-weight:700;margin-bottom:2px;">Join our Discord</div>
                                <div style="color:#6b7280;font-size:0.75rem;">Click the button below to open the server invite.</div>
                            </div>
                        </div>
                        <div style="display:flex;align-items:flex-start;gap:12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:12px 14px;">
                            <div style="min-width:24px;height:24px;background:#2563eb;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:0.7rem;font-weight:800;color:#fff;">2</div>
                            <div>
                                <div style="color:#111827;font-size:0.8rem;font-weight:700;margin-bottom:2px;">Go to #support</div>
                                <div style="color:#6b7280;font-size:0.75rem;">Find the support channel and open a ticket or message staff.</div>
                            </div>
                        </div>
                        <div style="display:flex;align-items:flex-start;gap:12px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:12px 14px;">
                            <div style="min-width:24px;height:24px;background:#2563eb;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:0.7rem;font-weight:800;color:#fff;">3</div>
                            <div>
                                <div style="color:#111827;font-size:0.8rem;font-weight:700;margin-bottom:2px;">Submit your template</div>
                                <div style="color:#6b7280;font-size:0.75rem;">Share your HTML/CSS/JS and a preview image. Staff will add it for you.</div>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- Footer -->
                <div style="padding:0 26px 22px;display:flex;flex-direction:column;gap:10px;">
                    <a href="https://discord.gg/4vZ4Vz2gyX" target="_blank" rel="noopener noreferrer" style="display:flex;align-items:center;justify-content:center;gap:10px;background:linear-gradient(135deg,#5865f2,#4752c4);color:#fff;text-decoration:none;font-weight:800;font-size:0.88rem;padding:13px 20px;border-radius:10px;transition:all .2s;letter-spacing:0.01em;box-shadow:0 4px 20px rgba(88,101,242,0.25);" onmouseover="this.style.transform='translateY(-1px)';this.style.boxShadow='0 8px 28px rgba(88,101,242,0.4)'" onmouseout="this.style.transform='';this.style.boxShadow='0 4px 20px rgba(88,101,242,0.25)'">
                        <i class="fab fa-discord" style="font-size:1.05rem;"></i>
                        Join Discord &amp; Contact Support
                        <i class="fas fa-external-link-alt" style="font-size:0.7rem;opacity:0.7;"></i>
                    </a>
                    <button onclick="document.getElementById('mlp-add-template-modal').style.display='none'" style="background:transparent;border:1px solid #e5e7eb;color:#6b7280;font-size:0.8rem;padding:9px;border-radius:8px;cursor:pointer;transition:all .2s;" onmouseover="this.style.borderColor='#d1d5db';this.style.color='#374151'" onmouseout="this.style.borderColor='#e5e7eb';this.style.color='#6b7280'">Maybe Later</button>
                </div>
            </div>
        </div>

        <!-- Author My Templates Manager Modal -->
        <div id="mlp-author-manager-modal" style="display:none;">
            <div class="mlp-modal-overlay">
                <div class="mlp-modal-topbar">
                    <div class="mlp-topbar-breadcrumb">
                        <button class="mlp-modal-back-btn" id="mlp-manager-back-btn">
                            <i class="fas fa-arrow-left"></i> Back
                        </button>
                        <i class="fas fa-chevron-right mlp-bc-sep"></i>
                        <span class="mlp-bc-item mlp-bc-active"><i class="fas fa-layer-group"></i> My Templates</span>
                    </div>
                    <div style="margin-left:auto;display:flex;align-items:center;gap:10px;padding-right:4px;">
                        <span id="mlp-manager-logged-as" style="font-size:0.78rem;color:rgba(255,255,255,0.7);"></span>
                    </div>
                </div>
                <div class="mlp-author-modal-body">
                    <div class="mlp-author-modal-header" style="margin-bottom:20px;">
                        <div id="mlp-manager-avatar-wrap">
                            <img id="mlp-manager-avatar-img" src="" alt="" style="display:none;" class="mlp-author-avatar-img" />
                            <div id="mlp-manager-avatar-icon" class="mlp-author-avatar"><i class="fas fa-user-circle"></i></div>
                        </div>
                        <div>
                            <h2 id="mlp-manager-author-name" style="margin:0 0 4px;"></h2>
                            <p style="color:#888;font-size:0.82rem;margin:0;" id="mlp-manager-template-count"></p>
                        </div>
                    </div>
                    <div id="mlp-manager-empty" style="display:none;text-align:center;padding:60px 20px;color:#888;">
                        <i class="fas fa-inbox" style="font-size:2rem;display:block;margin-bottom:12px;opacity:0.4;"></i>
                        <p>You haven't published any templates yet.</p>
                    </div>
                    <div class="mlp-author-grid" id="mlp-manager-grid"></div>
                </div>
            </div>
        </div>

        <!-- Report Modal -->
        <div id="mlp-report-modal" style="display:none;">
            <div class="mlp-report-overlay">
                <div class="mlp-report-container">
                    <div class="mlp-report-header">
                        <strong>Report Build</strong>
                        <button class="mlp-report-close">&times;</button>
                    </div>
                    <div class="mlp-report-content">
                        <p>Reporting: <span id="report-title"></span> by <span id="report-author"></span></p>
                        <textarea id="report-reason" placeholder="Please describe why you're reporting this build..." rows="5"></textarea>
                        <div class="mlp-report-actions">
                            <button class="mlp-report-submit">Submit Report</button>
                            <button class="mlp-report-cancel">Cancel</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <style>
        /* Main Overlay */
        .mlp-community-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:#f8fafc;z-index:999999;overflow-y:auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}
        .mlp-community-container{max-width:1300px;margin:0 auto;padding:0 24px 40px;}
        .mlp-community-topbar{display:flex;align-items:center;justify-content:space-between;padding:16px 0;border-bottom:1px solid #e5e7eb;position:sticky;top:0;background:#f8fafc;z-index:100;}
        /* ── NEW BRAND HEADER ── */
        .mlp-brand-header{display:flex;align-items:center;justify-content:space-between;padding:14px 30px;width:100%;box-sizing:border-box;background:linear-gradient(135deg,#f97316 0%,#ea580c 60%,#c2410c 100%);box-shadow:0 4px 20px rgba(249,115,22,0.45);position:relative;overflow:hidden;}
        .mlp-brand-header::before{content:'';position:absolute;inset:0;background:url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.04'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");pointer-events:none;}
        .mlp-brand-header-left{display:flex;align-items:center;z-index:1;}
        .mlp-brand-logo{height:140px;width:auto;max-width:380px;object-fit:contain;filter:drop-shadow(0 2px 8px rgba(0,0,0,0.25));}
        .mlp-brand-header-center{display:flex;align-items:center;z-index:1;}
        .mlp-brand-tagline{color:rgba(255,255,255,0.9);font-size:0.82rem;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;}
        .mlp-brand-header-right{display:flex;align-items:center;z-index:1;}
        .mlp-brand-site{color:rgba(255,255,255,0.75);font-size:0.78rem;font-weight:500;letter-spacing:0.04em;border:1px solid rgba(255,255,255,0.3);padding:4px 12px;border-radius:20px;background:rgba(255,255,255,0.1);}
        .mlp-brand-discord-link{display:flex;align-items:center;gap:6px;color:#fff;text-decoration:none;font-size:0.75rem;font-weight:700;background:#5865f2;border:1px solid rgba(255,255,255,0.2);padding:5px 13px;border-radius:20px;transition:background 0.15s,transform 0.15s;}
        .mlp-brand-discord-link:hover{background:#4752c4;transform:translateY(-1px);}
        .mlp-community-back-btn{display:flex;align-items:center;gap:8px;background:#fff;border:1px solid #d1d5db;color:#374151;padding:8px 16px;cursor:pointer;border-radius:8px;font-size:0.82rem;font-weight:600;transition:all 0.15s;}
        .mlp-community-back-btn:hover{background:#f3f4f6;color:#111827;border-color:#9ca3af;}
        .mlp-community-topbar-title{color:#111827;font-weight:700;}
        .mlp-community-add-btn{display:flex;align-items:center;gap:6px;background:#fff;border:1px solid #d1d5db;color:#374151;padding:8px 18px;border-radius:8px;text-decoration:none;font-size:0.82rem;font-weight:600;transition:all 0.15s;}
        .mlp-community-add-btn:hover{background:#f3f4f6;border-color:#9ca3af;}
        .mlp-community-hero{text-align:center;padding:40px 0 30px;}
        .mlp-community-hero-title{font-size:2rem;color:#111827;margin:0 0 10px;font-weight:800;}
        .mlp-community-hero-desc{color:#6b7280;font-size:0.85rem;margin-bottom:28px;}
        .mlp-community-search-wrap{position:relative;max-width:420px;margin:0 auto 20px;}
        .mlp-community-search-icon{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:#9ca3af;pointer-events:none;z-index:2;line-height:1;}
        .mlp-community-search{width:100% !important;padding:11px 16px 11px 40px !important;background:#fff !important;border:1px solid #d1d5db !important;color:#111827 !important;border-radius:10px !important;font-size:0.85rem !important;box-sizing:border-box !important;}
        .mlp-community-search:focus{border-color:#2563eb;outline:none;box-shadow:0 0 0 3px rgba(37,99,235,0.1);}
        .mlp-community-filters{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-bottom:20px;}
        .mlp-community-filter{background:#fff;border:1px solid #e5e7eb;color:#6b7280;padding:6px 16px;cursor:pointer;border-radius:20px;font-size:0.75rem;font-weight:500;transition:all 0.15s;}
        .mlp-community-filter:hover{border-color:#d1d5db;color:#374151;}
        .mlp-community-filter.active{background:#2563eb;border-color:#2563eb;color:#fff;}
        
        /* Section Headers */
        .mlp-section-header{padding:20px 0 0;}
        .mlp-section-title-row{display:flex;align-items:center;gap:10px;}
        .mlp-section-title{font-size:1.3rem;font-weight:800;color:#111827;margin:0;}
        .mlp-section-count{background:#e5e7eb;color:#374151;border-radius:20px;padding:2px 10px;font-size:0.72rem;font-weight:700;}
        .mlp-new-badge{display:inline-block;background:linear-gradient(135deg,#f59e0b,#ef4444);color:#fff;font-size:0.6rem;font-weight:800;padding:2px 8px;border-radius:10px;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px;}
        .mlp-new-card{border:1px solid rgba(245,158,11,0.3);box-shadow:0 0 0 1px rgba(245,158,11,0.08);}
        .mlp-more-wrap{text-align:center;padding:16px 0 24px;}
        .mlp-more-btn{background:#fff;border:1px solid #d1d5db;color:#374151;padding:10px 28px;border-radius:10px;font-size:0.82rem;font-weight:600;cursor:pointer;transition:all 0.15s;display:inline-flex;align-items:center;gap:8px;}
        .mlp-more-btn:hover{background:#f3f4f6;border-color:#9ca3af;color:#111827;}

        /* Cards Grid — row-based layout: 2 rows visible, scroll for more */
        .mlp-community-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:24px;padding:20px 0;}
        .mlp-grid-rows{grid-auto-rows:auto;}
        .mlp-community-card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;transition:all 0.3s;cursor:pointer;}
        .mlp-community-card:hover{transform:translateY(-4px);border-color:#d1d5db;box-shadow:0 12px 32px rgba(0,0,0,0.08);}
        .mlp-community-card-preview{height:160px;overflow:hidden;background:#f3f4f6;}
        .mlp-community-card-preview img{width:100%;height:100%;object-fit:cover;transition:transform 0.3s;}
        .mlp-community-card:hover .mlp-community-card-preview img{transform:scale(1.05);}
        .mlp-community-card-preview-placeholder{height:100%;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#eef2ff,#e0e7ff);color:#2563eb;font-size:2.5rem;}
        .mlp-community-card-info{padding:16px;}
        .mlp-community-card-title{font-size:1rem;font-weight:700;color:#111827;margin-bottom:6px;}
        .mlp-community-card-author{font-size:0.7rem;color:#6b7280;display:flex;align-items:center;gap:6px;}
        .mlp-community-card-footer{padding:12px 16px;border-top:1px solid #f3f4f6;display:flex;gap:10px;}
        .mlp-community-view-btn{flex:1;background:#2563eb;border:1px solid #1d4ed8;color:#fff;padding:8px;cursor:pointer;border-radius:8px;font-size:0.75rem;font-weight:600;transition:all 0.15s;}
        .mlp-community-view-btn:hover{background:#1d4ed8;}
        
        /* ── Spigot-Style Fullscreen View Modal ── */
        @keyframes mlpFsIn{from{opacity:0}to{opacity:1}}

        #mlp-view-modal{position:fixed;inset:0;background:#f0f0f0;z-index:1000000;overflow-y:auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;animation:mlpFsIn 0.18s ease both;}
        .mlp-modal-overlay{display:flex;flex-direction:column;min-height:100%;}

        /* Orange header */
        .mlp-modal-topbar{background:linear-gradient(135deg,#e8821a,#f0a030);height:44px;display:flex;align-items:center;padding:0 20px;flex-shrink:0;box-shadow:0 2px 6px rgba(0,0,0,0.25);}
        .mlp-topbar-breadcrumb{display:flex;align-items:center;gap:8px;font-size:0.82rem;font-weight:600;color:rgba(255,255,255,0.9);}
        .mlp-modal-back-btn{display:flex;align-items:center;gap:6px;background:rgba(0,0,0,0.18);border:none;color:#fff;padding:5px 14px;border-radius:4px;cursor:pointer;font-size:0.78rem;font-weight:700;transition:background 0.15s;}
        .mlp-modal-back-btn:hover{background:rgba(0,0,0,0.32);}
        .mlp-bc-sep{font-size:0.6rem;opacity:0.7;}
        .mlp-bc-item{color:rgba(255,255,255,0.85);}
        .mlp-bc-active{color:#fff;font-weight:700;}

        /* Page body */
        .mlp-modal-body{display:flex;flex:1 0 auto;min-height:calc(100vh - 44px);max-width:1280px;width:100%;margin:0 auto;padding:24px 20px 40px;gap:22px;box-sizing:border-box;align-items:flex-start;}

        /* MAIN */
        .mlp-modal-main{flex:1;min-width:0;display:flex;flex-direction:column;gap:0;min-height:calc(100vh - 44px);}

        /* Plugin header row */
        .mlp-plugin-header{background:#fff;border:1px solid #ddd;border-radius:4px 4px 0 0;padding:16px 20px;display:flex;align-items:center;gap:14px;border-bottom:none;}
        .mlp-plugin-icon{width:52px;height:52px;background:linear-gradient(135deg,#2563eb,#1d4ed8);border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:1.4rem;flex-shrink:0;}
        .mlp-plugin-title-col{flex:1;min-width:0;}
        .mlp-plugin-name{font-size:1.35rem;font-weight:700;color:#222;margin:0 0 4px;display:flex;align-items:baseline;gap:8px;}
        .mlp-plugin-version{font-size:0.9rem;font-weight:400;color:#888;}
        .mlp-plugin-tagline{font-size:0.82rem;color:#666;margin:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
        .mlp-load-now-btn{background:linear-gradient(135deg,#4a90d9,#357abd);border:1px solid #2a6099;color:#fff;padding:10px 22px;border-radius:4px;cursor:pointer;font-weight:700;font-size:0.85rem;display:flex;align-items:center;gap:8px;white-space:nowrap;transition:all 0.15s;flex-shrink:0;}
        .mlp-load-now-btn:hover{background:linear-gradient(135deg,#357abd,#2a6099);box-shadow:0 2px 8px rgba(74,144,217,0.4);}

        /* Page tabs (Spigot style) */
        .mlp-page-tabs{display:flex;background:#fff;border:1px solid #ddd;border-top:none;border-bottom:none;padding:0 20px;}
        .mlp-page-tab{background:none;border:none;border-bottom:3px solid transparent;padding:10px 18px;font-size:0.82rem;font-weight:600;color:#666;cursor:pointer;transition:all 0.15s;margin-bottom:-1px;}
        .mlp-page-tab:hover{color:#333;background:#f7f7f7;}
        .mlp-page-tab.active{color:#e8821a;border-bottom-color:#e8821a;}

        /* Tab panes */
        .mlp-tab-pane{background:#fff;border:1px solid #ddd;border-top:1px solid #e0e0e0;padding:20px;border-radius:0 0 4px 4px;flex:1;}

        /* Overview meta rows */
        .mlp-overview-meta-rows{display:grid;grid-template-columns:1fr 1fr;gap:8px 24px;padding-bottom:16px;border-bottom:1px solid #eee;margin-bottom:16px;}
        .mlp-overview-meta-row{display:flex;align-items:center;gap:6px;font-size:0.82rem;}
        .mlp-ovm-label{color:#666;font-weight:500;min-width:90px;}
        .mlp-ovm-value{color:#333;font-weight:600;}
        .mlp-ovm-accent{color:#e8821a;}

        /* Banner image */
        .mlp-overview-banner{border-radius:4px;overflow:hidden;margin-bottom:16px;background:#1a1a2e;min-height:120px;display:flex;align-items:center;justify-content:center;}
        .mlp-overview-banner img{width:100%;display:block;}
        .mlp-modal-preview-placeholder{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;color:#4dccff;font-size:2rem;padding:40px;opacity:0.5;}
        .mlp-modal-preview-placeholder span{font-size:0.75rem;color:#666;}

        /* Description */
        .mlp-overview-desc h3{font-size:0.9rem;font-weight:700;color:#333;margin:0 0 8px;}
        .mlp-overview-desc p{font-size:0.85rem;color:#555;line-height:1.65;margin:0 0 16px;}

        /* Action row */
        .mlp-overview-actions-row{display:flex;gap:10px;padding-top:4px;}
        .mlp-live-btn{background:linear-gradient(135deg,#4dccff,#3ab5e8);border:none;color:#fff;padding:9px 20px;border-radius:4px;cursor:pointer;font-weight:700;font-size:0.8rem;display:flex;align-items:center;gap:7px;transition:all 0.15s;}
        .mlp-live-btn:hover{box-shadow:0 2px 10px rgba(77,204,255,0.4);transform:translateY(-1px);}
        .mlp-report-inline-btn{background:#fff;border:1px solid #ddd;color:#999;padding:9px 16px;border-radius:4px;cursor:pointer;font-size:0.78rem;display:flex;align-items:center;gap:6px;transition:all 0.15s;}
        .mlp-report-inline-btn:hover{border-color:#ef4444;color:#ef4444;}

        /* Code tab pane */
        .mlp-code-toolbar{display:flex;justify-content:flex-start;padding-bottom:12px;border-bottom:1px solid #eee;margin-bottom:12px;}
        .mlp-code-tabs{display:flex;gap:4px;}
        .mlp-code-tab{background:#f5f5f5;border:1px solid #ddd;padding:5px 14px;border-radius:4px;color:#666;cursor:pointer;font-size:0.75rem;font-weight:600;display:flex;align-items:center;gap:5px;transition:all 0.12s;}
        .mlp-code-tab.active{background:#e8821a;border-color:#c86a0f;color:#fff;}
        .mlp-code-tab:hover:not(.active){background:#eee;color:#333;}
        .mlp-code-display{background:#1e1e2e;padding:18px;border-radius:6px;font-family:'Monaco','Menlo','Courier New',monospace;font-size:0.72rem;color:#cdd6f4;overflow:auto;white-space:pre-wrap;word-break:break-all;line-height:1.75;margin:0;max-height:500px;}

        /* Preview iframe */
        .mlp-preview-iframe-wrap{display:flex;flex-direction:column;gap:8px;}
        .mlp-preview-iframe{width:100%;height:500px;min-height:300px;border:1px solid #ddd;border-radius:4px;background:#fff;}
        .mlp-preview-notice{font-size:0.72rem;color:#888;display:flex;align-items:center;gap:5px;}

        /* SIDEBAR */
        .mlp-modal-sidebar{width:240px;min-width:220px;flex-shrink:0;display:flex;flex-direction:column;gap:16px;}
        .mlp-sidebar-box{background:#fff;border:1px solid #ddd;border-radius:4px;overflow:hidden;}
        .mlp-sidebar-box-header{background:linear-gradient(135deg,#e8821a,#f0a030);color:#fff;font-size:0.72rem;font-weight:700;letter-spacing:0.06em;padding:8px 14px;display:flex;align-items:center;gap:6px;}
        .mlp-sidebar-box-body{padding:0;}
        .mlp-sb-row{display:flex;justify-content:space-between;align-items:center;padding:8px 14px;font-size:0.78rem;border-bottom:1px solid #f0f0f0;gap:8px;}
        .mlp-sb-row:last-child{border-bottom:none;}
        .mlp-sb-row span:first-child{color:#666;}
        .mlp-sb-row span:last-child{color:#333;font-weight:600;text-align:right;}

        /* Responsive */
        @media(max-width:768px){
            .mlp-modal-body{flex-direction:column;padding:16px;}
            .mlp-modal-sidebar{width:100%;min-width:0;}
            .mlp-plugin-header{flex-wrap:wrap;}
            .mlp-overview-meta-rows{grid-template-columns:1fr;}
        }
        
        /* Report Modal */
        .mlp-report-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.4);backdrop-filter:blur(4px);z-index:1000001;display:flex;align-items:center;justify-content:center;}
        .mlp-report-container{background:#fff;border:1px solid #e5e7eb;border-radius:12px;width:90%;max-width:450px;box-shadow:0 20px 50px rgba(0,0,0,0.12);}
        .mlp-report-header{display:flex;justify-content:space-between;padding:16px 20px;border-bottom:1px solid #e5e7eb;font-weight:700;color:#111827;}
        .mlp-report-close{background:none;border:none;font-size:1.5rem;cursor:pointer;color:#9ca3af;}
        .mlp-report-close:hover{color:#374151;}
        .mlp-report-content{padding:20px;}
        .mlp-report-content p{color:#6b7280;font-size:0.85rem;margin-bottom:16px;}
        #report-reason{width:100%;background:#f9fafb;border:1px solid #d1d5db;color:#111827;padding:12px;border-radius:8px;margin-bottom:20px;resize:vertical;font-family:inherit;box-sizing:border-box;}
        #report-reason:focus{border-color:#2563eb;outline:none;box-shadow:0 0 0 3px rgba(37,99,235,0.1);}
        .mlp-report-actions{display:flex;gap:12px;justify-content:flex-end;}
        .mlp-report-submit{background:#dc2626;border:1px solid #b91c1c;color:#fff;padding:8px 20px;border-radius:8px;cursor:pointer;font-weight:600;transition:all 0.15s;}
        .mlp-report-submit:hover{background:#b91c1c;}
        .mlp-report-cancel{background:#fff;border:1px solid #d1d5db;color:#6b7280;padding:8px 20px;border-radius:8px;cursor:pointer;font-weight:500;transition:all 0.15s;}
        .mlp-report-cancel:hover{background:#f3f4f6;color:#374151;}
        
        /* Author Modal */
        #mlp-author-modal{position:fixed;inset:0;background:#f8fafc;z-index:1000001;overflow-y:auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;animation:mlpFsIn 0.18s ease both;}
        #mlp-author-manager-modal{position:fixed;inset:0;background:#f8fafc;z-index:1000001;overflow-y:auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;animation:mlpFsIn 0.18s ease both;}
        .mlp-author-modal-body{max-width:1280px;margin:0 auto;padding:28px 20px 60px;}
        .mlp-author-modal-header{display:flex;align-items:center;gap:22px;background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px 28px;margin-bottom:28px;}
        .mlp-author-avatar{width:72px;height:72px;border-radius:50%;background:linear-gradient(135deg,#e8821a,#f0a030);display:flex;align-items:center;justify-content:center;color:#fff;font-size:2rem;flex-shrink:0;}
        .mlp-author-avatar-img{width:72px;height:72px;border-radius:50%;object-fit:cover;flex-shrink:0;}
        .mlp-author-modal-header h2{font-size:1.4rem;font-weight:700;color:#222;margin:0 0 2px;}
        .mlp-author-socials-row{display:flex;flex-wrap:wrap;gap:8px;}
        .mlp-author-social-btn{display:inline-flex;align-items:center;gap:6px;color:#fff;text-decoration:none;font-size:0.72rem;font-weight:700;padding:5px 12px;border-radius:20px;}
        .mlp-author-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:24px;}
        /* Card author name clickable */
        .mlp-community-card-author-link{cursor:pointer;color:#2563eb;text-decoration:underline;transition:color 0.15s;}
        .mlp-community-card-author-link:hover{color:#1d4ed8;}
        
        .mlp-community-empty{text-align:center;padding:60px;color:#6b7280;}
        .mlp-community-footer{text-align:center;padding:40px 0 20px;border-top:1px solid #e5e7eb;color:#6b7280;font-size:0.75rem;}
        
        </style>

        <script>
        var mlp_ajax = {
            ajax_url: <?php echo json_encode(admin_url('admin-ajax.php')); ?>,
            nonce: <?php echo json_encode(wp_create_nonce('mlp_downloads_nonce')); ?>
        };
        (function() {
            let currentBuildData = null;
            // Track all build cards data for author lookup
            let allBuildsData = [];

            function buildFullDoc(html, css, js) {
                return '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{margin:0;padding:0;box-sizing:border-box;}body{background:#fff;font-family:system-ui;}</style><style>' + css + '</style></head><body>' + html + '<script>' + js + '<\/script></body></html>';
            }

            // ── MORE BUTTONS ──────────────────────────────────────────────
            document.querySelectorAll('.mlp-more-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    var section = this.dataset.section;
                    var instanceId = this.dataset.instance;
                    var gridId = section === 'new' ? 'mlp-new-grid-' + instanceId : 'mlp-community-grid-' + instanceId;
                    var grid = document.getElementById(gridId);
                    if (grid) {
                        grid.querySelectorAll('.mlp-community-card[style*="display:none"], .mlp-community-card[style*="display: none"]').forEach(function(card) {
                            card.style.display = '';
                        });
                    }
                    this.closest('.mlp-more-wrap').style.display = 'none';
                });
            });

            // ── AUTHOR POPUP ──────────────────────────────────────────────
            function openAuthorModal(authorName) {
                const authorBuilds = allBuildsData.filter(b => b.author === authorName);
                const modal = document.getElementById('mlp-author-modal');
                if (!modal) return;

                // Look up registered author profile
                const authorProfile = (window.mlpAuthorsData || []).find(a => a.name === authorName);

                document.getElementById('mlp-author-modal-name').textContent = authorName;
                document.getElementById('mlp-author-modal-title').textContent = authorName;
                document.getElementById('mlp-author-modal-count').textContent =
                    authorBuilds.length + ' build' + (authorBuilds.length !== 1 ? 's' : '') + ' by this author';

                // Avatar
                const avatarImg = document.getElementById('mlp-author-avatar-img');
                const avatarIcon = document.getElementById('mlp-author-avatar-icon');
                if (authorProfile && authorProfile.avatar) {
                    avatarImg.src = authorProfile.avatar;
                    avatarImg.style.display = 'block';
                    if (avatarIcon) avatarIcon.style.display = 'none';
                } else {
                    if (avatarImg) avatarImg.style.display = 'none';
                    if (avatarIcon) avatarIcon.style.display = 'flex';
                }

                // Bio
                const bioEl = document.getElementById('mlp-author-modal-bio');
                if (bioEl) bioEl.textContent = (authorProfile && authorProfile.bio) ? authorProfile.bio : '';

                // Socials
                const socialsRow = document.getElementById('mlp-author-modal-socials');
                if (socialsRow) {
                    socialsRow.innerHTML = '';
                    socialsRow.style.display = 'none';
                    if (authorProfile) {
                        const socials = [
                            { key: 'discord',  label: 'Discord', icon: 'fab fa-discord',  color: '#5865f2', isText: true },
                            { key: 'youtube',  label: 'YouTube', icon: 'fab fa-youtube',  color: '#ff0000', isUrl: true },
                            { key: 'twitter',  label: 'Twitter', icon: 'fab fa-twitter',  color: '#1da1f2', isUrl: true },
                            { key: 'github',   label: 'GitHub',  icon: 'fab fa-github',   color: '#24292e', isUrl: true },
                            { key: 'website',  label: 'Website', icon: 'fas fa-globe',    color: '#4dccff', isUrl: true },
                        ];
                        let hasSocial = false;
                        socials.forEach(s => {
                            const val = authorProfile[s.key];
                            if (!val) return;
                            hasSocial = true;
                            if (s.isUrl) {
                                const a = document.createElement('a');
                                a.href = val; a.target = '_blank'; a.rel = 'noopener';
                                a.className = 'mlp-author-social-btn';
                                a.style.background = s.color;
                                a.innerHTML = '<i class="' + s.icon + '"></i> ' + s.label;
                                socialsRow.appendChild(a);
                            } else {
                                const sp = document.createElement('span');
                                sp.className = 'mlp-author-social-btn';
                                sp.style.background = s.color;
                                sp.title = s.key.charAt(0).toUpperCase() + s.key.slice(1) + ': ' + val;
                                sp.innerHTML = '<i class="' + s.icon + '"></i> ' + escHtml(val);
                                socialsRow.appendChild(sp);
                            }
                        });
                        if (hasSocial) socialsRow.style.display = 'flex';
                    }
                }

                const grid = document.getElementById('mlp-author-grid');
                grid.innerHTML = '';
                if (authorBuilds.length === 0) {
                    grid.innerHTML = '<p style="color:#888;grid-column:1/-1;">No builds found for this author.</p>';
                } else {
                    authorBuilds.forEach(build => {
                        const card = document.createElement('div');
                        card.className = 'mlp-community-card';
                        card.innerHTML =
                            '<div class="mlp-community-card-preview">' +
                                (build.image_url
                                    ? '<img src="' + build.image_url + '" alt="' + escHtml(build.title) + '" />'
                                    : '<div class="mlp-community-card-preview-placeholder"><i class="fas fa-code"></i></div>') +
                            '</div>' +
                            '<div class="mlp-community-card-info">' +
                                '<div class="mlp-community-card-title">' + escHtml(build.title) + '</div>' +
                                '<div class="mlp-community-card-author"><i class="fas fa-user-circle"></i> ' + escHtml(build.author) + '</div>' +
                            '</div>' +
                            '<div class="mlp-community-card-footer">' +
                                '<button class="mlp-community-view-btn"><i class="fas fa-eye"></i> View</button>' +
                            '</div>';
                        card.querySelector('.mlp-community-view-btn').addEventListener('click', function(e) {
                            e.stopPropagation();
                            modal.style.display = 'none';
                            showViewModal(build);
                        });
                        grid.appendChild(card);
                    });
                }

                modal.style.display = 'block';
                modal.scrollTop = 0;
                document.documentElement.style.overflow = 'hidden';
                document.body.style.overflow = 'hidden';
            }

            function escHtml(str) {
                return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
            }

            // ── VIEW MODAL ────────────────────────────────────────────────
            function showViewModal(build) {
                currentBuildData = build;
                const cat = build.category ? (build.category.charAt(0).toUpperCase() + build.category.slice(1).replace(/-/g,' ')) : '';
                const desc = build.description || 'No description provided.';

                document.getElementById('modal-title').textContent = build.title;
                document.getElementById('modal-topbar-title').textContent = build.title;

                const authorOverview = document.getElementById('modal-author-overview');
                const sbAuthor = document.getElementById('sb-author');
                if (authorOverview) authorOverview.textContent = build.author;
                if (sbAuthor) sbAuthor.textContent = build.author;

                document.getElementById('modal-category-overview').textContent = cat;
                document.getElementById('modal-date-overview').textContent = build.date;
                document.getElementById('modal-description').textContent = desc;
                document.getElementById('sb-date').textContent = build.date;
                document.getElementById('sb-category').textContent = cat;

                const taglineEl = document.getElementById('modal-description-short');
                if (taglineEl) taglineEl.textContent = desc;

                const previewImg = document.getElementById('modal-preview-img');
                const placeholder = document.getElementById('modal-preview-placeholder');
                if (build.image_url) {
                    previewImg.src = build.image_url;
                    previewImg.style.display = 'block';
                    if (placeholder) placeholder.style.display = 'none';
                } else {
                    previewImg.style.display = 'none';
                    if (placeholder) placeholder.style.display = 'flex';
                }

                document.getElementById('modal-code-display').textContent = build.html || '<!-- No HTML provided -->';

                document.querySelectorAll('.mlp-page-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.mlp-tab-pane').forEach(p => p.style.display = 'none');
                const overviewTab = document.querySelector('.mlp-page-tab[data-tab="overview"]');
                const overviewPane = document.getElementById('mlp-tab-overview');
                if (overviewTab) overviewTab.classList.add('active');
                if (overviewPane) overviewPane.style.display = 'block';

                document.querySelectorAll('.mlp-code-tab').forEach(t => t.classList.remove('active'));
                const htmlTab = document.querySelector('.mlp-code-tab[data-code="html"]');
                if (htmlTab) htmlTab.classList.add('active');

                // Clear preview iframe
                const frame = document.getElementById('modal-preview-frame');
                if (frame) frame.srcdoc = '';

                const modal = document.getElementById('mlp-view-modal');
                modal.style.display = 'block';
                modal.scrollTop = 0;
                document.documentElement.style.overflow = 'hidden';
                document.body.style.overflow = 'hidden';
                ['wpwrap','wpcontent','wpbody','wpbody-content'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) { el.dataset.mlpOverflow = el.style.overflow; el.style.overflow = 'hidden'; }
                });
            }

            function closeViewModal() {
                const modal = document.getElementById('mlp-view-modal');
                if (modal) modal.style.display = 'none';
                document.documentElement.style.overflow = '';
                document.body.style.overflow = '';
                ['wpwrap','wpcontent','wpbody','wpbody-content'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) { el.style.overflow = el.dataset.mlpOverflow || ''; }
                });
            }

            // ── COLLECT ALL BUILD DATA FROM DOM ───────────────────────────
            function collectBuildsData() {
                allBuildsData = [];
                var seen = {};
                document.querySelectorAll('.mlp-community-card').forEach(card => {
                    var id = card.dataset.id;
                    if (seen[id]) return;
                    seen[id] = true;
                    allBuildsData.push({
                        id: id,
                        title: card.dataset.title,
                        author: card.dataset.author,
                        description: card.dataset.description,
                        category: card.dataset.category,
                        date: card.dataset.date,
                        image_url: card.dataset.imageUrl,
                        html: card.dataset.html,
                        css: card.dataset.css,
                        js: card.dataset.js
                    });
                });
            }

            // ── INIT PER INSTANCE ─────────────────────────────────────────
            function initCommunityBuilds(instanceId) {
                const $overlay = document.getElementById('mlp-community-overlay-' + instanceId);
                if (!$overlay) return;

                const $openBtn = document.querySelector('.mlp-community-open-btn[data-instance="' + instanceId + '"]');
                const $backBtn = $overlay.querySelector('.mlp-community-back-btn');
                const $searchInput = $overlay.querySelector('.mlp-community-search');
                const $filterBtns = $overlay.querySelectorAll('.mlp-community-filter');
                const $grid = document.getElementById('mlp-community-grid-' + instanceId);
                const $empty = document.getElementById('mlp-community-empty-' + instanceId);
                let activeFilter = 'all';

                if ($openBtn) {
                    $openBtn.addEventListener('click', function(e) {
                        e.preventDefault();
                        $overlay.style.display = 'block';
                        document.body.style.overflow = 'hidden';
                    });
                }

                if ($backBtn) {
                    $backBtn.addEventListener('click', function() {
                        $overlay.style.display = 'none';
                        document.body.style.overflow = '';
                    });
                }

                function filterCards() {
                    const query = $searchInput?.value.toLowerCase().trim() || '';
                    let visibleCount = 0;
                    var allGrids = $overlay.querySelectorAll('.mlp-community-grid');
                    allGrids.forEach(function(grid) {
                        var cards = grid.querySelectorAll('.mlp-community-card');
                        var gridVisible = 0;
                        cards.forEach(card => {
                            const category = card.dataset.category;
                            const title = card.dataset.title || '';
                            const author = card.dataset.author || '';
                            const text = (title + ' ' + author).toLowerCase();
                            const categoryMatch = activeFilter === 'all' || category === activeFilter;
                            const searchMatch = !query || text.indexOf(query) !== -1;
                            if (categoryMatch && searchMatch) { card.style.display = ''; visibleCount++; gridVisible++; }
                            else { card.style.display = 'none'; }
                        });
                        grid.style.display = gridVisible > 0 ? 'grid' : 'none';
                    });
                    var allSections = $overlay.querySelectorAll('.mlp-section-header');
                    allSections.forEach(function(sec) {
                        var nextGrid = sec.nextElementSibling;
                        while (nextGrid && !nextGrid.classList.contains('mlp-community-grid')) nextGrid = nextGrid.nextElementSibling;
                        if (nextGrid) sec.style.display = nextGrid.style.display === 'none' ? 'none' : '';
                    });
                    var allMores = $overlay.querySelectorAll('.mlp-more-wrap');
                    allMores.forEach(function(mw) { if (query || activeFilter !== 'all') mw.style.display = 'none'; });
                    if ($empty) {
                        if (visibleCount === 0) { $empty.style.display = 'block'; }
                        else { $empty.style.display = 'none'; }
                    }
                }

                if ($filterBtns) {
                    $filterBtns.forEach(btn => {
                        btn.addEventListener('click', function() {
                            $filterBtns.forEach(b => b.classList.remove('active'));
                            this.classList.add('active');
                            activeFilter = this.dataset.filter;
                            filterCards();
                        });
                    });
                }

                if ($searchInput) $searchInput.addEventListener('input', filterCards);

                // View buttons (all grids including new + explore)
                $overlay.querySelectorAll('.mlp-community-view-btn').forEach(btn => {
                    btn.addEventListener('click', function(e) {
                        e.stopPropagation();
                        const card = this.closest('.mlp-community-card');
                        if (card) {
                            const build = {
                                id: card.dataset.id, title: card.dataset.title,
                                author: card.dataset.author, description: card.dataset.description,
                                category: card.dataset.category, date: card.dataset.date,
                                image_url: card.dataset.imageUrl,
                                html: card.dataset.html, css: card.dataset.css, js: card.dataset.js
                            };
                            showViewModal(build);
                        }
                    });
                });

                // Author name click in cards (grid)
                $overlay.querySelectorAll('.mlp-community-card-author-link').forEach(link => {
                    link.addEventListener('click', function(e) {
                        e.stopPropagation();
                        openAuthorModal(this.dataset.author);
                    });
                });

                filterCards();
            }

            // ── MODAL EVENT HANDLERS ──────────────────────────────────────
            const viewModal = document.getElementById('mlp-view-modal');
            const backBtn = document.getElementById('mlp-modal-back-btn');
            const loadBtn = document.getElementById('modal-load-btn');
            const reportBtn = document.getElementById('modal-report-btn');
            const runLiveBtn = document.getElementById('modal-run-live');
            const codeTabs = document.querySelectorAll('.mlp-code-tab');
            const codeDisplay = document.getElementById('modal-code-display');

            if (backBtn) backBtn.addEventListener('click', closeViewModal);

            if (loadBtn) {
                loadBtn.addEventListener('click', () => {
                    if (!currentBuildData) return;

                    // ALWAYS close all community popups first
                    closeViewModal();
                    ['mlp-author-modal','mlp-author-manager-modal','mlp-report-modal',
                     'mlp-author-login-modal','mlp-add-template-modal'].forEach(function(id) {
                        var el = document.getElementById(id);
                        if (el) el.style.display = 'none';
                    });
                    document.querySelectorAll('[id^="mlp-community-overlay-"]').forEach(function(el) {
                        el.style.display = 'none';
                    });
                    document.body.style.overflow = '';
                    document.documentElement.style.overflow = '';

                    // Try to load into the editor as a new tab
                    var openBtn = document.querySelector('.mlp-community-open-btn');
                    var instanceId = openBtn ? openBtn.dataset.instance : null;

                    if (
                        instanceId &&
                        window.monacoInstances &&
                        window.monacoInstances[instanceId] &&
                        typeof window.mlpCreateTabElement === 'function' &&
                        typeof window.mlpSwitchTab === 'function'
                    ) {
                        var tabId = 'readme-community-' + Date.now();
                        var instances = window.monacoInstances[instanceId];
                        var tabData = {
                            id: tabId,
                            title: currentBuildData.title || 'Community Build',
                            emoji: '🌐',
                            html: currentBuildData.html || '',
                            css: currentBuildData.css || '',
                            js: currentBuildData.js || '',
                            preprocessors: { html: 'none', css: 'none', js: 'none' },
                            isReadOnly: true,
                            isForked: false,
                            active: false
                        };
                        instances.tabs[tabId] = tabData;
                        window.mlpCreateTabElement(instanceId, tabId, tabData.title, tabData.emoji, false, true);
                        window.mlpSwitchTab(instanceId, tabId);
                    } else {
                        // Fallback: open as standalone page in new browser tab
                        var doc = buildFullDoc(currentBuildData.html || '', currentBuildData.css || '', currentBuildData.js || '');
                        var newWin = window.open('', '_blank');
                        if (newWin) { newWin.document.write(doc); newWin.document.close(); }
                    }

                });
            }

            if (runLiveBtn) {
                runLiveBtn.addEventListener('click', () => {
                    document.querySelectorAll('.mlp-page-tab').forEach(t => t.classList.remove('active'));
                    document.querySelectorAll('.mlp-tab-pane').forEach(p => p.style.display = 'none');
                    const previewTab = document.querySelector('.mlp-page-tab[data-tab="preview"]');
                    const previewPane = document.getElementById('mlp-tab-preview');
                    if (previewTab) previewTab.classList.add('active');
                    if (previewPane) previewPane.style.display = 'block';
                    if (currentBuildData) {
                        const frame = document.getElementById('modal-preview-frame');
                        if (frame) frame.srcdoc = buildFullDoc(currentBuildData.html || '', currentBuildData.css || '', currentBuildData.js || '');
                    }
                });
            }

            document.querySelectorAll('.mlp-page-tab').forEach(tab => {
                tab.addEventListener('click', () => {
                    document.querySelectorAll('.mlp-page-tab').forEach(t => t.classList.remove('active'));
                    document.querySelectorAll('.mlp-tab-pane').forEach(p => p.style.display = 'none');
                    tab.classList.add('active');
                    const pane = document.getElementById('mlp-tab-' + tab.dataset.tab);
                    if (pane) pane.style.display = 'block';
                    if (tab.dataset.tab === 'preview' && currentBuildData) {
                        const frame = document.getElementById('modal-preview-frame');
                        if (frame && !frame.srcdoc) {
                            frame.srcdoc = buildFullDoc(currentBuildData.html || '', currentBuildData.css || '', currentBuildData.js || '');
                        }
                    }
                });
            });

            if (codeTabs) {
                codeTabs.forEach(tab => {
                    tab.addEventListener('click', () => {
                        codeTabs.forEach(t => t.classList.remove('active'));
                        tab.classList.add('active');
                        const codeType = tab.dataset.code;
                        if (currentBuildData) {
                            if (codeType === 'html') codeDisplay.textContent = currentBuildData.html || '<!-- No HTML provided -->';
                            else if (codeType === 'css') codeDisplay.textContent = currentBuildData.css || '/* No CSS provided */';
                            else if (codeType === 'js') codeDisplay.textContent = currentBuildData.js || '// No JavaScript provided';
                        }
                    });
                });
            }

            // Author links inside view modal (overview + sidebar)
            document.querySelectorAll('.mlp-author-link').forEach(el => {
                el.addEventListener('click', () => {
                    if (currentBuildData) openAuthorModal(currentBuildData.author);
                });
            });

            // Author modal back button
            const authorBackBtn = document.getElementById('mlp-author-back-btn');
            if (authorBackBtn) {
                authorBackBtn.addEventListener('click', () => {
                    document.getElementById('mlp-author-modal').style.display = 'none';
                    document.documentElement.style.overflow = 'hidden';
                    document.body.style.overflow = 'hidden';
                });
            }

            // Report modal
            const reportModal = document.getElementById('mlp-report-modal');
            const reportClose = document.querySelector('.mlp-report-close');
            const reportCancel = document.querySelector('.mlp-report-cancel');
            const reportSubmit = document.querySelector('.mlp-report-submit');

            if (reportBtn) {
                reportBtn.addEventListener('click', () => {
                    if (currentBuildData) {
                        document.getElementById('report-title').textContent = currentBuildData.title;
                        document.getElementById('report-author').textContent = currentBuildData.author;
                        document.getElementById('report-reason').value = '';
                        reportModal.style.display = 'flex';
                    }
                });
            }

            if (reportClose) reportClose.addEventListener('click', () => { reportModal.style.display = 'none'; });
            if (reportCancel) reportCancel.addEventListener('click', () => { reportModal.style.display = 'none'; });
            if (reportSubmit) {
                reportSubmit.addEventListener('click', () => {
                    const reason = document.getElementById('report-reason').value.trim();
                    if (!reason) { alert('Please provide a reason.'); return; }
                    alert('Thank you for your report. Our team will review this build.');
                    reportModal.style.display = 'none';
                });
            }

            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    const loginModal   = document.getElementById('mlp-author-login-modal');
                    const managerModal = document.getElementById('mlp-author-manager-modal');
                    const authorModal  = document.getElementById('mlp-author-modal');
                    if (loginModal?.style.display === 'block')   { loginModal.style.display = 'none'; return; }
                    if (managerModal?.style.display === 'block')  { managerModal.style.display = 'none'; document.documentElement.style.overflow=''; document.body.style.overflow=''; return; }
                    if (authorModal?.style.display === 'block')  { authorModal.style.display = 'none'; return; }
                    if (viewModal?.style.display === 'block')    { closeViewModal(); return; }
                    if (reportModal?.style.display === 'flex')   { reportModal.style.display = 'none'; return; }
                    const overlay = document.querySelector('.mlp-community-overlay[style*="display: block"]');
                    if (overlay) { overlay.style.display = 'none'; document.body.style.overflow = ''; }
                }
            });

            function mlpInit() {
                collectBuildsData();
                document.querySelectorAll('[id^="mlp-community-overlay-"]').forEach(el => {
                    const id = el.id.replace('mlp-community-overlay-', '');
                    initCommunityBuilds(id);
                });
                initAuthorSession();
            }
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', mlpInit);
            } else {
                mlpInit();
            }

            // ── AUTHOR SESSION ────────────────────────────────────────────
            let authorSession = null; // { id, name, avatar, password_plain, ... }

            function initAuthorSession() {
                // Restore from sessionStorage
                try {
                    const stored = sessionStorage.getItem('mlp_author_session');
                    if (stored) { authorSession = JSON.parse(stored); }
                } catch(e) {}
                applySessionUI();

                // Login button
                const loginBtn = document.getElementById('mlp-author-login-btn');
                if (loginBtn) loginBtn.addEventListener('click', openLoginModal);

                // Logout button
                const logoutBtn = document.getElementById('mlp-author-logout-btn');
                if (logoutBtn) logoutBtn.addEventListener('click', () => {
                    authorSession = null;
                    try { sessionStorage.removeItem('mlp_author_session'); } catch(e) {}
                    applySessionUI();
                });

                // Manager button
                const managerBtn = document.getElementById('mlp-author-manager-btn');
                if (managerBtn) managerBtn.addEventListener('click', openManagerModal);

                // Login modal wiring
                const loginModal = document.getElementById('mlp-author-login-modal');
                document.getElementById('mlp-login-modal-close')?.addEventListener('click', () => { loginModal.style.display = 'none'; });
                document.getElementById('mlp-login-cancel-btn')?.addEventListener('click', () => { loginModal.style.display = 'none'; });
                document.getElementById('mlp-login-submit-btn')?.addEventListener('click', doAuthorLogin);
                document.getElementById('mlp-login-password')?.addEventListener('keydown', e => { if (e.key === 'Enter') doAuthorLogin(); });
                document.getElementById('mlp-login-author-name')?.addEventListener('keydown', e => { if (e.key === 'Enter') doAuthorLogin(); });

                // Manager modal back
                document.getElementById('mlp-manager-back-btn')?.addEventListener('click', () => {
                    document.getElementById('mlp-author-manager-modal').style.display = 'none';
                    document.documentElement.style.overflow = '';
                    document.body.style.overflow = '';
                });
            }

            function applySessionUI() {
                const loginBtn   = document.getElementById('mlp-author-login-btn');
                const managerBtn = document.getElementById('mlp-author-manager-btn');
                const logoutBtn  = document.getElementById('mlp-author-logout-btn');
                if (!loginBtn) return;
                if (authorSession) {
                    loginBtn.style.display   = 'none';
                    managerBtn.style.display = '';
                    logoutBtn.style.display  = '';
                } else {
                    loginBtn.style.display   = '';
                    managerBtn.style.display = 'none';
                    logoutBtn.style.display  = 'none';
                }
            }

            function openLoginModal() {
                const modal = document.getElementById('mlp-author-login-modal');
                const err = document.getElementById('mlp-login-error');
                if (err) { err.style.display = 'none'; err.textContent = ''; }
                document.getElementById('mlp-login-password').value = '';
                document.getElementById('mlp-login-author-name').value = '';
                modal.style.display = 'block';
            }

            function doAuthorLogin() {
                const nameEl   = document.getElementById('mlp-login-author-name');
                const pwEl     = document.getElementById('mlp-login-password');
                const errEl    = document.getElementById('mlp-login-error');
                const btn      = document.getElementById('mlp-login-submit-btn');
                const authorName = nameEl?.value.trim();
                const password = pwEl?.value;
                if (!authorName) { showLoginError('Please enter your author name.'); return; }
                if (!password) { showLoginError('Please enter your password.'); return; }
                // Look up author id by name from the pre-loaded authors data
                const authorData = (window.mlpAuthorsData || []).find(
                    a => a.name.toLowerCase() === authorName.toLowerCase()
                );
                if (!authorData) { showLoginError('Author not found. Check your name and try again.'); return; }
                const authorId = authorData.id;
                btn.disabled = true;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in...';
                fetch(mlp_ajax.ajax_url + '?_t=' + Date.now(), {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({ action: 'mlp_author_login', author_id: authorId, password, nonce: mlp_ajax.nonce })
                })
                .then(r => r.json())
                .then(data => {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Log In';
                    if (data.success) {
                        authorSession = { ...data.data.author, password_plain: password };
                        try { sessionStorage.setItem('mlp_author_session', JSON.stringify(authorSession)); } catch(e) {}
                        document.getElementById('mlp-author-login-modal').style.display = 'none';
                        applySessionUI();
                        openManagerModal();
                    } else {
                        showLoginError(data.data || 'Login failed.');
                    }
                })
                .catch(() => {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Log In';
                    showLoginError('Network error. Please try again.');
                });
            }

            function showLoginError(msg) {
                const el = document.getElementById('mlp-login-error');
                if (!el) return;
                el.textContent = msg;
                el.style.display = 'block';
            }

            function openManagerModal() {
                if (!authorSession) { openLoginModal(); return; }
                const modal = document.getElementById('mlp-author-manager-modal');
                const myBuilds = allBuildsData.filter(b => b.author === authorSession.name);

                // Avatar + name
                const avatarImg  = document.getElementById('mlp-manager-avatar-img');
                const avatarIcon = document.getElementById('mlp-manager-avatar-icon');
                if (authorSession.avatar) {
                    avatarImg.src = authorSession.avatar; avatarImg.style.display = 'block';
                    if (avatarIcon) avatarIcon.style.display = 'none';
                } else {
                    if (avatarImg) avatarImg.style.display = 'none';
                    if (avatarIcon) avatarIcon.style.display = 'flex';
                }
                document.getElementById('mlp-manager-author-name').textContent = authorSession.name;
                document.getElementById('mlp-manager-logged-as').textContent = 'Logged in as: ' + authorSession.name;
                document.getElementById('mlp-manager-template-count').textContent =
                    myBuilds.length + ' template' + (myBuilds.length !== 1 ? 's' : '');

                const grid = document.getElementById('mlp-manager-grid');
                const emptyEl = document.getElementById('mlp-manager-empty');
                grid.innerHTML = '';

                if (myBuilds.length === 0) {
                    emptyEl.style.display = 'block';
                } else {
                    emptyEl.style.display = 'none';
                    myBuilds.forEach(build => {
                        const card = document.createElement('div');
                        card.className = 'mlp-community-card';
                        card.dataset.id = build.id;
                        card.innerHTML =
                            '<div class="mlp-community-card-preview">' +
                                (build.image_url
                                    ? '<img src="' + build.image_url + '" alt="' + escHtml(build.title) + '" />'
                                    : '<div class="mlp-community-card-preview-placeholder"><i class="fas fa-code"></i></div>') +
                            '</div>' +
                            '<div class="mlp-community-card-info">' +
                                '<div class="mlp-community-card-title">' + escHtml(build.title) + '</div>' +
                                '<div class="mlp-community-card-author" style="font-size:0.72rem;color:#94a3b8;margin-top:4px;">' +
                                    '<i class="fas fa-user-circle"></i> ' + escHtml(build.author) +
                                '</div>' +
                            '</div>' +
                            '<div class="mlp-community-card-footer">' +
                                '<button class="mlp-community-view-btn" data-id="' + build.id + '"><i class="fas fa-eye"></i> View</button>' +
                                '<button class="mlp-manager-delete-btn" data-id="' + build.id + '" data-title="' + escHtml(build.title) + '" style="flex:1;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);color:#ef4444;padding:8px;cursor:pointer;border-radius:8px;font-size:0.75rem;font-weight:600;"><i class="fas fa-trash"></i> Remove</button>' +
                            '</div>';

                        // View button
                        card.querySelector('.mlp-community-view-btn').addEventListener('click', () => {
                            modal.style.display = 'none';
                            showViewModal(build);
                            // When view modal closes, re-open manager
                            const origClose = closeViewModal;
                            const managerRestoreHandler = function() {
                                document.getElementById('mlp-modal-back-btn').removeEventListener('click', managerRestoreHandler);
                                openManagerModal();
                            };
                            document.getElementById('mlp-modal-back-btn').addEventListener('click', managerRestoreHandler);
                        });

                        // Delete button
                        card.querySelector('.mlp-manager-delete-btn').addEventListener('click', function() {
                            const buildId    = this.dataset.id;
                            const buildTitle = this.dataset.title;
                            if (!confirm('Are you sure you want to permanently delete "' + buildTitle + '"?\nThis cannot be undone.')) return;
                            const delBtn = this;
                            delBtn.disabled = true;
                            delBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Removing...';
                            fetch(mlp_ajax.ajax_url + '?_t=' + Date.now(), {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                                body: new URLSearchParams({
                                    action: 'mlp_author_delete_build',
                                    author_id: authorSession.id,
                                    build_id: buildId,
                                    password: authorSession.password_plain,
                                    nonce: mlp_ajax.nonce
                                })
                            })
                            .then(r => r.json())
                            .then(data => {
                                if (data.success) {
                                    // Remove from DOM
                                    card.style.transition = 'opacity 0.3s,transform 0.3s';
                                    card.style.opacity = '0'; card.style.transform = 'scale(0.9)';
                                    setTimeout(() => {
                                        card.remove();
                                        // Remove from allBuildsData
                                        allBuildsData = allBuildsData.filter(b => b.id !== buildId);
                                        // Update count
                                        const remaining = allBuildsData.filter(b => b.author === authorSession.name);
                                        document.getElementById('mlp-manager-template-count').textContent =
                                            remaining.length + ' template' + (remaining.length !== 1 ? 's' : '');
                                        if (remaining.length === 0) {
                                            document.getElementById('mlp-manager-empty').style.display = 'block';
                                        }
                                        // Remove from ALL main community grids (not manager grid)
                                        document.querySelectorAll('[id^="mlp-community-grid-"] .mlp-community-card[data-id="' + buildId + '"]').forEach(c => c.remove());
                                    }, 300);
                                } else {
                                    delBtn.disabled = false;
                                    delBtn.innerHTML = '<i class="fas fa-trash"></i> Remove';
                                    alert('Error: ' + (data.data || 'Could not delete.'));
                                }
                            })
                            .catch(() => {
                                delBtn.disabled = false;
                                delBtn.innerHTML = '<i class="fas fa-trash"></i> Remove';
                                alert('Network error.');
                            });
                        });

                        grid.appendChild(card);
                    });
                }

                modal.style.display = 'block';
                modal.scrollTop = 0;
                document.documentElement.style.overflow = 'hidden';
                document.body.style.overflow = 'hidden';
            }
        })();
        </script>
        <?php
    }

    private static function render_single_card($build, $extra_attrs = '', $is_new = false) {
        $category = esc_attr($build['category']);
        $image_url = !empty($build['image_url']) ? esc_url($build['image_url']) : '';
        $html = esc_attr($build['html'] ?? '');
        $css = esc_attr($build['css'] ?? '');
        $js = esc_attr($build['js'] ?? '');
        $author = esc_attr($build['author']);
        $title = esc_attr($build['title']);
        $description = esc_attr($build['description'] ?? '');
        $date = esc_attr($build['date']);
        $build_id = esc_attr($build['id']);
        ?>
        <div class="mlp-community-card<?php echo $is_new ? ' mlp-new-card' : ''; ?>"
             data-category="<?php echo $category; ?>"
             data-id="<?php echo $build_id; ?>"
             data-title="<?php echo $title; ?>"
             data-author="<?php echo $author; ?>"
             data-description="<?php echo $description; ?>"
             data-date="<?php echo $date; ?>"
             data-image-url="<?php echo $image_url; ?>"
             data-html="<?php echo $html; ?>"
             data-css="<?php echo $css; ?>"
             data-js="<?php echo $js; ?>"<?php echo $extra_attrs; ?>>
            <div class="mlp-community-card-preview">
                <?php if ($image_url): ?>
                    <img src="<?php echo $image_url; ?>" alt="<?php echo $title; ?>" />
                <?php else: ?>
                    <div class="mlp-community-card-preview-placeholder">
                        <i class="fas fa-code"></i>
                    </div>
                <?php endif; ?>
            </div>
            <div class="mlp-community-card-info">
                <?php if ($is_new): ?>
                    <span class="mlp-new-badge">NEW</span>
                <?php endif; ?>
                <div class="mlp-community-card-title"><?php echo esc_html($title); ?></div>
                <div class="mlp-community-card-author">
                    <i class="fas fa-user-circle"></i> <span class="mlp-community-card-author-link" data-author="<?php echo $author; ?>"><?php echo esc_html($author); ?></span>
                </div>
            </div>
            <div class="mlp-community-card-footer">
                <button class="mlp-community-view-btn">
                    <i class="fas fa-eye"></i> View
                </button>
            </div>
        </div>
        <?php
    }

    private static function get_community_builds() {
        $saved = self::get_saved_builds();
        $hardcoded = array();
        return array_merge($saved, $hardcoded);
    }

    public static function get_saved_builds() {
        $builds = get_option('mlp_community_builds', array());
        return is_array($builds) ? $builds : array();
    }

    public static function get_styles() { return ''; }
    public static function get_script() { return ''; }
}

add_action('admin_menu', array('MLP_Community_Builds', 'register_admin_menu'));
add_action('admin_init', array('MLP_Community_Builds', 'handle_admin_actions'));
add_action('admin_init', array('MLP_Community_Builds', 'handle_author_actions'));

// Helper: send no-cache headers so Cloudflare never caches AJAX responses
function mlp_nocache_headers() {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
    header('CF-Cache-Status: BYPASS'); // hint to Cloudflare
}

// AJAX: author login
add_action('wp_ajax_nopriv_mlp_author_login', 'mlp_ajax_author_login');
add_action('wp_ajax_mlp_author_login', 'mlp_ajax_author_login');
function mlp_ajax_author_login() {
    mlp_nocache_headers();
    $author_id = sanitize_text_field($_POST['author_id'] ?? '');
    $password  = $_POST['password'] ?? '';
    if (!$author_id || !$password) { wp_send_json_error('Missing credentials'); }
    $author = MLP_Community_Builds::get_author_by_id($author_id);
    if (!$author) { wp_send_json_error('Author not found'); }
    if (empty($author['password'])) { wp_send_json_error('This author has no password set. Ask an admin to add one.'); }
    if (!wp_check_password($password, $author['password'])) { wp_send_json_error('Incorrect password'); }
    // Return safe profile (no password hash)
    $safe = $author;
    unset($safe['password']);
    wp_send_json_success(array('author' => $safe));
}

// AJAX: author delete own template
add_action('wp_ajax_nopriv_mlp_author_delete_build', 'mlp_ajax_author_delete_build');
add_action('wp_ajax_mlp_author_delete_build', 'mlp_ajax_author_delete_build');
function mlp_ajax_author_delete_build() {
    mlp_nocache_headers();
    $author_id = sanitize_text_field($_POST['author_id'] ?? '');
    $build_id  = sanitize_text_field($_POST['build_id'] ?? '');
    $password  = $_POST['password'] ?? '';
    if (!$author_id || !$build_id || !$password) { wp_send_json_error('Missing data'); }
    // Re-verify author credentials
    $author = MLP_Community_Builds::get_author_by_id($author_id);
    if (!$author || empty($author['password'])) { wp_send_json_error('Auth failed'); }
    if (!wp_check_password($password, $author['password'])) { wp_send_json_error('Auth failed'); }
    // Find the build and verify ownership
    $builds = MLP_Community_Builds::get_saved_builds();
    $found = false;
    foreach ($builds as $b) {
        if ($b['id'] === $build_id && $b['author'] === $author['name']) { $found = true; break; }
    }
    if (!$found) { wp_send_json_error('Build not found or not yours'); }
    $builds = array_filter($builds, function($b) use ($build_id) { return $b['id'] !== $build_id; });
    update_option('mlp_community_builds', array_values($builds));
    MLP_Community_Builds::purge_cloudflare_cache();
    wp_send_json_success('deleted');
}
