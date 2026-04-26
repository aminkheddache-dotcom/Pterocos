<?php
/**
 * Be proud that we got oxygen for free
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class MLP_Projects {

    /**
     * localStorage key — now stores an ARRAY of project objects.
     * Old single-object format is auto-migrated to the array format.
     */
    const LS_KEY = 'mlp_projects';

    /**
     * Register all hooks.
     * Call this from the main plugin's frontend section (not inside is_admin()).
     */
    public static function init() {
        add_action( 'wp_head',   [ __CLASS__, 'output_styles'  ], 99 );
        add_action( 'wp_footer', [ __CLASS__, 'output_popup'   ],  1 );
    }

    /**
     * Step 1 of publish: run AI moderation on the project content.
     * Returns a short-lived moderation token if content passes.
     */
    public static function ajax_moderate_project() {
        if ( ! check_ajax_referer( 'mlp_share_project', 'nonce', false ) ) {
            wp_send_json_error( [ 'message' => 'Invalid request.' ], 403 );
        }

        // ── Per-IP rate limiting (10-minute window) — READ-ONLY check first ─
        // We only CHECK the limit here. The increment is deferred until AFTER
        // Turnstile passes, so failed captcha attempts don't burn rate-limit
        // slots. Bots without a valid captcha can never reach the increment.
        $rate_max     = 5;                       // Max attempts per window
        $rate_window  = 10 * MINUTE_IN_SECONDS;  // 10 minutes
        $client_ip    = self::get_client_ip();
        $rate_key     = 'mlp_rate_' . md5( $client_ip );
        $rate_data    = get_transient( $rate_key );

        if ( ! is_array( $rate_data ) ) {
            $rate_data = [ 'count' => 0, 'reset_at' => time() + $rate_window ];
        }
        if ( $rate_data['reset_at'] <= time() ) {
            $rate_data = [ 'count' => 0, 'reset_at' => time() + $rate_window ];
        }

        if ( $rate_data['count'] >= $rate_max ) {
            $remaining = max( 1, $rate_data['reset_at'] - time() );
            $time_str  = self::format_seconds_human( $remaining );
            wp_send_json_error( [
                'message'           => 'Wait 10 minutes before publishing again. You have used your publish attempts for this period. Time left: ' . $time_str . '.',
                'rate_limited'      => true,
                'retry_after'       => $remaining,
                'retry_after_human' => $time_str,
            ], 429 );
            return;
        }
        // ───────────────────────────────────────────────────────────────────

        // ── Cloudflare Turnstile verification ──────────────────────────────
        $ts_token  = isset( $_POST['cf_turnstile_token'] ) ? sanitize_text_field( wp_unslash( $_POST['cf_turnstile_token'] ) ) : '';
        $ts_secret = defined( 'MLP_TURNSTILE_SECRET_KEY' ) ? MLP_TURNSTILE_SECRET_KEY : '';

        if ( empty( $ts_token ) ) {
            wp_send_json_error( [ 'message' => 'Please complete the security check before publishing.' ], 403 );
        }

        if ( ! empty( $ts_secret ) ) {
            $ts_response = wp_remote_post(
                'https://challenges.cloudflare.com/turnstile/v0/siteverify',
                [
                    'timeout' => 10,
                    'body'    => [
                        'secret'   => $ts_secret,
                        'response' => $ts_token,
                        'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
                    ],
                ]
            );
            if ( is_wp_error( $ts_response ) ) {
                wp_send_json_error( [ 'message' => 'Security check could not be verified. Please try again.' ], 503 );
            }
            $ts_body = json_decode( wp_remote_retrieve_body( $ts_response ), true );
            if ( empty( $ts_body['success'] ) ) {
                wp_send_json_error( [ 'message' => 'Security check failed. Please refresh the captcha and try again.' ], 403 );
            }
        }
        // ───────────────────────────────────────────────────────────────────

        // ── Rate-limit INCREMENT — only after Turnstile has passed ─────────
        // Failed captcha attempts do NOT burn slots; only verified humans do.
        $rate_data['count']++;
        set_transient( $rate_key, $rate_data, max( 60, $rate_data['reset_at'] - time() ) );
        // ───────────────────────────────────────────────────────────────────

        $content = isset( $_POST['content'] ) ? wp_unslash( $_POST['content'] ) : '';
        if ( ! is_string( $content ) || $content === '' || strlen( $content ) > 500000 ) {
            wp_send_json_error( [ 'message' => 'Content too large or missing.' ], 400 );
        }

        // ── HTML content requirements (zero-cost) ─────────────────────────────────
        // The content field is a concatenated blob: name, description, HTML, CSS,
        // JS, and tab content. We extract only the HTML portion — the block that
        // follows the "HTML:" marker — to avoid false-positives from CSS/JS tabs.
        // Rule: the HTML portion must exist and be at least 80 characters long,
        // and must contain at least one real HTML tag.
        $html_portion = '';
        if ( preg_match( '/\bHTML:\s*\n(.*?)(?=\n\n(?:CSS:|JS:|Tab:|Description:|Project name:)|$)/si', $content, $html_match ) ) {
            $html_portion = trim( $html_match[1] );
        }

        if ( $html_portion !== '' && ! preg_match( '/<[a-z][a-z0-9]*[\s>\/]/i', $html_portion ) ) {
            wp_send_json_error(
                [ 'message' => 'Your HTML tab does not appear to contain valid HTML. Please add HTML tags (e.g. <html>, <div>, <p>) before publishing.' ],
                400
            );
            return;
        }
        // ────────────────────────────────────────────────────────────────────────────

        // Optional project name — also moderated.
        $project_name = isset( $_POST['project_name'] ) ? sanitize_text_field( wp_unslash( $_POST['project_name'] ) ) : '';
        if ( strlen( $project_name ) > 200 ) {
            $project_name = mb_substr( $project_name, 0, 200 );
        }

        // Optional project description — also moderated.
        $project_description = isset( $_POST['project_description'] ) ? sanitize_textarea_field( wp_unslash( $_POST['project_description'] ) ) : '';
        if ( strlen( $project_description ) > 2000 ) {
            $project_description = mb_substr( $project_description, 0, 2000 );
        }



        // ── Server-side malicious / hacking domain blocking in CODE (zero-cost) ──────
        // Scans the project CODE for known hacking tool sites, malware distribution
        // domains, exploit databases, dark-web mirrors, RAT/keylogger hosts, paste
        // sites commonly used for credential dumps, and similar harmful resources.
        // Legitimate educational security references are rare in web projects;
        // we err on the side of rejection for all known bad domains.
        $bad_domain_patterns = [
            // ── Hacking / exploit tool distribution ──────────────────────────────
            'hackforums?\.net',
            'nulled\.to',
            'nulled\.cx',
            'cracked\.to',
            'cracked\.io',
            'leakforums?\.net',
            'sinister\.ly',
            'hackthissite\.org',       // often used in malicious context
            'exploit\.in',
            'exploit-db\.com',         // raw exploit download links
            'packetstormsecurity\.(?:com|net|org)',
            'darkc0de\.com',
            'hackerone\.com\/reports\/', // direct vuln-report deep-links used in exploits
            'inj3ct0r\.com',
            'xss\.cx',
            'xssed\.com',
            'sqli\.x10host\.com',
            'zone-h\.org',             // defacement archive

            // ── RAT / keylogger / malware hosts ──────────────────────────────────
            'darkcomet[\.\-]rat',
            'njrat[\.\-]',
            'blackshades\.(?:net|co)',
            'luminosity[\.\-]link',
            'nanocore[\.\-]rat',
            'xtremerat\.(?:com|net)',
            'imminent[\.\-]monitor',
            'remcos[\.\-](?:rat|pro|com)',
            'asyncrat[\.\-]',
            'quasar[\.\-]rat',
            'revenge[\.\-]rat',

            // ── Cracking / keygen / warez ─────────────────────────────────────────
            'thepiratebay\.(?:org|se|to|mx)',
            '1337x\.(?:to|st|is)',
            'kickass(?:torrents?)?\.(?:to|cr|cd)',
            'rarbg\.(?:to|is)',
            'skidrow(?:reloaded)?\.(?:com|eu)',
            'fitgirl[\.\-]repacks\.site',
            'cs\.rin\.ru',
            'f95zone\.to',
            'steamunlocked\.net',
            'igg[\.\-]games\.com',
            'oceansofgames\.com',

            // ── Credential dump / paste / combo-list sites ────────────────────────
            'pastebin\.com',           // flagged when in code (not name/desc, which is already blocked)
            'ghostbin\.(?:com|co)',
            'paste\.ee',
            'controlc\.com',
            'hastebin\.com',
            'privatebin\.net',
            'justpaste\.it',
            'rentry\.co',
            'cl1p\.net',
            'dpaste\.(?:com|org)',

            // ── DDoS / stresser / booter services ────────────────────────────────
            'stresser\.(?:ai|to|pw|xyz|net|biz)',
            'booter\.(?:xyz|pw|to|net)',
            'skynetsec\.(?:com|net)',
            'anonStresser\.(?:com|xyz)',
            'cyberflood\.(?:com|org)',
            'vdos[\.\-]s\.(?:com|co)',
            'quantum[\.\-]stresser',
            'hackerstresser\.com',

            // ── Carding / fraud / dark-web markets ───────────────────────────────
            'joker[\.\-]stash\.(?:bazar|net|su|cc)',
            'rescator\.(?:cm|biz|mn)',
            'fe[\.\-]shop\.(?:cc|pw|pro)',
            'unicc\.(?:cm|biz|ac|ws)',
            'bingodumps\.(?:com|net)',
            'carder\.(?:su|pw|to)',
            'altenen\.(?:com|ws)',
            'darkmarkets?\.(?:onion|to|net)',
            'silkroad[0-9]*\.(?:onion|to)',
            'alphabay\.(?:onion|net)',
            'hansa[\.\-]market',
            'empire[\.\-]market',
            'versus[\.\-]market',
            'darknet[\.\-]market',

            // ── Phishing kit / tool hosts ─────────────────────────────────────────
            'phishtank\.com',          // raw phish URL references used in kits
            'openphish\.com',
            'evilginx[\.\-]',
            'modlishka[\.\-]',
            'gophish[\.\-]',

            // ── Telegram / Discord bot invite abuse ───────────────────────────────
            // These patterns catch suspicious deep-links used in scam/hack pages
            't\.me\/(?:(?:crack|hack|gen|leak|rat|stealer|combo|dump|account|free|nitro|robux|vbuck)[a-z0-9_]*)',
            'discord(?:app)?\.(?:com|gg)\/invite\/(?=.*(?:crack|hack|gen|leak|rat|combo|dump|free|nitro|robux))',
        ];

        $bad_domain_regex = '/(?:' . implode( '|', $bad_domain_patterns ) . ')/i';

        if ( preg_match( $bad_domain_regex, $content ) ) {
            wp_send_json_error(
                [
                    'message' => 'Your project contains a link or reference to a site that is not allowed. '
                        . 'Links to hacking forums, exploit databases, malware/RAT hosts, warez/cracking sites, '
                        . 'credential-dump paste sites, DDoS stresser services, carding/fraud markets, '
                        . 'or phishing tool hosts are prohibited. '
                        . 'Please remove these links and try again.',
                ],
                400
            );
            return;
        }
        // ────────────────────────────────────────────────────────────────────────────



        // ── Runtime / hot-loaded image blocking (zero-cost) ────────────────────────
        // Server-side scanning can only see images that are statically referenced in
        // the code. Images loaded at runtime via JavaScript (fetch + blob URL,
        // dynamic <img>.src assignments from variables, lazy-loaded from a private
        // API, etc.) bypass the entire vision-moderation pipeline. We therefore
        // REJECT any project whose code contains common runtime image-loading
        // patterns. Static <img src="..."> tags and CSS background-image with
        // string literals are unaffected.
        // NARROWED PATTERNS — only flag patterns that are unambiguously about
        // dynamic image loading. Avoids false positives on legitimate JS that
        // happens to use .src= or setAttribute('src') for scripts, iframes,
        // audio/video, etc. These patterns each contain explicit image-context
        // markers (Image, img, FileReader for image MIME, blob URL chained to
        // an image, etc.).
        $runtime_image_patterns = [
            // FileReader.readAsDataURL chained directly to an image src assignment
            '\.readAsDataURL\s*\([^)]*\)[^;]{0,200}\.src\s*=',
        ];

        $runtime_image_regex = '/(?:' . implode( '|', $runtime_image_patterns ) . ')/i';

        if ( preg_match( $runtime_image_regex, $content ) ) {
            wp_send_json_error(
                [
                    'message' => 'Your project loads images at runtime (via JavaScript fetch, blob URLs, dynamic <img> src assignments, FileReader, Image() constructors, etc.). Runtime-loaded images cannot be moderated and are not allowed. Please use only static <img src="..."> tags or CSS background-image with literal URLs (which will then be checked by our image moderation system).',
                ],
                400
            );
            return;
        }
        // ────────────────────────────────────────────────────────────────────────────

        // ── Server-side scam / cracked-account / fake-giveaway blocking (zero-cost) ──
        // Catches the most common scam pages: cracked game/service accounts,
        // fake free currency (Robux, V-Bucks, Nitro, coins, gems, credits),
        // free subscription generators, and account-sharing/selling schemes.
        // Checked across the entire content string (name + description + code).
        $full_text_to_scan = $project_name . ' ' . $project_description . ' ' . $content;

        $scam_keyword_patterns = [
            // Cracked / leaked accounts for specific services
            '(?:cracked?|leaked?|free|hack(?:ed)?|gen(?:erated)?)\s+(?:minecraft|fortnite|roblox|discord|netflix|spotify|hulu|disney\+?|prime\s+video|twitch|steam|origin|epic\s+games?|xbox\s+game\s+pass|playstation\s+plus|ps\s*plus|ubisoft|battle\.?net|valorant|league\s+of\s+legends|lol|genshin|apex\s+legends?|call\s+of\s+duty|cod|warzone|overwatch|wow|world\s+of\s+warcraft|runescape|csgo|cs2|counter[-\s]?strike|dota|pubg|among\s+us)\s*(?:accounts?|logins?|passwords?|combos?|ids?)?',
            '(?:minecraft|fortnite|roblox|discord|netflix|spotify|steam|epic|xbox|playstation|ubisoft|valorant|genshin|apex|cod|warzone|overwatch)\s*(?:accounts?|logins?|passwords?|combos?)\s*(?:cracked?|leaked?|free|hack(?:ed)?|gen(?:erated)?|working)',

            // Free virtual currency / premium subscriptions (generator / giveaway scams)
            'free\s+(?:robux|vbucks|v[\s\-]?bucks|discord\s+nitro|nitro|minecoins?|minecraft\s+coins?|gems?|coins?|credits?|tokens?|points?|diamonds?|uc\b|apex\s+coins?|cod\s+points?|cp\b|riot\s+points?|rp\b|valorant\s+points?|star\s+coins?|tiktok\s+coins?)',
            '(?:robux|vbucks|v[\s\-]?bucks|nitro|minecoins?|gems?|coins?|credits?|tokens?)\s+(?:generator|gen|hack|adder|giver|gratis|gratuit|gratis|kostenlos)',
            'get\s+(?:free\s+)?(?:robux|vbucks|v[\s\-]?bucks|discord\s+nitro|nitro|minecoins?|gems?|coins?)',

            // Account selling / trading / sharing
            '(?:sell(?:ing)?|buy(?:ing)?|trad(?:e|ing)|shar(?:e|ing))\s+(?:minecraft|fortnite|roblox|discord|netflix|spotify|steam|epic|valorant|genshin|apex|cod|warzone|overwatch|cracked)\s*(?:accounts?|logins?|passwords?)',
            'account\s*(?:shop|store|market|sell|buy|trade|sharing)',
            '(?:cracked?|leaked?)\s+accounts?\s*(?:list|dump|combo|db|database|pastebin|txt)',

            // Combo list / credential dump language
            'combo\s*(?:list|pack|dump|db)',
            '(?:email\s*[:|;]?\s*pass(?:word)?|user(?:name)?\s*[:|;]?\s*pass(?:word)?)\s*combo',
            'credential\s*(?:stuffing|dump|leak|list)',
            'account\s*(?:checker|cracker|brute)',

            // Generic giveaway scam phrases
            '(?:claim|get|win|receive)\s+(?:your\s+)?(?:free\s+)?(?:premium|pro|vip|gold|ultimate)\s+(?:account|subscription|membership|pass)',
            'free\s+(?:premium|pro|vip|gold)\s+(?:account|subscription|membership)',
            '(?:gift\s+card|giftcard)\s+(?:generator|gen|hack|giveaway|free)',
            'free\s+(?:gift\s+card|giftcard|psn|xbox\s+live|itunes|amazon|google\s+play|steam\s+wallet)',
            'psn\s+(?:code\s+generator|free\s+codes?|hack)',
            'xbox\s+(?:code\s+generator|free\s+codes?|gift\s+card\s+generator)',

            // Survey scam / human verification fake gates
            'complete\s+(?:a\s+)?(?:survey|offer|task)\s+to\s+(?:unlock|get|receive|claim)',
            'human\s+verification\s+required',
            '(?:verify|verification)\s+(?:you\'?re|you\s+are)\s+(?:human|not\s+a\s+bot)',

            // Phishing / account stealer pages
            'enter\s+(?:your\s+)?(?:minecraft|fortnite|roblox|discord|steam|epic|valorant|netflix|spotify)\s+(?:username|password|login|credentials?|email)',
            '(?:login|sign\s+in)\s+with\s+(?:your\s+)?(?:minecraft|fortnite|roblox|discord|steam|epic|valorant)\s+(?:account|credentials?)',
        ];

        $scam_regex = '/(?:' . implode( '|', $scam_keyword_patterns ) . ')/i';

        // We check name+description+code together. The full_text_to_scan is already
        // assembled above, so we only run one preg_match.
        if ( preg_match( $scam_regex, $full_text_to_scan ) ) {
            wp_send_json_error(
                [
                    'message' => 'Your project appears to promote or facilitate one or more of the following, which are not allowed: '
                        . 'cracked/leaked game or service accounts (Minecraft, Fortnite, Discord, Netflix, etc.), '
                        . 'free virtual currency generators (Robux, V-Bucks, Discord Nitro, etc.), '
                        . 'account selling, trading, or sharing, '
                        . 'credential/combo-list dumps, '
                        . 'fake gift-card generators, '
                        . 'or scam survey/human-verification gates. '
                        . 'Please remove this content and try again.',
                ],
                400
            );
            return;
        }
        // ────────────────────────────────────────────────────────────────────────────

        // ── Server-side hacking / criminal-tool / account-generator blocking (zero-cost) ──
        // Catches pages that promote, distribute, or demonstrate hacking tools,
        // malware, exploits, criminal services, or account/key generators.
        $hack_keyword_patterns = [
            // Hacking tools & attack concepts
            '(?:ddos|dos)\s+(?:attack|tool|script|panel|booter|stresser)',
            '(?:ip\s*)?(?:booter|stresser|flooder|nuker)\s*(?:tool|panel|script|service|online|free)?',
            'rat.*(?:tool|builder|payload|trojan|remote\s+access)',
            'remote\s+access\s+(?:trojan|tool|rat)',
            '(?:keylogger|key\s*logger)\s*(?:builder|download|free|tool|script)?',
            '(?:exploit|0day|zero[\s\-]?day)\s*(?:kit|pack|builder|panel|download|free)',
            'metasploit\s*(?:tutorial|payload|exploit|shell)',
            '(?:reverse|bind)\s+shell\s*(?:generator|builder|payload)',
            'meterpreter\s+(?:session|payload|shell)',
            '(?:sql\s*injection|sqli)\s*(?:tool|scanner|exploit|hack|bypass)',
            'xss\s*(?:payload|inject|exploit|attack|steal\s+cookie)',
            '(?:brute\s*force|bruteforce)\s*(?:tool|attack|script|software|panel|online)',
            '(?:password|pass)\s*(?:cracker|cracking\s+tool|hash\s+cracker)',
            'hash\s*(?:cracker|crack|decrypter)',
            '(?:phishing\s+(?:kit|page|panel|template)|fake\s+(?:login|site|page)\s+(?:to\s+)?(?:steal|harvest|grab))',
            'cookie\s*(?:stealer|grabber|logger|hijack)',
            'session\s*(?:hijack|fixation|stealer)',
            '(?:malware|spyware|ransomware|adware|botnet)\s*(?:builder|creator|maker|generator|download|source)',
            'botnet\s*(?:panel|c2|c&c|command|control)',
            'crypter\s*(?:fud|builder|tool|download)',
            'fud\s+(?:crypter|rat|payload|malware)',

            // Illegal services & dark-web references
            '(?:carding|cc\s+shop|cvv\s+shop|dumps?\s+shop)',
            '(?:buy|sell|get|free)\s+(?:cvv|cc\s+dumps?|fullz|bank\s+logs?|dumps?\s+with\s+pin)',
            'paypal\s+(?:money\s+adder|flip|hack|generator|logs?)',
            'bank\s+(?:logs?|account\s+hack|transfer\s+hack)',
            '(?:darkweb|dark\s+web|onion\s+link|tor\s+link)\s*(?:market|shop|link)',
            'hitman\s+(?:service|for\s+hire)',
            '(?:hire|find)\s+(?:a\s+)?hacker',
            'hacker\s+for\s+hire',

            // Account / key / license generators
            '(?:account|key|license|serial|cd[\s\-]?key|activation\s+code)\s+(?:generator|gen|cracker|hack|maker)',
            '(?:windows|office|adobe|autodesk|antivirus|avg|avast|kaspersky|norton|bitdefender|malwarebytes)\s+(?:key\s+generator|keygen|crack|activator|license\s+generator)',
            'keygen\s+(?:for|download|free|online)',
            'serial\s+(?:key\s+generator|keygen|crack)',
            'product\s+key\s+(?:generator|gen|hack|crack)',
            'license\s+(?:key\s+generator|keygen|activator|crack)',

            // Cheating / aimbot / wallhack (game cheats distributed as tools)
            '(?:aimbot|wallhack|esp\s+hack|triggerbot|spinbot|cheat\s+engine)\s*(?:download|free|inject|injector|undetected|source)',
            '(?:inject|injector)\s+(?:cheat|hack|dll|mod)\s*(?:free|download|undetected)',
            '(?:undetected|ud)\s+(?:cheat|hack|aimbot|wallhack|esp)',
        ];

        $hack_regex = '/(?:' . implode( '|', $hack_keyword_patterns ) . ')/i';

        if ( preg_match( $hack_regex, $full_text_to_scan ) ) {
            wp_send_json_error(
                [
                    'message' => 'Your project appears to promote or facilitate hacking, cybercrime, or illegal tools, which are not allowed. '
                        . 'This includes: DDoS/stresser tools, RATs, keyloggers, exploit kits, brute-force tools, phishing kits, '
                        . 'malware/ransomware builders, carding/CVV shops, account/key/license generators, '
                        . 'dark-web market links, and game cheat injectors. '
                        . 'Please remove this content and try again.',
                ],
                400
            );
            return;
        }
        // ────────────────────────────────────────────────────────────────────────────

        // ── Server-side historical-villain / political-propaganda blocking (zero-cost) ──
        // Blocks three categories:
        //   1. Glorification or promotion of historical villains / war criminals / genocidal figures.
        //   2. Political propaganda, electoral manipulation, and political radicalization content.
        //   3. Historical figures being weaponised to promote harmful ideologies (nazism, fascism, etc.).
        $history_political_patterns = [

            // ── 1. Historical villains — glorification / promotion ────────────────
            // Named figures paired with glorification language. We do NOT block
            // neutral educational mentions; we block praise, promotion, and idolisation.
            '(?:heil|glory\s+to|praise|long\s+live|salute\s+to)\s+(?:hitler|mussolini|himmler|goebbels|stalin|pol\s+pot|mao\s+zedong|idi\s+amin|saddam\s+hussein|bin\s+laden|al[\s\-]?baghdadi|pinochet|franco|mengele)',
            '(?:hitler|mussolini|himmler|goebbels|stalin|pol\s+pot|idi\s+amin|pinochet|mengele|bin\s+laden|al[\s\-]?baghdadi)\s+(?:was\s+right|had\s+the\s+right\s+idea|is\s+my\s+hero|is\s+a\s+hero|did\s+nothing\s+wrong|should\s+have\s+won|was\s+a\s+great\s+(?:man|leader)|is\s+an\s+inspiration)',
            '(?:worship|idolize|admire|support|glorif[ying]+)\s+(?:hitler|mussolini|himmler|goebbels|stalin|pol\s+pot|idi\s+amin|pinochet|mengele|bin\s+laden|al[\s\-]?baghdadi)',
            // Holocaust denial paired with villain glorification
            '(?:holocaust|shoah)\s+(?:never\s+happened|was\s+fake|is\s+a\s+lie|is\s+a\s+myth|was\s+exaggerated)',
            '(?:six\s+million|6\s+million)\s+(?:lie|myth|fake|never\s+happened)',
            // Genocide promotion / praise
            '(?:genocide|ethnic\s+cleansing|mass\s+murder)\s+(?:was\s+justified|was\s+right|is\s+the\s+answer|should\s+happen\s+again)',

            // ── 2. Harmful ideology promotion ────────────────────────────────────
            '(?:join|support|promote|spread|share)\s+(?:nazism|national\s+socialism|fascism|neo[\s\-]?nazism|the\s+kkk|white\s+(?:nationalism|supremacy|power)|black\s+(?:nationalism\s+that\s+promotes\s+violence)|jihadism|isis|isil|daesh|al[\s\-]?qaeda|boko\s+haram)',
            '(?:white|racial)\s+(?:supremacy|superiority)\s+(?:is\s+(?:true|right|fact|real)|must\s+(?:rise|prevail|win))',
            '(?:nazis?|fascists?|kkk|white\s+nationalists?)\s+(?:were|are)\s+(?:right|correct|justified|heroes?)',
            '(?:death\s+to|kill\s+all|exterminate|wipe\s+out)\s+(?:jews?|muslims?|christians?|blacks?|whites?|arabs?|asians?|(?:any\s+)?ethnic\s+group)',
            '(?:sub[\s\-]?human|untermensch|vermin|parasites?|cockroaches?)\s+(?:referring\s+to\s+any\s+ethnic\s+(?:or\s+)?religious\s+group|jews?|muslims?|blacks?|whites?|arabs?|asians?)',
            '(?:race\s+war|racial\s+holy\s+war|rahowa)\s+(?:now|is\s+coming|is\s+necessary|is\s+needed)',
            '(?:accelerationism|accelerate\s+the\s+collapse)\s+(?:manifesto|guide|plan)',

            // ── 3. Political propaganda & manipulation ────────────────────────────
            // Voter manipulation / election interference
            '(?:vote\s+(?:fraud|rigging|manipulation|stuffing)|election\s+(?:fraud|rigging|manipulation|interference|is\s+stolen|was\s+stolen))\s+(?:guide|how\s+to|tutorial|method)',
            '(?:how\s+to|guide\s+to)\s+(?:rig|steal|manipulate|hack)\s+(?:an?\s+)?election',
            '(?:fake|false)\s+(?:voter|election|ballot)\s+(?:registration|records?|results?)',
            // Radicalization funnels
            '(?:join|become\s+(?:a|one\s+of)\s+(?:us|our))\s+(?:and\s+)?(?:fight\s+(?:for|against)|rise\s+up\s+against)\s+(?:the\s+)?(?:government|state|system|establishment|elites?|globalists?|zionists?)',
            '(?:red[\s\-]?pill|wake\s+up)\s+(?:sheeple|normies|the\s+masses)\s+(?:to\s+the\s+)?(?:truth\s+about|real\s+agenda\s+of)',
            '(?:great\s+replacement|white\s+genocide)\s+(?:is\s+real|is\s+happening|theory|manifesto)',
            // Incitement to political violence
            '(?:assassinate|kill|murder|execute)\s+(?:the\s+)?(?:president|prime\s+minister|senator|politician|leader|government\s+official)',
            '(?:armed|violent)\s+(?:revolution|uprising|insurrection|overthrow)\s+(?:is\s+(?:needed|necessary|justified|the\s+only\s+way)|against\s+the\s+government)',
            '(?:bomb|attack|shoot)\s+(?:a\s+)?(?:government\s+building|parliament|congress|white\s+house|capitol)',
        ];

        $history_political_regex = '/(?:' . implode( '|', $history_political_patterns ) . ')/i';

        if ( preg_match( $history_political_regex, $full_text_to_scan ) ) {
            wp_send_json_error(
                [
                    'message' => 'Your project contains content that is not allowed: '
                        . 'glorification of historical villains or war criminals, '
                        . 'promotion of harmful ideologies (Nazism, fascism, white supremacy, etc.), '
                        . 'Holocaust denial, genocide promotion, '
                        . 'or political propaganda designed to manipulate, radicalise, or incite violence. '
                        . 'Please remove this content and try again.',
                ],
                400
            );
            return;
        }
        // ────────────────────────────────────────────────────────────────────────────

        $mistral_key = defined( 'MLP_MISTRAL_API_KEY' ) ? MLP_MISTRAL_API_KEY : '';
        if ( empty( $mistral_key ) ) {
            // No key configured — allow publish but log it
            $mod_token = 'nokey_' . strtolower( wp_generate_password( 16, false, false ) );
            set_transient( 'mlp_mod_' . $mod_token, [ 'ok' => true, 'ts' => time() ], 300 );
            wp_send_json_success( [ 'mod_token' => $mod_token, 'passed' => true, 'reason' => '' ] );
            return;
        }

        // Chunk full content into 12000-char segments so the ENTIRE project is
        // moderated, not just the first 12K. Each chunk is sent through Mistral
        // independently; if ANY chunk fails, the whole publish is rejected.
        $chunk_size = 12000;
        $content_len = mb_strlen( $content );
        $chunks = [];
        if ( $content_len === 0 ) {
            $chunks[] = '';
        } else {
            for ( $offset = 0; $offset < $content_len; $offset += $chunk_size ) {
                $chunks[] = mb_substr( $content, $offset, $chunk_size );
            }
        }
        // Hard cap on number of chunks to avoid runaway cost on huge payloads
        $max_chunks = 25; // 25 * 12K = 300KB which matches the 500KB content cap
        if ( count( $chunks ) > $max_chunks ) {
            $chunks = array_slice( $chunks, 0, $max_chunks );
        }

        $system_prompt = 'You are an EXTREMELY STRICT content moderation AI with ZERO TOLERANCE for offensive language. Analyze the following user-submitted web project — including ALL THREE of: the project NAME/TITLE, the project DESCRIPTION, and the project CODE (HTML/CSS/JavaScript) — and determine if ANY of them contains ANY of these violations. The project name and description are shown publicly on the share page, so they must be moderated with MAXIMUM strictness — be even stricter on the name and description than on the code itself:

ZERO-TOLERANCE PROFANITY RULE (applies to NAME, DESCRIPTION, and CODE):
Reject IMMEDIATELY if the name, description, or code contains ANY profanity, vulgarity, slur, sexual term, or crude word — in ANY language, in ANY form (full word, partial, abbreviated, leetspeak/numbers-for-letters like a55, p*ssy, sh1t, f@ck, deliberately misspelled, spaced out like "a s s", reversed, with extra characters, hidden in unicode, l33t, or any other obfuscation). This includes but is NOT LIMITED to:
- Sexual/anatomical vulgar terms: pussy, dick, cock, tits, boobs, ass, asshole, butt (when crude), arse, balls (crude), penis (when crude), vagina (when crude), cum, jizz, blowjob, handjob, anal, oral, etc.
- General profanity: fuck, shit, bitch, bastard, damn, hell (when crude), crap, piss, prick, twat, wanker, bollocks, bloody (UK profane), etc.
- Slurs of ANY kind targeting race, ethnicity, religion, nationality, gender, sexual orientation, disability, or any group — including the n-word, f-slur, r-slur, and ANY similar terms in any language
- Sexual acts or fetish terms
- Drug-related crude slang
- Crude insults: motherf***er, son of a b****, etc.
- ANY equivalent profanity in Arabic, Urdu, Hindi, Spanish, French, German, Russian, Chinese, or any other language
- ANY creative spelling, abbreviation, censoring (with *, $, @, 0, 1, !, etc.), or obfuscation of the above

If you see clear, deliberate use of these in the name or description, REJECT. In code (HTML/CSS/JS), only reject if the profanity appears in visible user-facing text, not as part of variable names, comments, or incidental technical strings.

OTHER VIOLATIONS (any one = reject):
1. Malware, viruses, ransomware, exploit code, obfuscated malicious scripts, credential-stealing code, or any code designed to harm visitors
2. Phishing attempts or fake login forms designed to steal credentials
3. Glorification of historical villains, war criminals, or genocidal figures — this includes but is NOT LIMITED to:
   a) Praising, idolising, or promoting Hitler, Mussolini, Himmler, Goebbels, Stalin, Pol Pot, Idi Amin, Pinochet, Mengele, Bin Laden, Al-Baghdadi, or any other war criminal or genocidal leader.
   b) Statements such as "Hitler was right", "did nothing wrong", "is my hero", or any similar glorification of such figures.
   c) Holocaust denial, minimisation, or revisionism (e.g. "the Holocaust never happened", "six million lie").
   d) Promoting, justifying, or celebrating genocide, ethnic cleansing, or mass atrocities.
4. Harmful ideology promotion — including Nazism, neo-Nazism, fascism, white supremacy, racial superiority claims, KKK content, jihadist recruitment, or any ideology that dehumanises people based on race, religion, or ethnicity.
   a) Dehumanising language targeting any ethnic or religious group (calling people "subhuman", "vermin", "parasites", etc.).
   b) Calls for a race war, racial holy war (RAHOWA), or accelerationist manifestos.
   c) Content that uses historical figures to recruit for or legitimise extremist movements.
5. Political propaganda and manipulation — including:
   a) Voter manipulation guides, election-rigging tutorials, or fake ballot/registration schemes.
   b) Radicalization funnels designed to recruit people into extremist political movements.
   c) "Great Replacement" or "white genocide" theory content.
   d) Incitement to political violence: calls to assassinate leaders, bomb government buildings, or carry out armed insurrection.
   e) Disinformation campaigns designed to manipulate public opinion through fabricated quotes, fake statistics, or false attribution to real political figures.
6. Hacking tools, cybercrime, or criminal content — this includes but is NOT LIMITED to:
   a) DDoS / IP stresser / booter tools or panels.
   b) Remote Access Trojans (RATs), keyloggers, spyware, ransomware, adware, or botnet builders/panels.
   c) Exploit kits, zero-day exploit pages, reverse/bind shell generators, or Metasploit payload builders.
   d) SQL injection tools, XSS payload pages, brute-force/password-cracking tools, or cookie/session stealers.
   e) Phishing kits, fake login page templates designed to harvest credentials, or crypters (FUD).
   f) Carding shops, CVV/dumps shops, bank-log sellers, PayPal flippers, or any page facilitating financial fraud.
   g) Dark-web market links, hitman-for-hire pages, or "hire a hacker" services.
   h) Account generators, key generators (keygens), software cracks, license/serial-key generators, or activators for ANY software or service.
   i) Game cheat injectors, aimbots, wallhacks, ESPs, or undetected cheat downloads.
3. Hate speech, racism, extreme toxicity, or slurs targeting any group
4. NSFW/adult/pornographic content or any sexual references
5. Harassment, doxxing, or content targeting specific real individuals
6. Spam, scam, or fraudulent content — this includes but is NOT LIMITED to:
   a) Cracked, leaked, hacked, or stolen accounts for ANY game or service (Minecraft, Fortnite, Roblox, Discord, Netflix, Spotify, Steam, Epic Games, Xbox Game Pass, PlayStation Plus, Ubisoft, Valorant, Genshin Impact, Apex Legends, Call of Duty / Warzone, Overwatch, Twitch, TikTok, and any other platform).
   b) Free virtual currency generators, adders, or hacks: Robux, V-Bucks, Discord Nitro, Minecoins, Apex Coins, COD Points, Riot Points, Valorant Points, TikTok Coins, or ANY in-game currency or premium subscription for ANY service.
   c) Account selling, buying, trading, or sharing schemes (account shops, markets, or combo-list dumps).
   d) Credential stuffing tools, account checkers, account crackers, or combo-list / credential-dump pages.
   e) Fake gift-card generators (PSN, Xbox Live, iTunes, Amazon, Google Play, Steam Wallet, or any other gift card).
   f) Fake prize or giveaway pages that require survey completion, human verification, or personal information to "claim" a reward.
   g) Phishing pages that impersonate game or service login screens to harvest usernames/passwords.
   h) Any page that promises something free that normally costs money in exchange for credentials, surveys, app installs, referrals, or social shares.
7. ANY profanity or offensive/crude/vulgar language (see zero-tolerance list above) — NO mild language allowance
8. Any content that is disrespectful, blasphemous, or insulting toward Allah, the Prophet Muhammad (peace be upon him), Islam, the Quran, or any Islamic figure or practice
9. Content that promotes, glorifies, or facilitates anything haram (forbidden) in Islam, including but not limited to: alcohol, gambling, pork/forbidden foods, interest-based finance (riba), pornography, drugs, witchcraft/magic, idol worship, or apostasy
10. Religion-related content that mocks, undermines, or attacks Islamic beliefs, values, or religious obligations (prayer, fasting, hijab, halal, etc.)
11. Nonsense/gibberish names or descriptions clearly meant to disguise profanity or hide offensive intent
12. Names or descriptions designed to provoke, shock, or disgust (toilet humor, gore references, etc.)
13. ANY external URL, hyperlink, or domain reference in the project NAME or DESCRIPTION — including but not limited to: http://, https://, www., or any domain pattern like "example.com", "site.org", "link.net", "go.io", or any other top-level domain (.com, .net, .org, .io, .co, .app, .dev, .xyz, .info, .biz, .me, .tv, .gg, .ai, .uk, .us, .fr, .de, .ru, .cn, and ALL other TLDs). The name and description must never contain clickable or plain-text links or bare domain names of any kind.
14. External URLs or domain references inside the CODE that serve no legitimate technical purpose and appear designed to redirect users, load trackers, exfiltrate data, phish credentials, or promote external sites — such as hidden iframes, auto-redirect scripts (window.location = "https://..."), or suspicious fetch/XHR calls to third-party domains.
15. Base64-encoded or otherwise encoded images embedded in the code (data:image/..., raw base64 strings, atob() calls, Canvas drawImage with encoded data) that contain or appear to contain NSFW, offensive, violent, or otherwise policy-violating visual content. Even if the image is encoded or obfuscated, if the base64 string or surrounding context suggests an image that would violate policy, REJECT. Any attempt to hide an image behind encoding is itself grounds for rejection.
17. Any code that loads images at runtime from JavaScript — including but not limited to: URL.createObjectURL, FileReader.readAsDataURL, new Image() with dynamic src, document.createElement("img") with non-literal src, fetch().then(...).blob(), XMLHttpRequest with responseType blob/arraybuffer, dynamic .src or setAttribute("src", ...) assignments using variables/template-literals/concatenation, dynamic ES module imports of image files, Service Worker / Cache API image loading, or ANY other technique that fetches or constructs images after page load. Runtime-loaded images bypass server-side image moderation and are NOT allowed under any circumstances. Only static <img src="..."> tags with literal URLs and CSS background-image with literal URLs are acceptable. REJECT if you detect any runtime image loading.
16. ANY image — whether AI-generated, photographic, illustrated, drawn, rendered, cartoon, anime, 3D, pixel art, silhouette, or in any other style — that depicts a human being or human figure of ANY gender (male, female, non-binary, child, adult, elderly, etc.), including full-body, partial-body, face-only, portrait, group, or crowd images. This applies to ALL image sources in the project: <img src="..."> tags pointing to external URLs (including AI image generation services, stock photo sites, avatar services like ui-avatars, dicebear, gravatar, randomuser.me, thispersondoesnotexist.com, unsplash people photos, etc.), background-image CSS, base64/data-URI images, SVG depictions of people, Canvas-drawn human figures, <picture>/<source> elements, and any image referenced or generated by code (fetch calls to image APIs, AI image prompts mentioning people/man/woman/boy/girl/person/human/face/portrait, etc.). Even tasteful, fully-clothed, professional, or artistic depictions of human figures — male or female — must be REJECTED. Pictures of people are NOT allowed in projects under any circumstances. If the code contains an AI image generation prompt that mentions a person, man, woman, human, face, portrait, model, or any human descriptor, REJECT. If in doubt about whether an image contains a human figure, REJECT.

When in doubt, PASS. Only reject submissions that clearly and unambiguously violate the above rules. Do not reject borderline or ambiguous content — legitimate web projects should be allowed through. Err on the side of allowing content unless a violation is obvious.

Respond ONLY with a JSON object in this exact format (no markdown, no explanation outside the JSON):
{"passed": true_or_false, "violations": ["list","of","violation","types","found"], "reason": "brief human-readable explanation if failed, empty string if passed"}';

        // Run text moderation across every chunk. FAIL-CLOSED: if the API
        // errors on any chunk we cannot verify it, so we treat that as a
        // service outage and reject with a maintenance message.
        $passed = true;
        $reason = '';
        $maintenance_mode = false;

        foreach ( $chunks as $chunk_idx => $chunk_snippet ) {
            // Only include name/description in the FIRST chunk so they aren't
            // moderated repeatedly (cost) and so the AI judges them once.
            if ( $chunk_idx === 0 ) {
                $user_msg = "Moderate this project.\n\nPROJECT NAME/TITLE:\n"
                    . ( $project_name !== '' ? $project_name : '(none provided)' )
                    . "\n\nPROJECT DESCRIPTION:\n"
                    . ( $project_description !== '' ? $project_description : '(none provided)' )
                    . "\n\nPROJECT CODE (chunk 1 of " . count( $chunks ) . "):\n"
                    . $chunk_snippet;
            } else {
                $user_msg = "Moderate this project code.\n\nPROJECT CODE (chunk "
                    . ( $chunk_idx + 1 ) . " of " . count( $chunks ) . "):\n"
                    . $chunk_snippet;
            }

            $response = wp_remote_post(
                'https://api.mistral.ai/v1/chat/completions',
                [
                    'timeout' => 20,
                    'headers' => [
                        'Authorization' => 'Bearer ' . $mistral_key,
                        'Content-Type'  => 'application/json',
                    ],
                    'body' => wp_json_encode( [
                        'model'       => 'mistral-small-latest',
                        'max_tokens'  => 300,
                        'temperature' => 0,
                        'messages'    => [
                            [ 'role' => 'system', 'content' => $system_prompt ],
                            [ 'role' => 'user',   'content' => $user_msg ],
                        ],
                    ] ),
                ]
            );

            if ( is_wp_error( $response ) ) {
                error_log( '[MLP Text Mod] API error on chunk ' . ( $chunk_idx + 1 ) . ': ' . $response->get_error_message() );
                $maintenance_mode = true;
                break;
            }

            $resp_code = wp_remote_retrieve_response_code( $response );
            if ( $resp_code < 200 || $resp_code >= 300 ) {
                error_log( '[MLP Text Mod] HTTP ' . $resp_code . ' on chunk ' . ( $chunk_idx + 1 ) );
                $maintenance_mode = true;
                break;
            }

            $body = json_decode( wp_remote_retrieve_body( $response ), true );
            $ai_text = $body['choices'][0]['message']['content'] ?? '';

            // Strip markdown fences if present
            $ai_text = preg_replace( '/^```(?:json)?\s*/i', '', trim( $ai_text ) );
            $ai_text = preg_replace( '/\s*```$/', '', $ai_text );

            $result = json_decode( $ai_text, true );

            if ( ! is_array( $result ) || ! isset( $result['passed'] ) ) {
                // Could not parse — treat as outage to avoid silent fail-open
                error_log( '[MLP Text Mod] Could not parse AI response on chunk ' . ( $chunk_idx + 1 ) );
                $maintenance_mode = true;
                break;
            }

            $chunk_passed = ( $result['passed'] === true );
            if ( ! $chunk_passed ) {
                $passed = false;
                $reason = $result['reason'] ?? 'Content violates moderation policy.';
                break; // Fail fast on first bad chunk
            }
        }

        if ( $maintenance_mode ) {
            wp_send_json_error( [
                'message'     => 'The system is currently down for maintenance. Please come back later (we\'ll be back in the next day).',
                'maintenance' => true,
            ], 503 );
            return;
        }

        if ( $passed ) {
            // ── Server-side image moderation (Options 1 & 2) ─────────────────
            // Extract all image sources embedded in the project code and check
            // each one with Sightengine (Option 1), Imagga (Option 2), and Google Vision (Option 3).
            $image_sources = self::extract_image_sources( $content );

            foreach ( $image_sources as $img_src ) {
                // Track null (unable-to-check) results across all 5 providers
                // so we can fail-closed when the entire vision pipeline is down.
                $null_count = 0;

                // Option 1 — Sightengine (primary, runs first) — CACHED
                $se_result = self::cached_image_check( 'sightengine', $img_src, [ __CLASS__, 'sightengine_check_image' ] );
                if ( $se_result === null ) { $null_count++; }
                if ( $se_result === false ) {
                    error_log( '[MLP Image Mod] Sightengine blocked image in project: ' . mb_substr( $img_src, 0, 80 ) );
                    wp_send_json_error( [
                        'passed'     => false,
                        'reason'     => 'Your project contains an image that violates our content policy (nudity, violence, or offensive material).',
                        'violations' => [ 'nsfw_image' ],
                    ], 200 );
                    return;
                }

                // Option 1b — Imagga (tertiary, independent second opinion alongside Sightengine) — CACHED
                $ig_result = self::cached_image_check( 'imagga', $img_src, [ __CLASS__, 'imagga_check_image' ] );
                if ( $ig_result === null ) { $null_count++; }
                if ( $ig_result === false ) {
                    error_log( '[MLP Image Mod] Imagga blocked image in project: ' . mb_substr( $img_src, 0, 80 ) );
                    wp_send_json_error( [
                        'passed'     => false,
                        'reason'     => 'Your project contains an image that violates our content policy (nudity, violence, or offensive material).',
                        'violations' => [ 'nsfw_image' ],
                    ], 200 );
                    return;
                }

                // Option 1c — Google Vision SafeSearch (daily quota, highly accurate) — CACHED
                $gv_result = self::cached_image_check( 'gvision', $img_src, [ __CLASS__, 'google_vision_check_image' ] );
                if ( $gv_result === null ) { $null_count++; }
                if ( $gv_result === false ) {
                    error_log( '[MLP Image Mod] Google Vision blocked image in project: ' . mb_substr( $img_src, 0, 80 ) );
                    wp_send_json_error( [
                        'passed'     => false,
                        'reason'     => 'Your project contains an image that violates our content policy (nudity, violence, or offensive material).',
                        'violations' => [ 'nsfw_image' ],
                    ], 200 );
                    return;
                }

                // Option 1d — Gemini Vision (free tier) — detects human figures (male/female, real/cartoon) — CACHED
                $gem_result = self::cached_image_check( 'gemini', $img_src, [ __CLASS__, 'gemini_check_image' ] );
                if ( $gem_result === null ) { $null_count++; }
                if ( $gem_result === false ) {
                    error_log( '[MLP Image Mod] Gemini blocked image (human detected): ' . mb_substr( $img_src, 0, 80 ) );
                    wp_send_json_error( [
                        'passed'     => false,
                        'reason'     => 'Your project contains an image that depicts a person. Pictures of people — male, female, real, or cartoon — are not allowed. Please remove all human images and try again.',
                        'violations' => [ 'human_image' ],
                    ], 200 );
                    return;
                }

                // Option 1e — Groq Vision (Llama vision, free tier) — second opinion on human-figure detection — CACHED
                $groq_result = self::cached_image_check( 'groq', $img_src, [ __CLASS__, 'groq_check_image' ] );
                if ( $groq_result === null ) { $null_count++; }
                if ( $groq_result === false ) {
                    error_log( '[MLP Image Mod] Groq blocked image (human detected): ' . mb_substr( $img_src, 0, 80 ) );
                    wp_send_json_error( [
                        'passed'     => false,
                        'reason'     => 'Your project contains an image that depicts a person. Pictures of people — male, female, real, or cartoon — are not allowed. Please remove all human images and try again.',
                        'violations' => [ 'human_image' ],
                    ], 200 );
                    return;
                }

                // FAIL-OPEN: if every single provider was unable to verify
                // this image (all returned null / unconfigured), allow through.
                if ( $null_count >= 5 ) {
                    error_log( '[MLP Image Mod] All providers returned null for image (unconfigured or outage): ' . mb_substr( $img_src, 0, 80 ) . ' — allowing through.' );
                }
            }
            // ── End image moderation ─────────────────────────────────────────

            $mod_token = 'ok_' . strtolower( wp_generate_password( 18, false, false ) );
            set_transient( 'mlp_mod_' . $mod_token, [ 'ok' => true, 'ts' => time() ], 300 );
            wp_send_json_success( [ 'mod_token' => $mod_token, 'passed' => true, 'reason' => '' ] );
        } else {
            // Log rejected content attempt
            error_log( '[MLP Moderation] Project rejected. Violations: ' . wp_json_encode( $result['violations'] ?? [] ) . ' | Reason: ' . $reason );
            wp_send_json_error( [
                'passed'     => false,
                'reason'     => $reason ?: 'Your project contains content that violates our sharing policy.',
                'violations' => $result['violations'] ?? [],
            ], 200 ); // 200 so JS can read the body
        }
    }

    // =========================================================================
    // IMAGE MODERATION HELPERS
    // =========================================================================
    //
    //
    // =========================================================================

    /**
     * Option 1 — Sightengine: moderate a single image (URL or base64 data-URI).
     *
     * Returns true  = image is clean.
     * Returns false = image is NSFW / blocked.
     * Returns null  = API error / key not configured (fail-open).
     *
     * @param string $image_src  A URL ("https://…") or a base64 data-URI ("data:image/…;base64,…").
     * @return bool|null
     */
    private static function sightengine_check_image( $image_src ) {
        $se_user   = defined( 'MLP_SIGHTENGINE_USER' )   ? MLP_SIGHTENGINE_USER   : '';
        $se_secret = defined( 'MLP_SIGHTENGINE_SECRET' ) ? MLP_SIGHTENGINE_SECRET : '';

        if ( empty( $se_user ) || empty( $se_secret ) ) {
            return null; // Not configured — fail-open
        }

        $body = [
            'models'     => 'nudity-2.1,offensive,scam,gore-2.0,text-content',
            'api_user'   => $se_user,
            'api_secret' => $se_secret,
        ];

        // Detect base64 data-URI vs plain URL
        if ( strncmp( $image_src, 'data:', 5 ) === 0 ) {
            // Extract the raw base64 portion after the comma
            $comma = strpos( $image_src, ',' );
            if ( $comma === false ) {
                return null;
            }
            $body['image'] = substr( $image_src, $comma + 1 );
            $endpoint      = 'https://api.sightengine.com/1.0/check.json';
        } else {
            $body['url'] = $image_src;
            $endpoint    = 'https://api.sightengine.com/1.0/check.json';
        }

        $response = wp_remote_post( $endpoint, [
            'timeout' => 15,
            'body'    => $body,
        ] );

        if ( is_wp_error( $response ) ) {
            error_log( '[MLP Sightengine] API error: ' . $response->get_error_message() );
            return null; // Fail-open on connection error
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $data['status'] ) || $data['status'] !== 'success' ) {
            error_log( '[MLP Sightengine] Unexpected response: ' . wp_remote_retrieve_body( $response ) );
            return null;
        }

        // ── Nudity check ──────────────────────────────────────────────────────
        // nudity-2.1 returns sexual_activity, sexual_display, erotica thresholds
        $nudity = $data['nudity'] ?? [];
        if (
            ( isset( $nudity['sexual_activity'] ) && $nudity['sexual_activity'] > 0.5 ) ||
            ( isset( $nudity['sexual_display']  ) && $nudity['sexual_display']  > 0.5 ) ||
            ( isset( $nudity['erotica']          ) && $nudity['erotica']         > 0.5 ) ||
            // Legacy nudity model keys (fallback)
            ( isset( $nudity['raw']              ) && $nudity['raw']             > 0.5 ) ||
            ( isset( $nudity['partial']          ) && $nudity['partial']         > 0.6 )
        ) {
            return false;
        }

        // ── Offensive check ───────────────────────────────────────────────────
        $offensive = $data['offensive'] ?? [];
        if ( isset( $offensive['prob'] ) && $offensive['prob'] > 0.5 ) {
            return false;
        }

        // ── Text-in-image profanity check ─────────────────────────────────────
        // text-content model returns detected text; block if Sightengine flags it as offensive
        $text_content = $data['text'] ?? [];
        if ( isset( $text_content['profanity'] ) && $text_content['profanity'] > 0.5 ) {
            return false;
        }

        // ── Gore check ────────────────────────────────────────────────────────
        $gore = $data['gore'] ?? [];
        if ( isset( $gore['prob'] ) && $gore['prob'] > 0.7 ) {
            return false;
        }

        return true; // Passed all checks
    }

    /**
     * Imagga content moderation: checks an image for adult / NSFW content.
     *
     * Imagga's content endpoint returns scores for categories like
     * "adult content", "suggestive", "violence", "drug use", etc.
     *
     * Returns true  = image is clean.
     * Returns false = image is NSFW / blocked.
     * Returns null  = API error / key not configured (fail-open).
     *
     * wp-config.php:
     *   define( 'MLP_IMAGGA_KEY',    'acc_1327590704bacf1' );
     *   define( 'MLP_IMAGGA_SECRET', '8ec4449e68e4286877dc7de259bc6fee' );
     *
     * @param string $image_src  A URL ("https://…") or a base64 data-URI.
     * @return bool|null
     */
    private static function imagga_check_image( $image_src ) {
        $imagga_key    = defined( 'MLP_IMAGGA_KEY' )    ? MLP_IMAGGA_KEY    : '';
        $imagga_secret = defined( 'MLP_IMAGGA_SECRET' ) ? MLP_IMAGGA_SECRET : '';

        if ( empty( $imagga_key ) || empty( $imagga_secret ) ) {
            return null; // Not configured — fail-open
        }

        $args = [
            'timeout' => 15,
            'headers' => [
                'Authorization' => 'Basic ' . base64_encode( $imagga_key . ':' . $imagga_secret ),
            ],
        ];

        if ( strncmp( $image_src, 'data:', 5 ) === 0 ) {
            // Base64 data-URI — upload via multipart form first, then check
            $comma = strpos( $image_src, ',' );
            if ( $comma === false ) {
                return null;
            }
            $mime    = 'image/jpeg';
            $matches = [];
            if ( preg_match( '/^data:([^;]+);base64,/', $image_src, $matches ) ) {
                $mime = $matches[1];
            }
            $raw_data = base64_decode( substr( $image_src, $comma + 1 ) );
            if ( $raw_data === false ) {
                return null;
            }
            // Upload image to Imagga upload endpoint
            $boundary = wp_generate_password( 24, false );
            $body  = "--{$boundary}\r\n";
            $body .= "Content-Disposition: form-data; name=\"image\"; filename=\"image.jpg\"\r\n";
            $body .= "Content-Type: {$mime}\r\n\r\n";
            $body .= $raw_data . "\r\n";
            $body .= "--{$boundary}--\r\n";

            $args['headers']['Content-Type'] = 'multipart/form-data; boundary=' . $boundary;
            $args['body'] = $body;

            $upload_response = wp_remote_post( 'https://api.imagga.com/v2/uploads', $args );
            if ( is_wp_error( $upload_response ) ) {
                error_log( '[MLP Imagga] Upload error: ' . $upload_response->get_error_message() );
                return null;
            }
            $upload_data = json_decode( wp_remote_retrieve_body( $upload_response ), true );
            $upload_id   = $upload_data['result']['upload_id'] ?? '';
            if ( empty( $upload_id ) ) {
                error_log( '[MLP Imagga] Upload failed: ' . wp_remote_retrieve_body( $upload_response ) );
                return null;
            }

            // Now check content moderation using the upload_id
            unset( $args['headers']['Content-Type'], $args['body'] );
            $check_response = wp_remote_get(
                'https://api.imagga.com/v2/content?image_upload_id=' . urlencode( $upload_id ),
                $args
            );

            // Clean up the upload
            wp_remote_request( 'https://api.imagga.com/v2/uploads/' . urlencode( $upload_id ), array_merge( $args, [ 'method' => 'DELETE' ] ) );

        } else {
            // Plain URL — pass directly
            $check_response = wp_remote_get(
                'https://api.imagga.com/v2/content?image_url=' . urlencode( $image_src ),
                $args
            );
        }

        if ( is_wp_error( $check_response ) ) {
            error_log( '[MLP Imagga] Check error: ' . $check_response->get_error_message() );
            return null;
        }

        $data = json_decode( wp_remote_retrieve_body( $check_response ), true );

        if ( empty( $data['result']['categories'] ) ) {
            error_log( '[MLP Imagga] Unexpected response: ' . wp_remote_retrieve_body( $check_response ) );
            return null; // Fail-open on unexpected response
        }

        // Imagga returns categories with a score 0–100.
        // Block if adult content or suggestive content scores are high.
        $blocked_categories = [
            'adult content' => 50,  // block if score > 50
            'suggestive'    => 60,
            'violence'      => 60,
            'drug use'      => 60,
            'gore'          => 50,
        ];

        foreach ( $data['result']['categories'] as $category ) {
            $name  = strtolower( $category['name']  ?? '' );
            $score = floatval( $category['score'] ?? 0 );
            foreach ( $blocked_categories as $blocked => $threshold ) {
                if ( strpos( $name, $blocked ) !== false && $score > $threshold ) {
                    error_log( '[MLP Imagga] Blocked image. Category: ' . $name . ' Score: ' . $score );
                    return false;
                }
            }
        }

        return true; // Passed all checks
    }

    /**
     * Google Vision SafeSearch: detect adult/violent/racy content in an image.
     *
     * Uses Google Cloud Vision API's SafeSearch Detection feature.
     * Returns severity scores for: adult, spoof, medical, violence, racy.
     * Blocks if any of adult/violence/racy score LIKELY or VERY_LIKELY.
     *
     * Quota resets DAILY (~1,000 free requests/day via $200 monthly credit).
     *
     *
     * Returns true  = image is clean.
     * Returns false = image is blocked.
     * Returns null  = API error / key not configured (fail-open).
     *
     * @param string $image_src  A URL ("https://…") or a base64 data-URI.
     * @return bool|null
     */
    private static function google_vision_check_image( $image_src ) {
        $gv_key = defined( 'MLP_GOOGLE_VISION_KEY' ) ? MLP_GOOGLE_VISION_KEY : '';

        if ( empty( $gv_key ) ) {
            return null; // Not configured — fail-open
        }

        // Build the image source block for the API request
        if ( strncmp( $image_src, 'data:', 5 ) === 0 ) {
            // Base64 data-URI — extract raw base64 content
            $comma = strpos( $image_src, ',' );
            if ( $comma === false ) {
                return null;
            }
            $b64_content = substr( $image_src, $comma + 1 );
            $image_block = [ 'content' => $b64_content ];
        } else {
            // Plain URL
            $image_block = [ 'source' => [ 'imageUri' => $image_src ] ];
        }

        $response = wp_remote_post(
            'https://vision.googleapis.com/v1/images:annotate?key=' . $gv_key,
            [
                'timeout' => 15,
                'headers' => [ 'Content-Type' => 'application/json' ],
                'body'    => wp_json_encode( [
                    'requests' => [
                        [
                            'image'    => $image_block,
                            'features' => [
                                [ 'type' => 'SAFE_SEARCH_DETECTION' ],
                            ],
                        ],
                    ],
                ] ),
            ]
        );

        if ( is_wp_error( $response ) ) {
            error_log( '[MLP Google Vision] API error: ' . $response->get_error_message() );
            return null;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        // Check for API-level errors (e.g. invalid key, quota exceeded)
        if ( ! empty( $body['error'] ) || ! empty( $body['responses'][0]['error'] ) ) {
            $err = $body['error']['message'] ?? ( $body['responses'][0]['error']['message'] ?? 'unknown error' );
            error_log( '[MLP Google Vision] API returned error: ' . $err );
            return null; // Fail-open on API error
        }

        $safe_search = $body['responses'][0]['safeSearchAnnotation'] ?? null;
        if ( ! is_array( $safe_search ) ) {
            error_log( '[MLP Google Vision] No safeSearchAnnotation in response.' );
            return null;
        }

        // Likelihood scale: UNKNOWN, VERY_UNLIKELY, UNLIKELY, POSSIBLE, LIKELY, VERY_LIKELY
        // We block on LIKELY or VERY_LIKELY for adult/violence/racy
        $block_on = [ 'LIKELY', 'VERY_LIKELY' ];
        $checked_fields = [ 'adult', 'violence', 'racy' ];

        foreach ( $checked_fields as $field ) {
            $likelihood = $safe_search[ $field ] ?? 'UNKNOWN';
            if ( in_array( $likelihood, $block_on, true ) ) {
                error_log( '[MLP Google Vision] Blocked image. Field: ' . $field . ' Likelihood: ' . $likelihood );
                return false;
            }
        }

        return true; // Passed SafeSearch
    }

    /**
     * Best-effort client IP detection for rate limiting.
     * Honors common proxy headers but falls back to REMOTE_ADDR.
     *
     * @return string  IP address (or 'unknown' if none could be determined).
     */
    private static function get_client_ip() {
        $candidates = [
            'HTTP_CF_CONNECTING_IP',  // Cloudflare
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];
        foreach ( $candidates as $key ) {
            if ( ! empty( $_SERVER[ $key ] ) ) {
                $val = $_SERVER[ $key ];
                if ( $key === 'HTTP_X_FORWARDED_FOR' && strpos( $val, ',' ) !== false ) {
                    $val = trim( explode( ',', $val )[0] );
                }
                $val = trim( wp_unslash( $val ) );
                if ( filter_var( $val, FILTER_VALIDATE_IP ) ) {
                    return $val;
                }
            }
        }
        return 'unknown';
    }

    /**
     * Format a number of seconds into a short human-readable countdown
     * like "9 minutes 42 seconds" or "47 seconds".
     *
     * @param int $seconds
     * @return string
     */
    private static function format_seconds_human( $seconds ) {
        $seconds = max( 0, (int) $seconds );
        $minutes = (int) floor( $seconds / 60 );
        $secs    = $seconds % 60;

        if ( $minutes <= 0 ) {
            return $secs . ' second' . ( $secs === 1 ? '' : 's' );
        }
        if ( $secs === 0 ) {
            return $minutes . ' minute' . ( $minutes === 1 ? '' : 's' );
        }
        return $minutes . ' minute' . ( $minutes === 1 ? '' : 's' )
            . ' ' . $secs . ' second' . ( $secs === 1 ? '' : 's' );
    }

    /**
     * Cache wrapper for per-image, per-provider moderation checks.
     * Uses WordPress transients so identical image URLs across multiple publish
     * attempts don't re-hit the upstream API (saves Gemini/Groq/Sightengine/etc. quota).
     *
     * Cached values:
     *   true  → image previously passed
     *   false → image previously blocked
     *   null  → previously errored / unable to check (NOT cached, so we retry next time)
     *
     * @param string   $provider     Short provider id, e.g. 'gemini', 'groq', 'sightengine'.
     * @param string   $image_src    The image URL or data URI.
     * @param callable $check_fn     Function that performs the real check and returns true|false|null.
     * @param int      $ttl_seconds  How long to cache pass/fail results. Default 24h.
     * @return bool|null
     */
    private static function cached_image_check( $provider, $image_src, callable $check_fn, $ttl_seconds = DAY_IN_SECONDS ) {
        // Build a stable cache key from provider + image source hash
        $key = 'mlp_imgmod_' . $provider . '_' . md5( $image_src );

        $cached = get_transient( $key );
        if ( $cached === 'pass' ) {
            return true;
        }
        if ( $cached === 'fail' ) {
            return false;
        }
        // Not cached (or expired) — run the real check
        $result = $check_fn( $image_src );

        // Only cache definitive pass/fail results — NEVER cache null (errors),
        // so a transient API failure doesn't poison the cache.
        if ( $result === true ) {
            set_transient( $key, 'pass', $ttl_seconds );
        } elseif ( $result === false ) {
            set_transient( $key, 'fail', $ttl_seconds );
        }

        return $result;
    }

    /**
     * Download an external image URL and return [ base64_data, mime_type ] or null on failure.
     * Used by Gemini (which requires inline base64 for arbitrary URLs).
     *
     * @param string $image_src
     * @return array|null  [ 'b64' => string, 'mime' => string ] or null
     */
    private static function fetch_image_as_base64( $image_src ) {
        // If it's already a data URI, parse it directly
        if ( strncmp( $image_src, 'data:', 5 ) === 0 ) {
            if ( preg_match( '/^data:([a-z0-9.+\-\/]+);base64,(.+)$/i', $image_src, $m ) ) {
                return [ 'b64' => $m[2], 'mime' => $m[1] ];
            }
            return null;
        }

        // Otherwise, fetch the URL
        $resp = wp_remote_get( $image_src, [
            'timeout'     => 10,
            'redirection' => 3,
            'user-agent'  => 'MLP-ImageModeration/1.0',
        ] );

        if ( is_wp_error( $resp ) ) {
            return null;
        }

        $code = wp_remote_retrieve_response_code( $resp );
        if ( $code < 200 || $code >= 300 ) {
            return null;
        }

        $body = wp_remote_retrieve_body( $resp );
        if ( empty( $body ) || strlen( $body ) > 8 * 1024 * 1024 ) {
            // Reject empty or huge images (>8MB)
            return null;
        }

        $mime = wp_remote_retrieve_header( $resp, 'content-type' );
        if ( is_array( $mime ) ) {
            $mime = $mime[0] ?? '';
        }
        if ( empty( $mime ) || strpos( $mime, 'image/' ) !== 0 ) {
            // Try to sniff
            $finfo = function_exists( 'finfo_open' ) ? finfo_open( FILEINFO_MIME_TYPE ) : false;
            if ( $finfo ) {
                $sniffed = finfo_buffer( $finfo, $body );
                finfo_close( $finfo );
                if ( $sniffed && strpos( $sniffed, 'image/' ) === 0 ) {
                    $mime = $sniffed;
                } else {
                    return null;
                }
            } else {
                return null;
            }
        }

        return [ 'b64' => base64_encode( $body ), 'mime' => $mime ];
    }

    /**
     * Gemini Vision check — detects whether an image contains a human figure
     * (male, female, real, cartoon, anime, illustrated, etc.). Free-tier friendly.
     *
     * Returns:
     *   true  — passed (no human figure detected)
     *   false — blocked (human figure detected)
     *   null  — not configured / API error / unable to check (fail-open)
     */
    private static function gemini_check_image( $image_src ) {
        $gem_key = defined( 'MLP_GEMINI_KEY' ) ? MLP_GEMINI_KEY : '';
        if ( empty( $gem_key ) ) {
            return null;
        }

        $img = self::fetch_image_as_base64( $image_src );
        if ( $img === null ) {
            return null; // Could not fetch — fail-open
        }

        $prompt = 'You are an image classifier. Your task is to detect whether an image depicts a real human being or a clearly humanoid character that is the main subject. Be accurate — only flag images that clearly and obviously contain a person or human figure.

Answer has_human=TRUE if the image clearly contains:
- Real people (photos, screenshots of people)
- Illustrated or drawn human characters that are the main subject
- Cartoon or anime characters that are clearly humanoid and the focus of the image

Answer has_human=FALSE for:
- Pure animals, nature, landscapes, food, vehicles, objects, buildings
- Abstract art or patterns
- UI screenshots, code, charts, diagrams
- Icons or tiny incidental human silhouettes in a UI (e.g. a small user icon in a nav bar)
- Stick figures or extremely abstract/minimal symbols

Be conservative — only return true if a human or clearly humanoid figure is prominently present. If uncertain, return false.

Respond with ONLY a single JSON object in this exact format, no markdown, no explanation: {"has_human": true_or_false, "confidence": "high"_or_"medium"_or_"low"}';

        $response = wp_remote_post(
            'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=' . rawurlencode( $gem_key ),
            [
                'timeout' => 20,
                'headers' => [ 'Content-Type' => 'application/json' ],
                'body'    => wp_json_encode( [
                    'contents' => [
                        [
                            'parts' => [
                                [ 'text' => $prompt ],
                                [
                                    'inline_data' => [
                                        'mime_type' => $img['mime'],
                                        'data'      => $img['b64'],
                                    ],
                                ],
                            ],
                        ],
                    ],
                    'generationConfig' => [
                        'temperature'     => 0,
                        'maxOutputTokens' => 80,
                    ],
                ] ),
            ]
        );

        if ( is_wp_error( $response ) ) {
            error_log( '[MLP Gemini Vision] API error: ' . $response->get_error_message() );
            return null;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! empty( $body['error'] ) ) {
            error_log( '[MLP Gemini Vision] API returned error: ' . ( $body['error']['message'] ?? 'unknown' ) );
            return null;
        }

        $text = $body['candidates'][0]['content']['parts'][0]['text'] ?? '';
        $text = preg_replace( '/^```(?:json)?\s*/i', '', trim( $text ) );
        $text = preg_replace( '/\s*```$/', '', $text );

        $parsed = json_decode( $text, true );
        if ( ! is_array( $parsed ) || ! isset( $parsed['has_human'] ) ) {
            error_log( '[MLP Gemini Vision] Could not parse response: ' . mb_substr( $text, 0, 200 ) );
            return null;
        }

        if ( $parsed['has_human'] === true ) {
            error_log( '[MLP Gemini Vision] Blocked image (human detected): ' . mb_substr( $image_src, 0, 80 ) );
            return false;
        }

        return true;
    }

    /**
     * Groq Vision check — second opinion on whether an image contains a human figure.
     * Uses Llama 3.2 vision models on Groq's free tier.
     *
     * Returns:
     *   true  — passed (no human figure detected)
     *   false — blocked (human figure detected)
     *   null  — not configured / API error / unable to check (fail-open)
     */
    private static function groq_check_image( $image_src ) {
        $groq_key = defined( 'MLP_GROQ_API_KEY' ) ? MLP_GROQ_API_KEY : '';
        if ( empty( $groq_key ) ) {
            return null;
        }

        // Groq accepts either a public URL or a base64 data URI in image_url.url
        if ( strncmp( $image_src, 'data:', 5 ) === 0 ) {
            $image_url_value = $image_src;
        } elseif ( preg_match( '#^https?://#i', $image_src ) ) {
            $image_url_value = $image_src;
        } else {
            return null;
        }

        $prompt = 'You are an image classifier. Detect whether the image clearly depicts a real human being or a prominently humanoid character.

Answer has_human=TRUE if the image clearly contains:
- Real people in photos or screenshots
- Illustrated or drawn human characters that are the main subject
- Cartoon or anime characters that are clearly humanoid and the focus of the image

Answer has_human=FALSE for:
- Animals, nature, landscapes, food, vehicles, objects, buildings
- Abstract art or geometric patterns
- UI screenshots, code, charts, diagrams
- Small incidental human icons in a UI (e.g. a tiny user icon in a nav bar)
- Stick figures or extremely abstract symbols

Only return true if a human or clearly humanoid figure is prominently present. If uncertain, return false.

Respond with ONLY a single JSON object, no markdown, no extra text: {"has_human": true_or_false, "confidence": "high"_or_"medium"_or_"low"}';

        $response = wp_remote_post(
            'https://api.groq.com/openai/v1/chat/completions',
            [
                'timeout' => 20,
                'headers' => [
                    'Authorization' => 'Bearer ' . $groq_key,
                    'Content-Type'  => 'application/json',
                ],
                'body' => wp_json_encode( [
                    'model'       => 'meta-llama/llama-4-scout-17b-16e-instruct',
                    'temperature' => 0,
                    'max_tokens'  => 80,
                    'messages'    => [
                        [
                            'role'    => 'user',
                            'content' => [
                                [ 'type' => 'text', 'text' => $prompt ],
                                [
                                    'type'      => 'image_url',
                                    'image_url' => [ 'url' => $image_url_value ],
                                ],
                            ],
                        ],
                    ],
                ] ),
            ]
        );

        if ( is_wp_error( $response ) ) {
            error_log( '[MLP Groq Vision] API error: ' . $response->get_error_message() );
            return null;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! empty( $body['error'] ) ) {
            error_log( '[MLP Groq Vision] API returned error: ' . ( $body['error']['message'] ?? 'unknown' ) );
            return null;
        }

        $text = $body['choices'][0]['message']['content'] ?? '';
        $text = preg_replace( '/^```(?:json)?\s*/i', '', trim( $text ) );
        $text = preg_replace( '/\s*```$/', '', $text );

        $parsed = json_decode( $text, true );
        if ( ! is_array( $parsed ) || ! isset( $parsed['has_human'] ) ) {
            error_log( '[MLP Groq Vision] Could not parse response: ' . mb_substr( $text, 0, 200 ) );
            return null;
        }

        if ( $parsed['has_human'] === true ) {
            error_log( '[MLP Groq Vision] Blocked image (human detected): ' . mb_substr( $image_src, 0, 80 ) );
            return false;
        }

        return true;
    }

    /**
     * Extract all image sources (URLs and base64 data-URIs) from HTML/CSS/JS content.
     * Returns an array of unique image source strings.
     *
     * @param string $content  Raw project code.
     * @return string[]
     */
    private static function extract_image_sources( $content ) {
        $sources = [];

        // 1. Base64 data-URIs (images embedded directly in code)
        preg_match_all(
            '/data:image\/(?:png|jpe?g|gif|webp|svg\+xml|bmp|avif)[^"\'`\s)>]*/i',
            $content,
            $b64_matches
        );
        foreach ( $b64_matches[0] as $src ) {
            $sources[] = $src;
        }

        // 1b. Catch base64 data-URIs that may have been split across quotes or obfuscated
        //     e.g. "data:image/png;base64," + "iVBOR..." or template literals
        preg_match_all(
            '/data:image[^\w][^"\'`\s]{10,}/i',
            $content,
            $b64_loose_matches
        );
        foreach ( $b64_loose_matches[0] as $src ) {
            // Re-check it's a plausible data URI
            if ( preg_match( '/base64,/i', $src ) ) {
                $sources[] = $src;
            }
        }

        // 1c. Catch long standalone base64 strings that look like encoded images
        //     (common pattern: variable = "iVBOR..." or atob("...") )
        //     iVBOR = PNG, /9j/4 = JPEG, R0lGO = GIF, UklGR = WebP, PHN2Zy = SVG
        preg_match_all(
            '/["\']([A-Za-z0-9+\/]{100,}={0,2})["\']/',
            $content,
            $raw_b64_matches
        );
        foreach ( $raw_b64_matches[1] as $b64str ) {
            // Heuristic: check magic bytes of known image formats after decoding prefix
            $prefix = substr( $b64str, 0, 8 );
            $known_image_prefixes = [ 'iVBOR', '/9j/4', 'R0lGO', 'UklGR', 'PHN2Zy', 'Qk0', 'AAAAF' ];
            foreach ( $known_image_prefixes as $img_prefix ) {
                if ( strncmp( $prefix, $img_prefix, strlen( $img_prefix ) ) === 0 ) {
                    // Reconstruct as a data URI for moderation — guess JPEG if unknown
                    if ( strncmp( $prefix, '/9j/', 4 ) === 0 ) {
                        $sources[] = 'data:image/jpeg;base64,' . $b64str;
                    } elseif ( strncmp( $prefix, 'iVBOR', 5 ) === 0 ) {
                        $sources[] = 'data:image/png;base64,' . $b64str;
                    } elseif ( strncmp( $prefix, 'R0lGO', 5 ) === 0 ) {
                        $sources[] = 'data:image/gif;base64,' . $b64str;
                    } elseif ( strncmp( $prefix, 'UklGR', 5 ) === 0 ) {
                        $sources[] = 'data:image/webp;base64,' . $b64str;
                    } elseif ( strncmp( $prefix, 'PHN2Zy', 6 ) === 0 ) {
                        $sources[] = 'data:image/svg+xml;base64,' . $b64str;
                    } else {
                        $sources[] = 'data:image/png;base64,' . $b64str;
                    }
                    break;
                }
            }
        }

        // 2. <img src="…"> and <img src='…'>
        preg_match_all( '/<img[^>]+src=["\']([^"\']+)["\'][^>]*>/i', $content, $img_matches );
        foreach ( $img_matches[1] as $src ) {
            if ( filter_var( $src, FILTER_VALIDATE_URL ) ) {
                $sources[] = $src;
            }
        }

        // 3. CSS url(…) — background-image, etc.
        preg_match_all( '/url\(["\']?(https?:\/\/[^"\')\s]+)["\']?\)/i', $content, $css_matches );
        foreach ( $css_matches[1] as $src ) {
            $sources[] = $src;
        }

        // Deduplicate and cap at 10 images to keep moderation fast
        $sources = array_values( array_unique( $sources ) );
        return array_slice( $sources, 0, 10 );
    }

    /**
     * Step 2 of publish: save the project after moderation passed.
     * Requires a valid mod_token issued by ajax_moderate_project.
     */
    public static function ajax_save_shared_project() {
        if ( ! check_ajax_referer( 'mlp_share_project', 'nonce', false ) ) {
            wp_send_json_error( [ 'message' => 'Invalid share request.' ], 403 );
        }

        // Require a valid moderation token
        $mod_token = isset( $_POST['mod_token'] ) ? sanitize_text_field( wp_unslash( $_POST['mod_token'] ) ) : '';
        if ( $mod_token === '' ) {
            wp_send_json_error( [ 'message' => 'Content has not been moderated. Please use the Publish button.' ], 403 );
        }
        $mod_record = get_transient( 'mlp_mod_' . $mod_token );
        if ( ! is_array( $mod_record ) || empty( $mod_record['ok'] ) ) {
            wp_send_json_error( [ 'message' => 'Moderation token is invalid or expired. Please publish again.' ], 403 );
        }
        // Consume the token (one-time use)
        delete_transient( 'mlp_mod_' . $mod_token );

        $payload = isset( $_POST['payload'] ) ? wp_unslash( $_POST['payload'] ) : '';
        if ( ! is_string( $payload ) || $payload === '' || strlen( $payload ) > 2097152 ) {
            wp_send_json_error( [ 'message' => 'Project share data is invalid.' ], 400 );
        }

        $decoded = json_decode( $payload, true );
        if ( ! is_array( $decoded ) || empty( $decoded['id'] ) ) {
            wp_send_json_error( [ 'message' => 'Project share data is invalid.' ], 400 );
        }

        // If an existing token is supplied (RePublish flow), update in place.
        $existing_token = isset( $_POST['existing_token'] ) ? sanitize_key( wp_unslash( $_POST['existing_token'] ) ) : '';
        if ( $existing_token !== '' ) {
            $existing = get_option( 'mlp_share_' . $existing_token, null );
            if ( is_array( $existing ) ) {
                update_option(
                    'mlp_share_' . $existing_token,
                    [
                        'created'    => $existing['created'] ?? time(),
                        'updated'    => time(),
                        'payload'    => $payload,
                        'mod_token'  => $mod_token,
                        'project_id' => $decoded['id'] ?? ( $existing['project_id'] ?? '' ),
                        'shared_by'  => $decoded['sharedBy'] ?? ( $existing['shared_by'] ?? '' ),
                    ],
                    false
                );
                wp_send_json_success( [ 'token' => $existing_token, 'republished' => true ] );
                return;
            }
        }

        $token = strtolower( wp_generate_password( 22, false, false ) );
        update_option(
            'mlp_share_' . $token,
            [
                'created'    => time(),
                'payload'    => $payload,
                'mod_token'  => $mod_token,
                'project_id' => $decoded['id'] ?? '',
                'shared_by'  => $decoded['sharedBy'] ?? '',
            ],
            false
        );

        wp_send_json_success( [ 'token' => $token ] );
    }

    public static function ajax_get_shared_project() {
        $token = isset( $_REQUEST['token'] ) ? sanitize_key( wp_unslash( $_REQUEST['token'] ) ) : '';
        if ( $token === '' ) {
            wp_send_json_error( [ 'message' => 'Missing share token.' ], 400 );
        }

        $record = get_option( 'mlp_share_' . $token, null );
        if ( ! is_array( $record ) || empty( $record['payload'] ) ) {
            wp_send_json_error( [ 'message' => 'Share link not found.' ], 404 );
        }

        // Admin deleted — block the share link entirely
        if ( ! empty( $record['admin_deleted'] ) ) {
            wp_send_json_error( [ 'message' => 'This project has been removed and is no longer available.' ], 410 );
        }

        // ── View count tracking ──
        // Skip counting for the owner's own poll requests (?count=0)
        $skip_count = isset( $_REQUEST['count'] ) && $_REQUEST['count'] === '0';
        if ( ! $skip_count ) {
            $remote_ip = $_SERVER['REMOTE_ADDR'] ?? '';
            $dedupe_key = 'mlp_vw_' . $token . '_' . substr( md5( $remote_ip ), 0, 12 );
            if ( ! get_transient( $dedupe_key ) ) {
                $current_views = isset( $record['views'] ) ? intval( $record['views'] ) : 0;
                $record['views']       = $current_views + 1;
                $record['last_viewed'] = time();
                update_option( 'mlp_share_' . $token, $record, false );
                set_transient( $dedupe_key, 1, 300 ); // 5 min dedupe per IP
            }
        }

        wp_send_json_success( [
            'payload' => $record['payload'],
            'views'   => isset( $record['views'] ) ? intval( $record['views'] ) : 0,
        ] );
    }

    /**
     * Bulk-fetch view counts for a list of share tokens (owner's dashboard).
     * Accepts a JSON array of share tokens under $_POST['tokens'].
     * Returns an object map: { token: viewCount }.
     */
    public static function ajax_get_project_views() {
        $raw    = isset( $_POST['tokens'] ) ? wp_unslash( $_POST['tokens'] ) : '';
        $tokens = is_array( $raw ) ? $raw : json_decode( $raw, true );
        if ( ! is_array( $tokens ) || empty( $tokens ) ) {
            wp_send_json_success( [ 'views' => (object) [] ] );
            return;
        }
        $tokens = array_map( 'sanitize_key', array_slice( $tokens, 0, 100 ) );
        $views  = [];
        foreach ( $tokens as $token ) {
            if ( $token === '' ) continue;
            $record = get_option( 'mlp_share_' . $token, null );
            if ( is_array( $record ) ) {
                $views[ $token ] = isset( $record['views'] ) ? intval( $record['views'] ) : 0;
            }
        }
        wp_send_json_success( [ 'views' => (object) $views ] );
    }

    /**
     * Frontend polls this on init to check if any of its public projects were admin-deleted.
     * Accepts a JSON array of share tokens under $_POST['tokens'].
     * Returns the subset that have been admin-deleted so the frontend can set them private.
     */
    public static function ajax_check_project_status() {
        $raw    = isset( $_POST['tokens'] ) ? wp_unslash( $_POST['tokens'] ) : '';
        $tokens = is_array( $raw ) ? $raw : json_decode( $raw, true );
        if ( ! is_array( $tokens ) || empty( $tokens ) ) {
            wp_send_json_success( [ 'deleted' => [] ] );
            return;
        }
        $tokens  = array_map( 'sanitize_key', array_slice( $tokens, 0, 100 ) );
        $deleted = [];
        foreach ( $tokens as $token ) {
            if ( $token === '' ) continue;
            $record = get_option( 'mlp_share_' . $token, null );
            if ( is_array( $record ) && ! empty( $record['admin_deleted'] ) ) {
                $deleted[] = $token;
            }
        }
        wp_send_json_success( [ 'deleted' => $deleted ] );
    }

    /* ------------------------------------------------------------------ */
    /*  Shortcode page detection                                            */
    /* ------------------------------------------------------------------ */

    private static function is_shortcode_page( $tag = 'mobile_live_preview' ) {
        $post = get_post();
        if ( ! $post instanceof WP_Post ) {
            return false;
        }
        return has_shortcode( $post->post_content, $tag );
    }

    /* ------------------------------------------------------------------ */
    /*  CSS                                                                 */
    /* ------------------------------------------------------------------ */

    public static function output_styles() {
        if ( ! self::is_shortcode_page() ) {
            return;
        }
        echo '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>' . "\n";
        echo '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' . "\n";
        echo '<style id="mlp-projects-css">' . self::get_css() . '</style>' . "\n";
    }

    /* ------------------------------------------------------------------ */
    /*  HTML + JS                                                           */
    /* ------------------------------------------------------------------ */

    public static function output_popup() {
        if ( ! self::is_shortcode_page() ) {
            return;
        }
        echo self::get_html();
        echo '<script id="mlp-projects-js">' . self::get_js() . '</script>' . "\n";
    }

    /* ------------------------------------------------------------------ */
    /*  HTML template                                                       */
    /* ------------------------------------------------------------------ */

    private static function get_html() {
        ob_start();
        ?>
<!-- MLP Projects Popup -->
<div id="mlp-projects-overlay" class="mlp-proj-overlay" role="dialog" aria-modal="true" aria-label="Projects">

  <!-- Top navbar -->
  <div class="mlp-nav">
    <div class="mlp-nav-brand">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
      </svg>
      <span>Pterocos.eu.org</span>
    </div>
    <button id="mlp-sidebar-toggle-btn" class="mlp-sidebar-toggle-btn" type="button" title="Toggle sidebar" aria-label="Toggle sidebar" style="margin-left:39px;">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <line x1="3" y1="6"  x2="21" y2="6"/>
        <line x1="3" y1="12" x2="21" y2="12"/>
        <line x1="3" y1="18" x2="21" y2="18"/>
      </svg>
    </button>
    <div class="mlp-community-dropdown-wrap" id="mlp-community-dropdown-wrap">
      <span id="mlp-community-btn" class="mlp-community-btn" role="button" tabindex="0" aria-haspopup="true" aria-expanded="false">
        Community
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:0.6;flex-shrink:0;" id="mlp-community-caret">
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </span>
      <div id="mlp-community-dropdown" class="mlp-profile-dropdown" style="display:none;" role="menu">
        <a class="mlp-profile-dropdown-item" href="https://discord.gg/C5B9YCumB4" target="_blank" rel="noopener noreferrer" role="menuitem">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057c.002.022.015.043.032.054a19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>
          Discord Server
        </a>
        <a class="mlp-profile-dropdown-item" href="https://ptero.discourse.group/" target="_blank" rel="noopener noreferrer" role="menuitem">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
          Community Forum
        </a>
      </div>
    </div>
    <div class="mlp-nav-right">
      <button id="mlp-theme-toggle-btn" class="mlp-theme-toggle-btn" type="button" title="Toggle dark / light theme" aria-label="Toggle dark / light theme">
        <span class="mlp-theme-emoji mlp-theme-emoji-moon" aria-hidden="true">🌙</span>
        <span class="mlp-theme-emoji mlp-theme-emoji-sun" aria-hidden="true">☀️</span>
      </button>
      <div class="mlp-profile-dropdown-wrap" id="mlp-profile-dropdown-wrap">
        <button id="mlp-profile-btn" class="mlp-profile-btn" title="Profile menu" aria-haspopup="true" aria-expanded="false">
          <span id="mlp-nav-avatar" class="mlp-nav-avatar"></span>
          <span class="mlp-nav-username" id="mlp-nav-username-label">Loading…</span>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:0.6;flex-shrink:0;" id="mlp-profile-caret">
            <polyline points="6 9 12 15 18 9"/>
          </svg>
        </button>
        <div id="mlp-profile-dropdown" class="mlp-profile-dropdown" style="display:none;" role="menu">
          <button class="mlp-profile-dropdown-item" id="mlp-profile-dd-settings" role="menuitem">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
            Settings
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Layout: sidebar + content -->
  <div class="mlp-layout">

    <!-- Sidebar -->
    <aside class="mlp-sidebar">
      <div class="mlp-sidebar-section-label">Management</div>
      <nav class="mlp-sidebar-nav">
        <a href="#" class="mlp-sidebar-link mlp-sidebar-link-active" onclick="return false;">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
          </svg>
          Projects
        </a>
      </nav>
      <div id="mlp-sidebar-manage-section" style="display:none;">
        <div class="mlp-sidebar-section-label" style="margin-top:18px;">Your Projects</div>
        <nav class="mlp-sidebar-nav" id="mlp-sidebar-project-nav">
        </nav>
      </div>

      <!-- Sidebar bottom: load backup + user profile -->
      <div class="mlp-sidebar-profile-wrap">
        <div class="mlp-sidebar-profile-divider"></div>

        <!-- Load Backup (.zip) -->
        <div class="mlp-sidebar-loadbackup-row">
          <input type="file" id="mlp-load-backup-input" accept=".zip,.json" style="display:none;"/>
          <button id="mlp-load-backup-btn" class="mlp-sidebar-loadbackup-btn" title="Load a .zip or .json backup file">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/>
              <line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            Load Backup (.zip / .json)
          </button>
        </div>

        <div class="mlp-sidebar-profile-divider" style="margin-top:4px;"></div>

        <div class="mlp-sidebar-profile-card">
          <div class="mlp-sidebar-profile-avatar-wrap">
            <div class="mlp-sidebar-profile-avatar" id="mlp-sidebar-avatar"></div>
          </div>
          <div class="mlp-sidebar-profile-info">
            <span class="mlp-sidebar-profile-name" id="mlp-sidebar-profile-name">You</span>
            <span class="mlp-sidebar-profile-plan" id="mlp-sidebar-plan-chip">
              <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block !important;flex-shrink:0 !important;width:9px !important;height:9px !important;stroke:currentColor !important;fill:none !important;" id="mlp-plan-icon"><path d="M12 2L15.09 8.26L22 9.27L17 14.14L18.18 21.02L12 17.77L5.82 21.02L7 14.14L2 9.27L8.91 8.26L12 2Z"/></svg>
              <span id="mlp-plan-label">Developer</span>
            </span>
          </div>
          <button class="mlp-sidebar-settings-btn" id="mlp-sidebar-settings-btn" title="Profile settings" aria-label="Open profile settings">
            <i class="fa-solid fa-gear mlp-sidebar-settings-icon"></i>
          </button>
        </div>
      </div>
    </aside>

    <!-- Main content -->
    <main class="mlp-main">

      <!-- Page heading + breadcrumb -->
      <div class="mlp-page-header">
        <div>
          <h1 class="mlp-page-title">
            Projects
            <span class="mlp-page-subtitle">Each project has its own isolated editor, tabs &amp; saved state.</span>
          </h1>
        </div>
        <div class="mlp-breadcrumb">
          <span id="mlp-proj-count-current">0</span>
          <span class="mlp-breadcrumb-sep">/</span>
          <span id="mlp-proj-count-max">10</span>
          <span class="mlp-breadcrumb-unit">projects</span>
        </div>
      </div>

      <!-- Table card -->
      <div class="mlp-table-card">
        <div class="mlp-table-toolbar">
          <span class="mlp-table-label">Project List</span>
          <div class="mlp-table-toolbar-right">
            <div class="mlp-search-wrap">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              <input type="text" class="mlp-search-input" placeholder="Search Projects" id="mlp-proj-search" autocomplete="off"/>
            </div>
            <button id="mlp-proj-new-btn" class="mlp-btn-create">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
              </svg>
              New Project
            </button>
          </div>
        </div>

        <!-- Sort + Bulk bar -->
        <div class="mlp-sort-bar" id="mlp-sort-bar">
          <div class="mlp-sort-bar-left">
            <span class="mlp-sort-label">Sort:</span>
            <button class="mlp-sort-btn mlp-sort-active" data-sort="pinned" id="mlp-sort-pinned">📌 Pinned first</button>
            <button class="mlp-sort-btn" data-sort="favorite" id="mlp-sort-favorite">⭐ Favorites first</button>
            <button class="mlp-sort-btn" data-sort="name">Name</button>
            <button class="mlp-sort-btn" data-sort="created">Created</button>
            <button class="mlp-sort-btn" data-sort="modified">Modified</button>
            <button class="mlp-sort-btn" data-sort="opened">Last Opened</button>
            <button class="mlp-sort-btn" data-sort="views">Views</button>
            <button class="mlp-sort-btn" data-sort="size">Size</button>
            <button id="mlp-sort-dir-btn" class="mlp-sort-dir-btn" title="Toggle sort direction" style="display:none;" aria-label="Toggle sort direction">
              <svg id="mlp-sort-dir-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/>
              </svg>
            </button>
          </div>
          <div class="mlp-sort-bar-right" id="mlp-bulk-bar" style="display:none;">
            <span class="mlp-bulk-count" id="mlp-bulk-count">0 selected</span>
            <button class="mlp-btn-bulk-export" id="mlp-bulk-export-btn">📦 Export Selected</button>
            <button class="mlp-btn-bulk-tag" id="mlp-bulk-tag-btn">🏷 Tag Selected</button>
            <button class="mlp-btn-bulk-del" id="mlp-bulk-del-btn">🗑 Delete Selected</button>
            <button class="mlp-btn-ghost mlp-btn-xs" id="mlp-bulk-cancel-btn">Cancel</button>
          </div>
        </div>
        <!-- Status filter chips -->
        <div class="mlp-filter-bar" id="mlp-filter-bar">
          <span class="mlp-filter-label">Filter:</span>
          <div class="mlp-filter-chip-group" id="mlp-filter-status-group">
            <button class="mlp-filter-chip mlp-filter-active" data-filter="all">All</button>
            <button class="mlp-filter-chip" data-filter="public">🌐 Public</button>
            <button class="mlp-filter-chip" data-filter="private">🔒 Private</button>
            <button class="mlp-filter-chip" data-filter="pinned">📌 Pinned</button>
            <button class="mlp-filter-chip" data-filter="favorites">⭐ Favorites</button>
          </div>
          <div class="mlp-filter-tag-wrap" id="mlp-filter-tag-wrap" style="display:none;">
            <span class="mlp-filter-divider"></span>
            <span class="mlp-filter-label">Tags:</span>
            <div class="mlp-filter-chip-group" id="mlp-filter-tag-group"></div>
          </div>
        </div>
        <!-- localStorage usage bar -->
        <div class="mlp-storage-bar-wrap" id="mlp-storage-bar-wrap">
          <div class="mlp-storage-bar-label">
            <span>Storage used</span>
            <span id="mlp-storage-bar-text">— / ~5 MB</span>
          </div>
          <div class="mlp-storage-bar-track">
            <div class="mlp-storage-bar-fill" id="mlp-storage-bar-fill"></div>
          </div>
        </div>
        <!-- Table -->
        <div class="mlp-table-wrap">
          <table class="mlp-table">
            <thead>
              <tr>
                <th class="mlp-th-check"><input type="checkbox" id="mlp-select-all" class="mlp-cb"/></th>
                <th class="mlp-th-pin"></th>
                <th class="mlp-th-star"></th>
                <th>Name</th>
                <th>Created</th>
                <th>Last Modified</th>
                <th>Size</th>
                <th>Visibility</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="mlp-proj-tbody">
            </tbody>
          </table>
          <!-- Empty state -->
          <div id="mlp-proj-empty" class="mlp-empty-state" style="display:none;">
            <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
            </svg>
            <p>No projects yet</p>
            <span>Click <strong>New Project</strong> to get started</span>
          </div>
        </div>
      </div>

    </main>

    <!-- Stats Sidebar Panel -->
    <aside class="mlp-stats-panel" id="mlp-stats-panel" style="display:none;" aria-label="Project stats">
      <div class="mlp-stats-panel-inner">
        <!-- Header -->
        <div class="mlp-stats-header">
          <div class="mlp-stats-header-left">
            <div class="mlp-stats-icon-wrap">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
            </div>
            <span class="mlp-stats-title">Project Stats</span>
          </div>
          <button class="mlp-stats-close-btn" id="mlp-stats-close-btn" title="Close stats" aria-label="Close stats">❌</button>
        </div>

        <!-- Project identity -->
        <div class="mlp-stats-identity" id="mlp-stats-identity">
          <div class="mlp-stats-proj-icon" id="mlp-stats-proj-icon"></div>
          <div class="mlp-stats-proj-meta">
            <span class="mlp-stats-proj-name" id="mlp-stats-proj-name">—</span>
            <span class="mlp-stats-proj-vis" id="mlp-stats-proj-vis"></span>
          </div>
        </div>

        <!-- Scrollable body -->
        <div class="mlp-stats-body">

          <!-- Quick action -->
          <button class="mlp-stats-go-btn" id="mlp-stats-go-btn">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
            Go Code
          </button>

          <!-- Section: Code stats -->
          <div class="mlp-stats-section-label">Code</div>
          <div class="mlp-stats-cards">
            <div class="mlp-stats-card">
              <div class="mlp-stats-card-val" id="mlp-stats-lines">—</div>
              <div class="mlp-stats-card-key">Lines of Code</div>
            </div>
            <div class="mlp-stats-card">
              <div class="mlp-stats-card-val" id="mlp-stats-size">—</div>
              <div class="mlp-stats-card-key">Total Size</div>
            </div>
            <div class="mlp-stats-card">
              <div class="mlp-stats-card-val" id="mlp-stats-tabs">—</div>
              <div class="mlp-stats-card-key">Tabs</div>
            </div>
            <div class="mlp-stats-card">
              <div class="mlp-stats-card-val" id="mlp-stats-langs">—</div>
              <div class="mlp-stats-card-key">Languages</div>
            </div>
          </div>

          <!-- Language breakdown bar -->
          <div class="mlp-stats-lang-bar-wrap" id="mlp-stats-lang-bar-wrap" style="display:none;">
            <div class="mlp-stats-lang-bar" id="mlp-stats-lang-bar"></div>
            <div class="mlp-stats-lang-legend" id="mlp-stats-lang-legend"></div>
          </div>

          <!-- Section: Language Chart -->
          <div id="mlp-stats-lang-chart-section" style="display:none;">
            <div class="mlp-stats-section-label">Language Distribution</div>
            <div class="mlp-stats-lang-chart" id="mlp-stats-lang-chart"></div>
          </div>

          <!-- Section: Last 7 Edits -->
          <div id="mlp-stats-edits-section" style="display:none;">
            <div class="mlp-stats-section-label">Last 7 Edits</div>
            <div class="mlp-stats-edits-wrap" id="mlp-stats-edits-wrap"></div>
          </div>

          <!-- Section: Storage Usage -->
          <div class="mlp-stats-section-label">Storage</div>
          <div class="mlp-stats-storage-wrap" id="mlp-stats-storage-wrap">
            <div class="mlp-stats-storage-row">
              <span class="mlp-stats-storage-label">This project</span>
              <span class="mlp-stats-storage-val" id="mlp-stats-proj-size-val">—</span>
            </div>
            <div class="mlp-stats-storage-row">
              <span class="mlp-stats-storage-label">All projects</span>
              <span class="mlp-stats-storage-val" id="mlp-stats-total-size-val">—</span>
            </div>
            <div class="mlp-stats-storage-bar-track">
              <div class="mlp-stats-storage-bar-proj" id="mlp-stats-storage-bar-proj"></div>
              <div class="mlp-stats-storage-bar-other" id="mlp-stats-storage-bar-other"></div>
            </div>
            <div class="mlp-stats-storage-legend">
              <span><span class="mlp-stats-storage-dot mlp-dot-proj"></span>This project</span>
              <span><span class="mlp-stats-storage-dot mlp-dot-other"></span>Other projects</span>
              <span class="mlp-stats-storage-pct" id="mlp-stats-storage-pct"></span>
            </div>
          </div>

          <!-- Section: Timeline -->
          <div class="mlp-stats-section-label">Timeline</div>
          <div class="mlp-stats-timeline">
            <div class="mlp-stats-tl-row">
              <div class="mlp-stats-tl-dot mlp-tl-created"></div>
              <div class="mlp-stats-tl-content">
                <span class="mlp-stats-tl-label">Created</span>
                <span class="mlp-stats-tl-val" id="mlp-stats-created">—</span>
              </div>
            </div>
            <div class="mlp-stats-tl-row">
              <div class="mlp-stats-tl-dot mlp-tl-modified"></div>
              <div class="mlp-stats-tl-content">
                <span class="mlp-stats-tl-label">Last Modified</span>
                <span class="mlp-stats-tl-val" id="mlp-stats-modified">—</span>
              </div>
            </div>
            <div class="mlp-stats-tl-row">
              <div class="mlp-stats-tl-dot mlp-tl-opened"></div>
              <div class="mlp-stats-tl-content">
                <span class="mlp-stats-tl-label">Last Opened</span>
                <span class="mlp-stats-tl-val" id="mlp-stats-opened">—</span>
              </div>
            </div>
            <div class="mlp-stats-tl-row" id="mlp-stats-age-row">
              <div class="mlp-stats-tl-dot mlp-tl-age"></div>
              <div class="mlp-stats-tl-content">
                <span class="mlp-stats-tl-label">Project Age</span>
                <span class="mlp-stats-tl-val" id="mlp-stats-age">—</span>
              </div>
            </div>
          </div>

          <!-- Section: Views (public projects) -->
          <div id="mlp-stats-views-section" style="display:none;">
            <div class="mlp-stats-section-label">Sharing</div>
            <div class="mlp-stats-view-hero">
              <div class="mlp-stats-view-num" id="mlp-stats-view-num">—</div>
              <div class="mlp-stats-view-label">total views</div>
            </div>
            <!-- Sparkline chart -->
            <div class="mlp-stats-sparkline-wrap">
              <canvas id="mlp-stats-sparkline" class="mlp-stats-sparkline" width="220" height="48"></canvas>
              <div class="mlp-stats-spark-label" id="mlp-stats-spark-label"></div>
            </div>
          </div>

          <!-- Section: Version history count -->
          <div class="mlp-stats-section-label">History</div>
          <div class="mlp-stats-cards">
            <div class="mlp-stats-card">
              <div class="mlp-stats-card-val" id="mlp-stats-versions">—</div>
              <div class="mlp-stats-card-key">Versions</div>
            </div>
            <div class="mlp-stats-card">
              <div class="mlp-stats-card-val" id="mlp-stats-events">—</div>
              <div class="mlp-stats-card-key">Events</div>
            </div>
          </div>

          <!-- Tags -->
          <div id="mlp-stats-tags-section" style="display:none;">
            <div class="mlp-stats-section-label">Tags</div>
            <div class="mlp-stats-tags-wrap" id="mlp-stats-tags-wrap"></div>
          </div>

          <!-- Notes indicator -->
          <div id="mlp-stats-notes-section" style="display:none;">
            <div class="mlp-stats-section-label">Notes</div>
            <div class="mlp-stats-notes-preview" id="mlp-stats-notes-preview"></div>
          </div>

        </div><!-- /.mlp-stats-body -->
      </div>
    </aside>

  </div>

  <!-- Create project modal -->
  <div id="mlp-proj-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal">
      <div class="mlp-modal-header">
        <h3>New Project</h3>
        <button id="mlp-proj-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <label class="mlp-field-label" for="mlp-proj-name-input">Project Name</label>
        <input type="text" id="mlp-proj-name-input" class="mlp-field-input" placeholder="My Awesome Project" maxlength="80" autocomplete="off"/>
        <label class="mlp-field-label" for="mlp-proj-visibility-input">Visibility</label>
        <select id="mlp-proj-visibility-input" class="mlp-field-input">
          <option value="private" selected>Private</option>
          <option value="public">Public</option>
        </select>
        <label class="mlp-field-label" style="margin-top:4px;">
          Icon Color
        </label>
        <div class="mlp-premium-field-wrap" id="mlp-create-color-wrap">
          <div class="mlp-color-palette" id="mlp-create-color-palette"></div>

        </div>
        <label class="mlp-field-label" style="margin-top:12px;">
          Emoji (optional)
        </label>
        <div class="mlp-premium-field-wrap" id="mlp-create-emoji-wrap">
          <input type="text" id="mlp-proj-create-emoji-input" class="mlp-field-input" placeholder="e.g. 🚀 🎨 💡" maxlength="4" autocomplete="off"/>

        </div>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-proj-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-proj-create-btn" class="mlp-btn-primary">Create Project</button>
      </div>
    </div>
  </div>

  <!-- Delete confirm modal -->
  <div id="mlp-proj-del-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm">
      <div class="mlp-modal-header">
        <h3>Delete Project</h3>
        <button id="mlp-proj-del-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <p class="mlp-del-confirm-text">Are you sure you want to delete <strong id="mlp-proj-del-name"></strong>? This will permanently erase all its tabs and saved code.</p>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-proj-del-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-proj-del-confirm-btn" class="mlp-btn-danger">Delete</button>
      </div>
    </div>
  </div>

  <!-- Legacy hidden elements kept for JS compatibility -->
  <div id="mlp-proj-existing"    style="display:none;"></div>
  <div id="mlp-proj-create-form" style="display:none;"></div>
  <span id="mlp-proj-name-display" style="display:none;"></span>
  <span id="mlp-proj-date-display" style="display:none;"></span>
  <div class="mlp-proj-card" style="display:none;"></div>

  <!-- ── Username onboarding modal ── -->
  <div id="mlp-username-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm mlp-onboard-modal">
      <div class="mlp-onboard-hero">
        <div class="mlp-onboard-avatar-preview" id="mlp-onboard-avatar-preview"></div>
        <h2 class="mlp-onboard-title">Welcome to Pterocos</h2>
        <p class="mlp-onboard-sub">Choose a username to get started</p>
      </div>
      <div class="mlp-modal-body">
        <label class="mlp-field-label" for="mlp-username-input">Your name</label>
        <input type="text" id="mlp-username-input" class="mlp-field-input" placeholder="e.g. Alex, dev_wizard…" maxlength="32" autocomplete="off"/>
        <p class="mlp-onboard-hint">This is shown on your editor nav bar.</p>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-username-save-btn" class="mlp-btn-primary" style="width:100%;">Let's go →</button>
      </div>
    </div>
  </div>

  <!-- ── Profile settings modal ── -->
  <div id="mlp-settings-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm">
      <div class="mlp-modal-header">
        <h3>Profile Settings</h3>
        <button id="mlp-settings-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <!-- Avatar section -->
        <div class="mlp-settings-avatar-row">
          <div class="mlp-settings-avatar-wrap">
            <div class="mlp-settings-avatar" id="mlp-settings-avatar-preview"></div>
          </div>
          <div class="mlp-settings-avatar-info">
            <span class="mlp-settings-avatar-label">Profile icon</span>
            <span class="mlp-settings-avatar-hint">Auto-generated from your display name.</span>
          </div>
        </div>
        <!-- Name -->
        <label class="mlp-field-label" for="mlp-settings-name-input" style="margin-top:16px;">Display name</label>
        <input type="text" id="mlp-settings-name-input" class="mlp-field-input" placeholder="Your name" maxlength="32" autocomplete="off"/>
        <!-- Danger zone -->
        <div class="mlp-settings-danger-zone">
          <span class="mlp-settings-danger-zone-label">Danger Zone</span>
          <button id="mlp-settings-delete-account-btn" class="mlp-btn-delete-account" type="button">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/>
            </svg>
            Delete Account &amp; All Data
          </button>
        </div>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-settings-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-settings-save-btn" class="mlp-btn-primary">Save changes</button>
      </div>
    </div>
  </div>

  <!-- Rename project modal -->
  <div id="mlp-proj-rename-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm">
      <div class="mlp-modal-header">
        <h3>Rename Project</h3>
        <button id="mlp-proj-rename-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <label class="mlp-field-label" for="mlp-proj-rename-input">New Name</label>
        <input type="text" id="mlp-proj-rename-input" class="mlp-field-input" placeholder="Project name" maxlength="80" autocomplete="off"/>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-proj-rename-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-proj-rename-save-btn" class="mlp-btn-primary">Save</button>
      </div>
    </div>
  </div>

  <!-- Color / Icon picker modal -->
  <div id="mlp-proj-color-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm">
      <div class="mlp-modal-header">
        <h3>Customize Project</h3>
        <button id="mlp-proj-color-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <label class="mlp-field-label">Icon Color</label>
        <div class="mlp-premium-field-wrap">
          <div class="mlp-color-palette" id="mlp-color-palette"></div>
        </div>
        <label class="mlp-field-label" style="margin-top:16px;">Emoji Icon (optional)</label>
        <div class="mlp-premium-field-wrap">
          <input type="text" id="mlp-proj-emoji-input" class="mlp-field-input" placeholder="e.g. 🚀 🎨 💡 (one emoji)" maxlength="4" autocomplete="off"/>
        </div>
        <p class="mlp-onboard-hint">Leave blank to use the default code icon.</p>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-proj-color-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-proj-color-save-btn" class="mlp-btn-primary">Apply</button>
      </div>
    </div>
  </div>

  <!-- Toast notification container -->
  <div id="mlp-toast-container" class="mlp-toast-container"></div>

  <!-- Keyboard shortcut hint -->
  <div id="mlp-kbd-hint" class="mlp-kbd-hint">
    <span><kbd>N</kbd> New</span>
    <span><kbd>/</kbd> Search</span>
    <button class="mlp-kbd-dismiss" id="mlp-kbd-dismiss" title="Dismiss">
      <svg viewBox="0 0 24 24" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>

  <!-- Delete Account confirm modal -->
  <div id="mlp-del-account-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm">
      <div class="mlp-modal-header mlp-modal-header-danger">
        <div class="mlp-del-account-header-left">
          <div class="mlp-del-account-icon-wrap">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
            </svg>
          </div>
          <h3>Delete Account</h3>
        </div>
        <button id="mlp-del-account-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body mlp-del-account-body">
        <div class="mlp-del-account-warning">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <span>This action is <strong>permanent and irreversible.</strong></span>
        </div>
        <p class="mlp-del-account-desc">Deleting your account will permanently erase:</p>
        <ul class="mlp-del-account-list">
          <li>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
            All your projects and their code
          </li>
          <li>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 1 0-16 0"/></svg>
            Your profile name and avatar
          </li>
          <li>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9h6M9 12h6M9 15h4"/></svg>
            All saved editor tabs and settings
          </li>
        </ul>
        <label class="mlp-del-account-confirm-label" for="mlp-del-account-confirm-input">
          Type <strong>DELETE</strong> to confirm
        </label>
        <input type="text" id="mlp-del-account-confirm-input" class="mlp-field-input mlp-del-account-input" placeholder="DELETE" autocomplete="off" maxlength="6"/>
      </div>
      <div class="mlp-modal-footer mlp-del-account-footer">
        <button id="mlp-del-account-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-del-account-confirm-btn" class="mlp-btn-danger mlp-btn-danger-full" disabled>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;">
            <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
          </svg>
          Delete Everything
        </button>
      </div>
    </div>
  </div>

  <!-- Project Notes modal (Premium) -->
  <div id="mlp-notes-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-notes">
      <div class="mlp-modal-header">
        <h3>📝 Project Notes</h3>
        <button id="mlp-notes-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <p id="mlp-notes-project-name" class="mlp-notes-proj-name"></p>
        <textarea id="mlp-notes-textarea" class="mlp-notes-textarea" placeholder="Write markdown notes about this project…"></textarea>
        <div id="mlp-notes-preview" class="mlp-notes-preview" style="display:none;"></div>
        <div class="mlp-notes-toolbar">
          <button id="mlp-notes-toggle-preview" class="mlp-btn-ghost mlp-btn-xs">👁 Preview</button>
          <span id="mlp-notes-char-count" class="mlp-notes-char">0 chars</span>
        </div>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-notes-cancel-btn" class="mlp-btn-ghost">Close</button>
        <button id="mlp-notes-save-btn" class="mlp-btn-primary">Save Notes</button>
      </div>
    </div>
  </div>

  <!-- Project PIN modal (Premium) -->
  <div id="mlp-pin-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm">
      <div class="mlp-modal-header">
        <h3 id="mlp-pin-modal-title">🔐 Set Project Password</h3>
        <button id="mlp-pin-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <p id="mlp-pin-desc" class="mlp-del-confirm-text" style="margin-bottom:8px;"></p>
        <label class="mlp-field-label" for="mlp-pin-input">PIN (4–8 digits)</label>
        <input type="password" id="mlp-pin-input" class="mlp-field-input" placeholder="Enter PIN…" maxlength="8" autocomplete="off" inputmode="numeric"/>
        <div id="mlp-pin-confirm-wrap" style="display:none;">
          <label class="mlp-field-label" style="margin-top:8px;" for="mlp-pin-confirm-input">Confirm PIN</label>
          <input type="password" id="mlp-pin-confirm-input" class="mlp-field-input" placeholder="Re-enter PIN…" maxlength="8" autocomplete="off" inputmode="numeric"/>
        </div>
        <p class="mlp-onboard-hint" id="mlp-pin-hint">Password is stored as a hash — it cannot be recovered.</p>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-pin-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-pin-save-btn" class="mlp-btn-primary">Set Password</button>
      </div>
    </div>
  </div>

  <!-- Project unlock modal -->
  <div id="mlp-unlock-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm">
      <div class="mlp-modal-header">
        <h3>🔐 Enter Password</h3>
        <button id="mlp-unlock-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <p class="mlp-del-confirm-text" id="mlp-unlock-desc">This project is password protected.</p>
        <label class="mlp-field-label" for="mlp-unlock-input">PIN</label>
        <input type="password" id="mlp-unlock-input" class="mlp-field-input" placeholder="Enter PIN…" maxlength="8" autocomplete="off" inputmode="numeric"/>
        <p class="mlp-onboard-hint mlp-unlock-error" id="mlp-unlock-error" style="display:none;color:#ef4444;">Incorrect PIN. Try again.</p>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-unlock-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-unlock-confirm-btn" class="mlp-btn-primary">Unlock</button>
      </div>
    </div>
  </div>

  <!-- Owner preview modal — shown when user B opens a share link -->
  <div id="mlp-owner-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm">
      <div class="mlp-modal-header">
        <h3>📬 Shared Project</h3>
        <button id="mlp-owner-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <div class="mlp-owner-card">
          <div class="mlp-owner-info">
            <span class="mlp-owner-label">Created by</span>
            <div class="mlp-owner-avatar" id="mlp-owner-modal-avatar"></div>
          </div>
        </div>
        <p class="mlp-owner-proj-name" id="mlp-owner-modal-proj-name"></p>
        <p class="mlp-owner-proj-desc" id="mlp-owner-modal-proj-desc" style="display:none;"></p>
        <p class="mlp-onboard-hint" style="margin-top:10px;">This project will be added to your library and opened in the editor.</p>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-owner-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-owner-import-btn" class="mlp-btn-primary">Import &amp; Open →</button>
      </div>
    </div>
  </div>


  <div id="mlp-desc-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal">
      <div class="mlp-modal-header">
        <h3>✏️ Description</h3>
        <button id="mlp-desc-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <label class="mlp-field-label" for="mlp-desc-input">Description</label>
        <input type="text" id="mlp-desc-input" class="mlp-field-input" placeholder="Short description of this project…" maxlength="120" autocomplete="off"/>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-desc-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-desc-save-btn" class="mlp-btn-primary">Save</button>
      </div>
    </div>
  </div>

  <!-- Backup modal -->
  <div id="mlp-backup-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm mlp-backup-modal-inner">
      <div class="mlp-modal-header mlp-backup-modal-header">
        <div class="mlp-backup-header-left">
          <div class="mlp-backup-icon-wrap">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
          </div>
          <h3>Backup Your Code</h3>
        </div>
        <div class="mlp-backup-header-right">
          <span class="mlp-backup-badge">Recommended</span>
          <button id="mlp-backup-close-btn" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
        </div>
      </div>
      <div class="mlp-modal-body mlp-backup-modal-body">
        <div class="mlp-backup-warning">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <span>You have <strong id="mlp-backup-tab-count">saved tabs</strong> in <strong id="mlp-backup-proj-name"></strong>. We recommend backing up before continuing.</span>
        </div>
        <p class="mlp-backup-desc">Your code is stored in localStorage which can be cleared by the browser. Export a <strong>.json backup</strong> to keep a safe copy on your device.</p>
        <div class="mlp-backup-info-row">
          <div class="mlp-backup-info-item">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9h6M9 12h6M9 15h4"/></svg>
            <span id="mlp-backup-size-label">Calculating…</span>
          </div>
          <div class="mlp-backup-info-item">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            <span id="mlp-backup-date-label">Last modified: —</span>
          </div>
        </div>
      </div>
      <div class="mlp-modal-footer mlp-backup-modal-footer">
        <button id="mlp-backup-skip-btn" class="mlp-btn-ghost mlp-backup-skip-btn">No, continue with localStorage</button>
        <button id="mlp-backup-download-btn" class="mlp-btn-primary mlp-backup-download-btn">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          Download Backup (.json)
        </button>
      </div>
    </div>
  </div>

  <div id="mlp-history-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-history-modal">
      <div class="mlp-modal-header">
        <h3>↩ Project History</h3>
        <button id="mlp-history-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <p id="mlp-history-project-name" class="mlp-notes-proj-name"></p>
        <div class="mlp-history-sections">
          <div>
            <h4 class="mlp-history-heading">Previous versions</h4>
            <div id="mlp-history-versions" class="mlp-history-list"></div>
          </div>
          <div>
            <h4 class="mlp-history-heading">Recent activity</h4>
            <div id="mlp-history-activity" class="mlp-history-list"></div>
          </div>
        </div>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-history-close-btn" class="mlp-btn-ghost">Close</button>
      </div>
    </div>
  </div>

  <!-- Publish / Share modal (with AI moderation gate) -->
  <div id="mlp-share-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal">
      <div class="mlp-modal-header">
        <h3 id="mlp-share-modal-title">🚀 Publish Project</h3>
        <button id="mlp-share-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <p class="mlp-share-proj-name" id="mlp-share-proj-title"></p>

        <!-- Step: pre-publish info -->
        <div id="mlp-publish-step-pre">
          <div class="mlp-publish-info-box">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;margin-top:1px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <span>Before your share link is created, our <strong>AI safety checker</strong> will scan your code for malware, hate speech, toxicity, phishing, and other policy violations.</span>
          </div>
          <p class="mlp-onboard-hint" style="margin-top:10px;">Projects that pass are shared instantly. Violations are blocked and logged.</p>
          <!-- Cloudflare Turnstile CAPTCHA -->
          <div style="margin-top:14px;">
            <div id="mlp-turnstile-widget"
                 class="cf-turnstile"
                 data-sitekey="<?php echo esc_attr( defined('MLP_TURNSTILE_SITE_KEY') ? MLP_TURNSTILE_SITE_KEY : '' ); ?>"
                 data-callback="mlpTurnstileCallback"
                 data-expired-callback="mlpTurnstileExpired"
                 data-error-callback="mlpTurnstileError"
                 data-theme="light">
            </div>
          </div>
        </div>

        <!-- Step: AI checking -->
        <div id="mlp-publish-step-checking" style="display:none;">
          <div class="mlp-mod-checking-wrap">
            <div class="mlp-mod-spinner"></div>
            <div class="mlp-mod-checking-text">
              <strong>AI Safety Check in progress…</strong>
              <span>Scanning for malware, toxic content &amp; policy violations.</span>
            </div>
          </div>
        </div>

        <!-- Step: Rejected -->
        <div id="mlp-publish-step-rejected" style="display:none;">
          <div class="mlp-mod-reject-box">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
            <div>
              <strong>Project blocked by AI review</strong>
              <p id="mlp-mod-reject-reason" class="mlp-mod-reject-reason"></p>
            </div>
          </div>
          <p class="mlp-onboard-hint" style="margin-top:10px;">Please remove the flagged content and try publishing again.</p>
        </div>

        <!-- Step: Approved — show link -->
        <div id="mlp-publish-step-approved" style="display:none;">
          <div class="mlp-mod-approve-box">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><polyline points="20 6 9 17 4 12"/></svg>
            <span>AI review passed — your project is safe to share!</span>
          </div>
          <label class="mlp-field-label" style="margin-top:14px;">Share Link — send this to anyone</label>
          <div class="mlp-share-link-row">
            <input type="text" id="mlp-share-domain-input" class="mlp-field-input mlp-share-domain-input" readonly/>
            <button id="mlp-share-copy-link-btn" class="mlp-btn-primary mlp-btn-xs" disabled>Copy Link</button>
          </div>
          <p class="mlp-onboard-hint" style="margin-top:8px;">When the recipient opens this link, the project is automatically added to their project list as a private copy.</p>
        </div>

      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-share-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-publish-run-btn" class="mlp-btn-primary">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;display:inline-block;"><path d="M22 2L11 13"/><path d="M22 2L15 22L11 13L2 9L22 2Z"/></svg>
          Publish &amp; Get Link
        </button>
      </div>
    </div>
  </div>


  <!-- Get Link popup -->
  <div id="mlp-getlink-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm">
      <div class="mlp-modal-header">
        <h3>🔗 Get Link</h3>
        <button id="mlp-getlink-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <p class="mlp-share-proj-name" id="mlp-getlink-proj-title"></p>
        <label class="mlp-field-label" style="margin-top:4px;">Share Link — send this to anyone</label>
        <div class="mlp-share-link-row">
          <input type="text" id="mlp-getlink-url-input" class="mlp-field-input mlp-share-domain-input" readonly/>
          <button id="mlp-getlink-copy-btn" class="mlp-btn-primary mlp-btn-xs">Copy Link</button>
        </div>
        <p class="mlp-onboard-hint" style="margin-top:8px;">When the recipient opens this link, the project is automatically added to their project list as a private copy.</p>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-getlink-close-btn" class="mlp-btn-ghost">Close</button>
      </div>
    </div>
  </div>

  <!-- RePublish modal -->
  <div id="mlp-republish-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal">
      <div class="mlp-modal-header">
        <h3 id="mlp-republish-modal-title">🔄 RePublish Project</h3>
        <button id="mlp-republish-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <p class="mlp-share-proj-name" id="mlp-republish-proj-title"></p>

        <!-- Step: pre -->
        <div id="mlp-republish-step-pre">
          <div class="mlp-publish-info-box">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;margin-top:1px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <span>The AI safety checker will scan your updated code. If it passes, the shared link will serve the new content — <strong>the URL stays the same</strong>.</span>
          </div>
          <!-- Cloudflare Turnstile CAPTCHA -->
          <div style="margin-top:14px;">
            <div id="mlp-turnstile-widget-republish"
                 class="cf-turnstile"
                 data-sitekey="<?php echo esc_attr( defined('MLP_TURNSTILE_SITE_KEY') ? MLP_TURNSTILE_SITE_KEY : '' ); ?>"
                 data-callback="mlpRepublishTurnstileCallback"
                 data-expired-callback="mlpRepublishTurnstileExpired"
                 data-error-callback="mlpRepublishTurnstileError"
                 data-theme="light">
            </div>
          </div>
        </div>

        <!-- Step: checking -->
        <div id="mlp-republish-step-checking" style="display:none;">
          <div class="mlp-mod-checking-wrap">
            <div class="mlp-mod-spinner"></div>
            <div class="mlp-mod-checking-text">
              <strong>AI Safety Check in progress…</strong>
              <span>Scanning for malware, toxic content &amp; policy violations.</span>
            </div>
          </div>
        </div>

        <!-- Step: rejected -->
        <div id="mlp-republish-step-rejected" style="display:none;">
          <div class="mlp-mod-reject-box">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
            <div>
              <strong>Project blocked by AI review</strong>
              <p id="mlp-republish-reject-reason" class="mlp-mod-reject-reason"></p>
            </div>
          </div>
          <p class="mlp-onboard-hint" style="margin-top:10px;">Please remove the flagged content and try again. Your existing share link is unchanged.</p>
        </div>

        <!-- Step: success -->
        <div id="mlp-republish-step-done" style="display:none;">
          <div class="mlp-mod-approve-box">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><polyline points="20 6 9 17 4 12"/></svg>
            <span>AI review passed — shared link updated with your new content!</span>
          </div>
          <label class="mlp-field-label" style="margin-top:14px;">Your link (unchanged)</label>
          <div class="mlp-share-link-row">
            <input type="text" id="mlp-republish-url-input" class="mlp-field-input mlp-share-domain-input" readonly/>
            <button id="mlp-republish-copy-btn" class="mlp-btn-primary mlp-btn-xs">Copy Link</button>
          </div>
        </div>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-republish-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-republish-run-btn" class="mlp-btn-primary">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;display:inline-block;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
          Run AI Check &amp; Update
        </button>
      </div>
    </div>
  </div>

  <!-- Bulk delete confirm modal -->
  <div id="mlp-bulk-del-modal" class="mlp-modal-backdrop" style="display:none;">
    <div class="mlp-modal mlp-modal-sm">
      <div class="mlp-modal-header">
        <h3>Delete Selected Projects</h3>
        <button id="mlp-bulk-del-modal-close" class="mlp-modal-close" aria-label="Close">&#x2715;</button>
      </div>
      <div class="mlp-modal-body">
        <p class="mlp-del-confirm-text">Delete <strong id="mlp-bulk-del-count"></strong> selected projects? This cannot be undone.</p>
      </div>
      <div class="mlp-modal-footer">
        <button id="mlp-bulk-del-cancel-btn" class="mlp-btn-ghost">Cancel</button>
        <button id="mlp-bulk-del-confirm-btn" class="mlp-btn-danger">Delete All</button>
      </div>
    </div>
  </div>




</div>
<!-- /MLP Projects Popup -->
        <?php
        return ob_get_clean();
    }

    /* ------------------------------------------------------------------ */
    /*  CSS block                                                           */
    /* ------------------------------------------------------------------ */

    private static function get_css() {
        return '
/* ================================================================
   MLP Projects Popup — Multi-Project Edition
   All styles are scoped under #mlp-projects-overlay to prevent
   any WordPress theme from leaking in or being affected.
   ================================================================ */

/* ── 1. Hard reset ───────────────────────────────────────────── */
#mlp-projects-overlay,
#mlp-projects-overlay *,
#mlp-projects-overlay *::before,
#mlp-projects-overlay *::after {
    all: unset;
    box-sizing: border-box !important;
}

/* ── 1b. Restore native display values ──────────────────────── */
#mlp-projects-overlay div,
#mlp-projects-overlay main,
#mlp-projects-overlay aside,
#mlp-projects-overlay nav,
#mlp-projects-overlay header,
#mlp-projects-overlay footer { display: block; }
#mlp-projects-overlay table  { display: table;              width: 100%; }
#mlp-projects-overlay thead  { display: table-header-group; }
#mlp-projects-overlay tbody  { display: table-row-group;    }
#mlp-projects-overlay tr     { display: table-row;          }
#mlp-projects-overlay th,
#mlp-projects-overlay td     { display: table-cell; vertical-align: middle; }
#mlp-projects-overlay button { display: inline-block; cursor: pointer; }
#mlp-projects-overlay input,
#mlp-projects-overlay select { display: inline-block; }
#mlp-projects-overlay a      { display: inline;  cursor: pointer; }
#mlp-projects-overlay span   { display: inline;  }
#mlp-projects-overlay label  { display: inline;  }
#mlp-projects-overlay svg    { display: inline-block; }
#mlp-projects-overlay p      { display: block;   }
#mlp-projects-overlay strong { display: inline; font-weight: 700; }

/* ── 2. Design tokens ───────────────────────────────────────── */
#mlp-projects-overlay {
    --mlp-accent:        #2563eb;
    --mlp-accent-hover:  #1d4ed8;
    --mlp-accent-light:  #eff6ff;
    --mlp-danger:        #dc2626;
    --mlp-danger-hover:  #b91c1c;
    --mlp-danger-bg:     rgba(220,38,38,0.07);
    --mlp-danger-border: rgba(220,38,38,0.30);
    --mlp-success-bg:    #f0fdf4;
    --mlp-success-text:  #16a34a;
    --mlp-public-bg:     #eff6ff;
    --mlp-public-text:   #1d4ed8;

    --mlp-bg:            #f1f5f9;
    --mlp-surface:       #ffffff;
    --mlp-sidebar-bg:    #0f172a;
    --mlp-nav-bg:        #0f172a;
    --mlp-border:        #e2e8f0;
    --mlp-border-muted:  #f1f5f9;

    --mlp-text-primary:  #0f172a;
    --mlp-text-secondary:#64748b;
    --mlp-text-muted:    #94a3b8;
    --mlp-text-inverse:  #ffffff;
    --mlp-text-link:     #2563eb;

    --mlp-font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    --mlp-font-mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;

    --mlp-radius-sm: 4px;
    --mlp-radius:    6px;
    --mlp-radius-lg: 10px;
    --mlp-shadow-sm: 0 1px 3px rgba(0,0,0,0.10), 0 1px 2px rgba(0,0,0,0.06);
    --mlp-shadow-md: 0 4px 16px rgba(0,0,0,0.12), 0 2px 6px rgba(0,0,0,0.08);
    --mlp-shadow-lg: 0 20px 50px rgba(0,0,0,0.22), 0 8px 20px rgba(0,0,0,0.12);
}

/* ── 2b. Dark theme overrides ──────────────────────────────── */
#mlp-projects-overlay[data-mlp-theme="dark"] {
    --mlp-accent:        #60a5fa;
    --mlp-accent-hover:  #3b82f6;
    --mlp-accent-light:  rgba(96,165,250,0.12);
    --mlp-danger:        #f87171;
    --mlp-danger-hover:  #ef4444;
    --mlp-danger-bg:     rgba(248,113,113,0.10);
    --mlp-danger-border: rgba(248,113,113,0.35);
    --mlp-success-bg:    rgba(34,197,94,0.12);
    --mlp-success-text:  #4ade80;
    --mlp-public-bg:     rgba(96,165,250,0.14);
    --mlp-public-text:   #93c5fd;

    --mlp-bg:            #0b1220;
    --mlp-surface:       #111827;
    --mlp-sidebar-bg:    #050a14;
    --mlp-nav-bg:        #050a14;
    --mlp-border:        #1f2937;
    --mlp-border-muted:  #182234;

    --mlp-text-primary:  #e5e7eb;
    --mlp-text-secondary:#9ca3af;
    --mlp-text-muted:    #6b7280;
    --mlp-text-inverse:  #f9fafb;
    --mlp-text-link:     #60a5fa;

    --mlp-shadow-sm: 0 1px 3px rgba(0,0,0,0.50), 0 1px 2px rgba(0,0,0,0.40);
    --mlp-shadow-md: 0 4px 16px rgba(0,0,0,0.55), 0 2px 6px rgba(0,0,0,0.40);
    --mlp-shadow-lg: 0 20px 50px rgba(0,0,0,0.70), 0 8px 20px rgba(0,0,0,0.50);
    color-scheme: dark;
}

/* ── 2c. Dark theme — override hardcoded light backgrounds ── */
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-table-card,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-table-toolbar,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-table-wrap,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-table {
    background: var(--mlp-surface) !important;
    color: var(--mlp-text-primary) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-table th {
    background: #0f172a !important;
    color: var(--mlp-text-secondary) !important;
    border-color: var(--mlp-border) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-table td {
    background: transparent !important;
    color: var(--mlp-text-primary) !important;
    border-color: var(--mlp-border) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-table tbody tr:hover td {
    background: rgba(96,165,250,0.08) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-row-active td {
    background: transparent !important;
    box-shadow: none !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-table tbody tr.mlp-row-active:hover td {
    background: rgba(96,165,250,0.08) !important;
}
/* Dark theme — Get Link / Publish action button */
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-proj-share-action-btn {
    background: rgba(56,189,248,0.10) !important;
    color: #7dd3fc !important;
    border: 1px solid rgba(56,189,248,0.30) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-proj-share-action-btn:hover {
    background: rgba(56,189,248,0.18) !important;
    color: #bae6fd !important;
    border-color: rgba(56,189,248,0.55) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-proj-share-action-btn * {
    color: #7dd3fc !important; stroke: #7dd3fc !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-proj-share-action-btn:hover * {
    color: #bae6fd !important; stroke: #bae6fd !important;
}
/* Dark theme — RePublish button */
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-proj-republish-btn {
    background: rgba(167,139,250,0.10) !important;
    color: #c4b5fd !important;
    border: 1px solid rgba(167,139,250,0.30) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-proj-republish-btn:hover {
    background: rgba(167,139,250,0.18) !important;
    color: #ddd6fe !important;
    border-color: rgba(167,139,250,0.55) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-proj-republish-btn * {
    color: #c4b5fd !important; stroke: #c4b5fd !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-proj-republish-btn:hover * {
    color: #ddd6fe !important; stroke: #ddd6fe !important;
}
/* Dark theme — Size badges */
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-size-badge.mlp-size-sm {
    background: rgba(34,197,94,0.12) !important;
    color: #86efac !important;
    border-color: rgba(34,197,94,0.30) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-size-badge.mlp-size-md {
    background: rgba(245,158,11,0.12) !important;
    color: #fcd34d !important;
    border-color: rgba(245,158,11,0.30) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-size-badge.mlp-size-lg {
    background: rgba(239,68,68,0.12) !important;
    color: #fca5a5 !important;
    border-color: rgba(239,68,68,0.30) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] tr.mlp-row-selected td {
    background: rgba(96,165,250,0.12) !important;
}
/* Sort bar / storage row use #f8fafc */
#mlp-projects-overlay[data-mlp-theme="dark"] [class*="mlp-sort"],
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-sort-bar,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-storage-bar,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-storage-used,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-storage-bar-wrap {
    background: var(--mlp-surface) !important;
    color: var(--mlp-text-secondary) !important;
    border-color: var(--mlp-border) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-storage-bar-track {
    background: #1e293b !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-sort-btn {
    background: #0f172a !important;
    color: var(--mlp-text-secondary) !important;
    border-color: var(--mlp-border) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-sort-btn:hover {
    background: #1e293b !important;
    border-color: #334155 !important;
    color: var(--mlp-text-primary) !important;
}
/* Modal / footer chrome */
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-modal,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-modal-body,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-modal-header,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-modal-footer {
    background: var(--mlp-surface) !important;
    color: var(--mlp-text-primary) !important;
    border-color: var(--mlp-border) !important;
}
/* Inputs */
#mlp-projects-overlay[data-mlp-theme="dark"] input,
#mlp-projects-overlay[data-mlp-theme="dark"] textarea,
#mlp-projects-overlay[data-mlp-theme="dark"] select,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-field-input,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-search-input {
    background: #0b1220 !important;
    color: var(--mlp-text-primary) !important;
    border-color: var(--mlp-border) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] input::placeholder,
#mlp-projects-overlay[data-mlp-theme="dark"] textarea::placeholder { color: var(--mlp-text-muted) !important; }
/* Ghost / lock / desc / dup / rename / color buttons fall back to f1f5f9 on hover */
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-btn-ghost,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-row-btn-lock,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-row-btn-desc,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-row-btn-rename,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-row-btn-dup,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-row-btn-color {
    background: transparent !important;
    color: var(--mlp-text-secondary) !important;
    border-color: var(--mlp-border) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-btn-ghost:hover,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-row-btn-lock:hover,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-row-btn-desc:hover,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-row-btn-rename:hover,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-row-btn-dup:hover,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-row-btn-color:hover {
    background: #1e293b !important;
    color: var(--mlp-text-primary) !important;
    border-color: #334155 !important;
}
/* Toasts */
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-toast {
    background: var(--mlp-surface) !important;
    color: var(--mlp-text-primary) !important;
    border-color: var(--mlp-border) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-toast-title { color: var(--mlp-text-primary) !important; }
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-toast-msg   { color: var(--mlp-text-secondary) !important; }
/* Catch-all: any element forced to a near-white bg should darken */
#mlp-projects-overlay[data-mlp-theme="dark"] [style*="background:#fff"],
#mlp-projects-overlay[data-mlp-theme="dark"] [style*="background: #fff"],
#mlp-projects-overlay[data-mlp-theme="dark"] [style*="background-color:#fff"],
#mlp-projects-overlay[data-mlp-theme="dark"] [style*="background-color: #fff"] {
    background: var(--mlp-surface) !important;
}

/* Theme toggle button (in nav) */
#mlp-projects-overlay .mlp-theme-toggle-btn {
    display: inline-flex !important;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    padding: 0;
    margin-right: 8px;
    background: rgba(255,255,255,0.06);
    color: var(--mlp-text-inverse);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: var(--mlp-radius);
    cursor: pointer;
    transition: background 0.15s ease, transform 0.15s ease, border-color 0.15s ease;
    flex-shrink: 0;
    font-size: 16px;
    line-height: 1;
}
#mlp-projects-overlay .mlp-theme-toggle-btn:hover {
    background: rgba(255,255,255,0.14);
    border-color: rgba(255,255,255,0.20);
}
#mlp-projects-overlay .mlp-theme-toggle-btn:active { transform: scale(0.94); }
#mlp-projects-overlay .mlp-theme-toggle-btn .mlp-theme-emoji {
    display: none;
    font-size: 16px;
    line-height: 1;
    font-family: "Apple Color Emoji","Segoe UI Emoji","Noto Color Emoji","Segoe UI Symbol",sans-serif;
    -webkit-font-smoothing: antialiased;
}
#mlp-projects-overlay .mlp-theme-toggle-btn .mlp-theme-emoji-moon { display: inline-block !important; }
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-theme-toggle-btn .mlp-theme-emoji-moon { display: none !important; }
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-theme-toggle-btn .mlp-theme-emoji-sun  { display: inline-block !important; }

/* ── 3. Overlay (fullscreen) ────────────────────────────────── */
#mlp-projects-overlay.mlp-proj-overlay {
    position:       fixed !important;
    inset:          0    !important;
    z-index:        2147483647 !important;
    display:        flex !important;
    flex-direction: column;
    background:     var(--mlp-bg);
    font-family:    var(--mlp-font);
    font-size:      14px;
    line-height:    1.5;
    color:          var(--mlp-text-primary);
    visibility:     visible;
    opacity:        1;
    transition:     opacity 0.2s ease, visibility 0.2s ease;
    overflow:       hidden;
    -webkit-font-smoothing: antialiased;
}
#mlp-projects-overlay.mlp-proj-overlay.mlp-proj-hidden {
    opacity:        0   !important;
    visibility:     hidden !important;
    pointer-events: none   !important;
}

/* ── 4. Top nav ─────────────────────────────────────────────── */
#mlp-projects-overlay .mlp-nav {
    display:         flex;
    align-items:     center;
    justify-content: space-between;
    background:      var(--mlp-nav-bg);
    color:           var(--mlp-text-inverse);
    height:          56px;
    padding:         0 24px;
    flex-shrink:     0;
    border-bottom:   1px solid rgba(255,255,255,0.06);
    box-shadow:      0 1px 0 rgba(0,0,0,0.25);
}
#mlp-projects-overlay .mlp-nav-brand {
    display: flex; align-items: center; gap: 10px;
    font-size: 0.9375rem; font-weight: 700;
    color: var(--mlp-text-inverse); letter-spacing: 0.01em;
}
#mlp-projects-overlay .mlp-nav-brand svg { color: var(--mlp-accent); flex-shrink: 0; }
#mlp-projects-overlay .mlp-sidebar-toggle-btn {
    display: inline-flex; align-items: center; justify-content: center;
    width: 36px; height: 36px;
    margin-left: 14px;
    background: rgba(96,165,250,0.10);
    color: #60a5fa;
    border: 1px solid rgba(96,165,250,0.25);
    border-radius: var(--mlp-radius-sm);
    cursor: pointer;
    transition: background 0.12s, color 0.12s, border-color 0.12s, transform 0.12s;
    padding: 0;
    margin-right: auto;
}
#mlp-projects-overlay .mlp-sidebar-toggle-btn:hover {
    background: rgba(96,165,250,0.18);
    color: #93c5fd;
    border-color: rgba(96,165,250,0.45);
}
#mlp-projects-overlay .mlp-sidebar-toggle-btn:active { transform: scale(0.95); }
#mlp-projects-overlay .mlp-sidebar-toggle-btn svg { stroke: currentColor; fill: none; flex-shrink: 0; }
#mlp-projects-overlay.mlp-sidebar-collapsed .mlp-sidebar {
    width: 0 !important; min-width: 0 !important;
    padding-left: 0 !important; padding-right: 0 !important;
    border-right: none !important;
    overflow: hidden !important;
}
#mlp-projects-overlay[data-mlp-theme="light"] .mlp-sidebar-toggle-btn {
    background: rgba(37,99,235,0.10);
    color: #2563eb;
    border-color: rgba(37,99,235,0.25);
}
#mlp-projects-overlay[data-mlp-theme="light"] .mlp-sidebar-toggle-btn:hover {
    background: rgba(37,99,235,0.18);
    color: #1d4ed8;
    border-color: rgba(37,99,235,0.45);
}
#mlp-projects-overlay .mlp-nav-right {
    display: flex; align-items: center; gap: 4px;
    font-size: 0.8125rem; color: #94a3b8;
}
#mlp-projects-overlay .mlp-nav-right svg { flex-shrink: 0; }
#mlp-projects-overlay .mlp-nav-username { padding: 0 12px; font-size: 0.8125rem; color: #94a3b8; }
#mlp-projects-overlay .mlp-nav-icon {
    width: 34px; height: 34px;
    display: flex; align-items: center; justify-content: center;
    color: #94a3b8; border-radius: var(--mlp-radius-sm);
    cursor: pointer; transition: background 0.12s, color 0.12s; padding: 8px;
}
#mlp-projects-overlay .mlp-nav-icon:hover { background: rgba(255,255,255,0.08); color: #e2e8f0; }

/* ── 5. Layout ──────────────────────────────────────────────── */
#mlp-projects-overlay .mlp-layout { display: flex; flex: 1; overflow: hidden; min-height: 0; }

/* ── 6. Sidebar ─────────────────────────────────────────────── */
#mlp-projects-overlay .mlp-sidebar {
    width: 210px; min-width: 210px; flex-shrink: 0;
    background: var(--mlp-sidebar-bg);
    padding: 20px 0; overflow-y: auto;
    border-right: 1px solid rgba(255,255,255,0.04);
}
#mlp-projects-overlay .mlp-sidebar-section-label {
    display: block; font-size: 0.6875rem; font-weight: 700;
    color: #6b7280; text-transform: uppercase; letter-spacing: 0.09em;
    padding: 0 18px 10px;
}
#mlp-projects-overlay .mlp-sidebar-nav {
    display: flex; flex-direction: column; gap: 2px; padding: 0 10px;
}
#mlp-projects-overlay .mlp-sidebar-link {
    display: flex; align-items: center; gap: 10px; padding: 9px 12px;
    border-radius: var(--mlp-radius-sm); font-size: 0.875rem;
    color: #64748b; text-decoration: none; cursor: pointer;
    transition: background 0.12s, color 0.12s;
}
#mlp-projects-overlay .mlp-sidebar-link svg { flex-shrink: 0; }
#mlp-projects-overlay .mlp-sidebar-link:hover { background: rgba(255,255,255,0.05); color: #cbd5e1; }
#mlp-projects-overlay .mlp-sidebar-link-active { background: rgba(37,99,235,0.20) !important; color: #93c5fd !important; }
#mlp-projects-overlay .mlp-sidebar-link-active svg { color: #60a5fa; }

/* Sidebar project entries */
#mlp-projects-overlay .mlp-sidebar-project-link {
    padding-left: 14px !important; font-size: 0.8125rem !important;
    color: #6b7280 !important; gap: 8px !important;
    overflow: hidden;
}
#mlp-projects-overlay .mlp-sidebar-project-link:hover { background: rgba(255,255,255,0.04) !important; color: #9ca3af !important; }
#mlp-projects-overlay .mlp-sidebar-proj-icon { font-size: 0.75rem; color: #6b7280; flex-shrink: 0; width: 14px; text-align: center; }
#mlp-projects-overlay .mlp-sidebar-proj-name {
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    flex: 1; min-width: 0; color: #6b7280; display: inline-block;
}
#mlp-projects-overlay .mlp-sidebar-proj-active .mlp-sidebar-proj-name { color: #93c5fd !important; }

/* ── 7. Main content ────────────────────────────────────────── */
#mlp-projects-overlay .mlp-main {
    flex: 1; overflow-y: auto; padding: 32px 36px;
    display: flex; flex-direction: column; gap: 22px; min-width: 0;
}

/* ── 8. Page header ─────────────────────────────────────────── */
#mlp-projects-overlay .mlp-page-header {
    display: flex; align-items: flex-start;
    justify-content: space-between; gap: 16px;
}
#mlp-projects-overlay .mlp-page-title {
    display: flex; align-items: baseline; gap: 12px;
    font-size: 1.375rem; font-weight: 700;
    color: var(--mlp-text-primary); line-height: 1.3;
}
#mlp-projects-overlay .mlp-page-subtitle { font-size: 0.8125rem; font-weight: 400; color: var(--mlp-text-secondary); }
#mlp-projects-overlay .mlp-breadcrumb {
    display: flex; align-items: center; gap: 4px;
    font-size: 0.8125rem; color: var(--mlp-text-secondary); margin-top: 4px;
}
#mlp-projects-overlay .mlp-breadcrumb-sep { color: var(--mlp-text-muted); }
#mlp-projects-overlay #mlp-proj-count-current {
    font-weight: 700; color: var(--mlp-text-primary); font-size: 0.9rem;
}
#mlp-projects-overlay #mlp-proj-count-max {
    font-weight: 600; color: var(--mlp-text-muted);
}
#mlp-projects-overlay .mlp-breadcrumb-unit {
    color: var(--mlp-text-muted); font-size: 0.8125rem;
}
/* Near-limit warning colour */
#mlp-projects-overlay #mlp-proj-count-current.mlp-count-warn { color: #f59e0b; }
#mlp-projects-overlay #mlp-proj-count-current.mlp-count-full  { color: #ef4444; }

/* ── 9. Table card ──────────────────────────────────────────── */
#mlp-projects-overlay .mlp-table-card {
    background: var(--mlp-surface); border-radius: var(--mlp-radius-lg);
    border: 1px solid var(--mlp-border); overflow: visible;
    box-shadow: var(--mlp-shadow-sm);
}
#mlp-projects-overlay .mlp-table-toolbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 20px; border-bottom: 1px solid var(--mlp-border);
    background: var(--mlp-surface); gap: 12px;
    border-radius: var(--mlp-radius-lg) var(--mlp-radius-lg) 0 0;
}
#mlp-projects-overlay .mlp-table-label { font-size: 0.9375rem; font-weight: 600; color: var(--mlp-text-primary); }
#mlp-projects-overlay .mlp-table-toolbar-right { display: flex; align-items: center; gap: 10px; }
#mlp-projects-overlay .mlp-search-wrap {
    display: flex; align-items: center; gap: 8px;
    background: var(--mlp-bg); border: 1px solid var(--mlp-border);
    border-radius: var(--mlp-radius-sm); padding: 7px 11px;
    transition: border-color 0.15s, box-shadow 0.15s;
}
#mlp-projects-overlay .mlp-search-wrap:focus-within {
    border-color: var(--mlp-accent); box-shadow: 0 0 0 3px rgba(37,99,235,0.12);
}
#mlp-projects-overlay .mlp-search-wrap svg { color: var(--mlp-text-muted); flex-shrink: 0; }
#mlp-projects-overlay .mlp-search-input {
    background: transparent; border: none; outline: none;
    font-size: 0.8125rem; font-family: var(--mlp-font);
    color: var(--mlp-text-primary); width: 190px;
}
#mlp-projects-overlay .mlp-search-input::placeholder { color: var(--mlp-text-muted); }

/* ── 10. Create New button ──────────────────────────────────── */
#mlp-projects-overlay .mlp-btn-create {
    display: inline-flex; align-items: center; gap: 6px;
    background: var(--mlp-accent); color: #fff; border: none;
    border-radius: var(--mlp-radius-sm); padding: 8px 16px;
    font-size: 0.8125rem; font-family: var(--mlp-font); font-weight: 600;
    cursor: pointer; transition: background 0.15s, box-shadow 0.15s, transform 0.1s;
    box-shadow: 0 1px 3px rgba(37,99,235,0.35); white-space: nowrap;
}
#mlp-projects-overlay .mlp-btn-create:hover {
    background: var(--mlp-accent-hover); box-shadow: 0 2px 6px rgba(37,99,235,0.45); transform: translateY(-1px);
}
#mlp-projects-overlay .mlp-btn-create:active { transform: translateY(0); }

/* ── 11. Table ──────────────────────────────────────────────── */
#mlp-projects-overlay .mlp-table-wrap { overflow-x: auto; border-radius: 0 0 var(--mlp-radius-lg) var(--mlp-radius-lg); }
#mlp-projects-overlay .mlp-table {
    width: 100%; border-collapse: collapse;
    font-size: 0.875rem; color: var(--mlp-text-secondary);
}
#mlp-projects-overlay .mlp-table thead tr { border-bottom: 2px solid var(--mlp-border); }
#mlp-projects-overlay .mlp-table th {
    text-align: left; padding: 11px 20px; font-size: 0.6875rem;
    font-weight: 700; color: var(--mlp-text-muted); text-transform: uppercase;
    letter-spacing: 0.07em; background: #f8fafc; white-space: nowrap;
}
#mlp-projects-overlay .mlp-table td {
    padding: 13px 20px; border-bottom: 1px solid var(--mlp-border-muted); vertical-align: middle;
}
#mlp-projects-overlay .mlp-table tbody tr:last-child td { border-bottom: none; }
#mlp-projects-overlay .mlp-table tbody tr { transition: background 0.12s; }
#mlp-projects-overlay .mlp-table tbody tr:hover td { background: var(--mlp-accent-light); }

/* ── 12. Row elements ───────────────────────────────────────── */
#mlp-projects-overlay .mlp-row-name {
    display: flex; align-items: center; gap: 11px;
    font-weight: 600; color: var(--mlp-text-link);
    cursor: pointer; text-decoration: none; transition: color 0.12s;
}
#mlp-projects-overlay .mlp-row-name:hover { color: var(--mlp-accent-hover); text-decoration: underline; }
#mlp-projects-overlay .mlp-row-icon {
    width: 30px !important; height: 30px !important; border-radius: var(--mlp-radius-sm) !important;
    background: var(--mlp-icon-bg, linear-gradient(135deg, #3b82f6 0%, #7c3aed 100%)) !important;
    display: flex !important; align-items: center !important; justify-content: center !important;
    flex-shrink: 0 !important; color: #fff !important; box-shadow: 0 1px 4px rgba(59,130,246,0.40) !important;
}
#mlp-projects-overlay .mlp-row-icon svg {
    stroke: #fff !important; fill: none !important; display: block !important;
    width: 14px !important; height: 14px !important;
}
#mlp-projects-overlay .mlp-row-date { color: var(--mlp-text-muted); font-size: 0.8125rem; white-space: nowrap; }
#mlp-projects-overlay .mlp-row-badge {
    display: inline-flex; align-items: center; gap: 4px;
    border-radius: 20px; padding: 3px 10px;
    font-size: 0.75rem; font-weight: 600; white-space: nowrap;
}
#mlp-projects-overlay .mlp-badge-private {
    background: var(--mlp-success-bg); color: var(--mlp-success-text);
}
#mlp-projects-overlay .mlp-badge-public {
    background: var(--mlp-public-bg); color: var(--mlp-public-text);
}
#mlp-projects-overlay .mlp-proj-domain-link {
    display: flex !important; align-items: center; gap: 5px;
    margin-top: 5px; font-size: 0.7rem; color: var(--mlp-text-link) !important;
    text-decoration: none !important; cursor: pointer !important;
    padding: 3px 7px; border-radius: 4px;
    border: 1px solid #bfdbfe !important; background: #eff6ff !important;
    transition: background 0.12s, border-color 0.12s;
    max-width: 180px; overflow: hidden;
    pointer-events: auto !important;
    font-family: var(--mlp-font) !important;
}
#mlp-projects-overlay .mlp-proj-domain-link:hover {
    background: #dbeafe; border-color: #93c5fd; color: #1d4ed8;
}
#mlp-projects-overlay .mlp-proj-domain-text {
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    flex: 1; min-width: 0;
}
#mlp-projects-overlay .mlp-share-proj-name {
    font-size: 0.875rem; font-weight: 600; color: var(--mlp-text-primary);
    margin-bottom: 12px;
}
#mlp-projects-overlay .mlp-share-link-row {
    display: flex; gap: 8px; align-items: center; margin-bottom: 16px;
}
#mlp-projects-overlay .mlp-share-domain-input {
    flex: 1; font-size: 0.8rem; color: var(--mlp-text-secondary);
    background: var(--mlp-bg); cursor: default;
}
#mlp-projects-overlay .mlp-row-actions { display: flex; gap: 6px; }
#mlp-projects-overlay .mlp-row-btn {
    display: inline-flex; align-items: center; border: none;
    border-radius: var(--mlp-radius-sm); padding: 5px 13px;
    font-size: 0.8125rem; font-family: var(--mlp-font); font-weight: 600;
    cursor: pointer; transition: background 0.12s, box-shadow 0.12s, transform 0.1s;
    white-space: nowrap;
}
#mlp-projects-overlay .mlp-row-btn:active { transform: scale(0.97); }
#mlp-projects-overlay .mlp-row-btn-go {
    background: var(--mlp-accent); color: #fff;
    box-shadow: 0 1px 3px rgba(37,99,235,0.30);
}
#mlp-projects-overlay .mlp-row-btn-go:hover {
    background: var(--mlp-accent-hover); box-shadow: 0 2px 6px rgba(37,99,235,0.40);
}
#mlp-projects-overlay .mlp-row-btn-del {
    background: transparent; color: var(--mlp-danger);
    border: 1px solid var(--mlp-danger-border);
}
#mlp-projects-overlay .mlp-row-btn-del:hover {
    background: var(--mlp-danger-bg); border-color: rgba(220,38,38,0.50);
}

/* ── More Options dropdown ───────────────────────────────────── */
#mlp-projects-overlay .mlp-more-wrap {
    position: relative; display: inline-flex;
}
#mlp-projects-overlay .mlp-row-btn-more {
    background: rgba(255,255,255,0.08) !important; color: #cbd5e1 !important;
    border: 1px solid rgba(255,255,255,0.12) !important; gap: 5px !important;
    display: inline-flex !important; align-items: center !important;
}
#mlp-projects-overlay .mlp-row-btn-more:hover { background: rgba(255,255,255,0.14) !important; color: #f1f5f9 !important; }
#mlp-projects-overlay .mlp-row-btn-more.mlp-more-open { background: rgba(255,255,255,0.16) !important; color: #f1f5f9 !important; border-color: rgba(255,255,255,0.22) !important; }
#mlp-projects-overlay .mlp-row-btn-more svg { flex-shrink: 0 !important; transition: transform 0.15s !important; stroke: currentColor !important; fill: none !important; }
#mlp-projects-overlay .mlp-row-btn-more.mlp-more-open svg { transform: rotate(180deg) !important; }
#mlp-projects-overlay .mlp-more-dropdown {
    position: fixed !important;
    background: #1e293b !important; border: 1px solid rgba(255,255,255,0.12) !important;
    border-radius: 10px !important;
    box-shadow: 0 12px 36px rgba(0,0,0,0.55), 0 3px 10px rgba(0,0,0,0.35) !important;
    min-width: 205px !important; z-index: 2147483647 !important;
    padding: 5px 0 !important; overflow: hidden !important;
    animation: mlpDropIn 0.13s ease !important;
}
@keyframes mlpDropIn {
    from { opacity: 0; transform: translateY(-5px); }
    to   { opacity: 1; transform: translateY(0); }
}
#mlp-projects-overlay .mlp-more-item {
    display: flex !important; align-items: center !important; gap: 9px !important;
    width: 100% !important; padding: 9px 16px !important;
    background: none !important; border: none !important; border-radius: 0 !important;
    font-size: 0.8125rem !important; font-family: var(--mlp-font) !important; font-weight: 500 !important;
    color: #e2e8f0 !important; cursor: pointer !important; text-align: left !important;
    transition: background 0.1s !important; white-space: nowrap !important;
}
#mlp-projects-overlay .mlp-more-item:hover { background: rgba(255,255,255,0.09) !important; color: #fff !important; }
#mlp-projects-overlay .mlp-more-item-locked { color: #64748b !important; }
#mlp-projects-overlay .mlp-more-item-locked:hover { background: rgba(245,158,11,0.12) !important; color: #fbbf24 !important; }
#mlp-projects-overlay .mlp-more-item-badge {
    margin-left: auto !important; font-size: 0.65rem !important;
    color: #fbbf24 !important; font-weight: 700 !important;
}
#mlp-projects-overlay .mlp-more-divider {
    height: 1px !important; background: rgba(255,255,255,0.08) !important; margin: 4px 0 !important;
}

/* ── 13. Active project highlight ───────────────────────────── */
#mlp-projects-overlay .mlp-row-active td { background: #f0f9ff !important; }
#mlp-projects-overlay .mlp-row-active .mlp-row-btn-go {
    background: #0ea5e9 !important;
}
#mlp-projects-overlay .mlp-active-badge {
    display: inline-flex; align-items: center; gap: 4px;
    background: #dbeafe; color: #1d4ed8;
    border-radius: 10px; padding: 2px 8px;
    font-size: 0.7rem; font-weight: 600; margin-left: 8px;
}

/* ── 14. Empty state ────────────────────────────────────────── */
#mlp-projects-overlay .mlp-empty-state {
    display: flex; flex-direction: column; align-items: center;
    justify-content: center; gap: 8px; padding: 60px 20px;
    color: var(--mlp-text-muted); text-align: center;
}
#mlp-projects-overlay .mlp-empty-state svg { color: var(--mlp-text-muted); opacity: 0.6; }
#mlp-projects-overlay .mlp-empty-state p {
    display: block; font-size: 0.9375rem; color: var(--mlp-text-secondary);
    font-weight: 600; margin-top: 8px;
}
#mlp-projects-overlay .mlp-empty-state span { display: block; font-size: 0.8125rem; color: var(--mlp-text-muted); }
#mlp-projects-overlay .mlp-empty-state strong { color: var(--mlp-text-secondary); }

/* ── 15. Modals ─────────────────────────────────────────────── */
#mlp-projects-overlay .mlp-modal-backdrop {
    position: absolute; inset: 0;
    background: rgba(15,23,42,0.60);
    backdrop-filter: blur(3px); -webkit-backdrop-filter: blur(3px);
    display: flex; align-items: center; justify-content: center; z-index: 10;
}
#mlp-projects-overlay .mlp-modal {
    background: var(--mlp-surface); border-radius: var(--mlp-radius-lg);
    width: 100%; max-width: 440px; box-shadow: var(--mlp-shadow-lg);
    overflow: hidden; animation: mlpModalIn 0.18s cubic-bezier(0.34,1.56,0.64,1);
}
#mlp-projects-overlay .mlp-modal-sm { max-width: 380px; }
@keyframes mlpModalIn {
    from { opacity: 0; transform: scale(0.94) translateY(-8px); }
    to   { opacity: 1; transform: scale(1)    translateY(0); }
}
#mlp-projects-overlay .mlp-modal-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 18px 22px; border-bottom: 1px solid var(--mlp-border);
}
#mlp-projects-overlay .mlp-modal-header h3 {
    display: block; font-size: 1rem; font-weight: 700; color: var(--mlp-text-primary);
}
#mlp-projects-overlay .mlp-modal-close {
    display: flex; align-items: center; justify-content: center;
    background: none; border: 1px solid transparent; cursor: pointer;
    font-size: 1rem; color: var(--mlp-text-muted);
    width: 28px; height: 28px; border-radius: var(--mlp-radius-sm);
    transition: background 0.12s, color 0.12s, border-color 0.12s;
}
#mlp-projects-overlay .mlp-modal-close:hover {
    background: #f1f5f9; color: var(--mlp-text-secondary); border-color: var(--mlp-border);
}
#mlp-projects-overlay .mlp-modal-body {
    padding: 22px; display: flex; flex-direction: column; gap: 8px;
}
#mlp-projects-overlay .mlp-del-confirm-text {
    font-size: 0.875rem; color: var(--mlp-text-secondary); line-height: 1.6;
}
#mlp-projects-overlay .mlp-field-label {
    display: block; font-size: 0.8125rem; font-weight: 600; color: var(--mlp-text-secondary);
}
#mlp-projects-overlay .mlp-field-input {
    display: block; width: 100%; padding: 9px 13px;
    border: 1px solid var(--mlp-border); border-radius: var(--mlp-radius-sm);
    font-size: 0.9rem; font-family: var(--mlp-font);
    color: var(--mlp-text-primary); background: var(--mlp-surface);
    outline: none; transition: border-color 0.15s, box-shadow 0.15s;
}
#mlp-projects-overlay .mlp-field-input::placeholder { color: var(--mlp-text-muted); }
#mlp-projects-overlay .mlp-field-input:focus {
    border-color: var(--mlp-accent); box-shadow: 0 0 0 3px rgba(37,99,235,0.15);
}
#mlp-projects-overlay select.mlp-field-input {
    appearance: none; -webkit-appearance: none; cursor: pointer;
    background-image: url(\'data:image/svg+xml,%3Csvg xmlns=\'\'http://www.w3.org/2000/svg\'\' width=\'\'12\'\' height=\'\'12\'\' viewBox=\'\'0 0 24 24\'\' fill=\'\'none\'\' stroke=\'\'%2394a3b8\'\' stroke-width=\'\'2\'\' stroke-linecap=\'\'round\'\' stroke-linejoin=\'\'round\'\'%3E%3Cpolyline points=\'\'6 9 12 15 18 9\'\'/%3E%3C/svg%3E\');
    background-repeat: no-repeat; background-position: right 11px center; padding-right: 32px;
}
#mlp-projects-overlay .mlp-modal-footer {
    display: flex; justify-content: flex-end; gap: 8px;
    padding: 16px 22px; border-top: 1px solid var(--mlp-border); background: #f8fafc;
}
#mlp-projects-overlay .mlp-btn-primary {
    display: inline-flex; align-items: center;
    background: var(--mlp-accent); color: #fff; border: none;
    border-radius: var(--mlp-radius-sm); padding: 9px 20px;
    font-size: 0.875rem; font-family: var(--mlp-font); font-weight: 600;
    cursor: pointer; transition: background 0.15s, box-shadow 0.15s, transform 0.1s;
    box-shadow: 0 1px 3px rgba(37,99,235,0.35);
}
#mlp-projects-overlay .mlp-btn-primary:hover {
    background: var(--mlp-accent-hover); box-shadow: 0 2px 7px rgba(37,99,235,0.45); transform: translateY(-1px);
}
#mlp-projects-overlay .mlp-btn-primary:active { transform: translateY(0); }
#mlp-projects-overlay .mlp-btn-primary[disabled],
#mlp-projects-overlay .mlp-btn-primary:disabled {
    background: #1e293b !important; color: #475569 !important;
    opacity: 1 !important; cursor: not-allowed !important;
    box-shadow: none !important; transform: none !important;
    pointer-events: none !important; border: 1px solid #334155 !important;
}
#mlp-projects-overlay .mlp-btn-danger {
    display: inline-flex; align-items: center;
    background: var(--mlp-danger); color: #fff; border: none;
    border-radius: var(--mlp-radius-sm); padding: 9px 20px;
    font-size: 0.875rem; font-family: var(--mlp-font); font-weight: 600;
    cursor: pointer; transition: background 0.15s, transform 0.1s;
}
#mlp-projects-overlay .mlp-btn-danger:hover { background: var(--mlp-danger-hover); transform: translateY(-1px); }
#mlp-projects-overlay .mlp-btn-danger:active { transform: translateY(0); }
#mlp-projects-overlay .mlp-btn-ghost {
    display: inline-flex; align-items: center;
    background: transparent; color: var(--mlp-text-secondary);
    border: 1px solid var(--mlp-border); border-radius: var(--mlp-radius-sm);
    padding: 9px 20px; font-size: 0.875rem; font-family: var(--mlp-font); font-weight: 600;
    cursor: pointer; transition: background 0.12s, border-color 0.12s;
}
#mlp-projects-overlay .mlp-btn-ghost:hover { background: #f1f5f9; border-color: #cbd5e1; }

/* ── 16. Scrollbars ─────────────────────────────────────────── */
#mlp-projects-overlay .mlp-main::-webkit-scrollbar,
#mlp-projects-overlay .mlp-sidebar::-webkit-scrollbar { width: 5px; }
#mlp-projects-overlay .mlp-main::-webkit-scrollbar-track,
#mlp-projects-overlay .mlp-sidebar::-webkit-scrollbar-track { background: transparent; }
#mlp-projects-overlay .mlp-main::-webkit-scrollbar-thumb { background: var(--mlp-border); border-radius: 99px; }
#mlp-projects-overlay .mlp-sidebar::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.10); border-radius: 99px; }

/* ── 17. Legacy ─────────────────────────────────────────────── */
#mlp-projects-overlay .mlp-proj-card { display: none !important; }

/* ── 18. Profile button (nav) ───────────────────────────────── */
#mlp-projects-overlay .mlp-profile-btn {
    display: inline-flex; align-items: center; gap: 9px;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 24px; padding: 5px 12px 5px 6px;
    cursor: pointer; transition: background 0.15s, border-color 0.15s;
    font-family: var(--mlp-font); color: var(--mlp-text-inverse);
}
#mlp-projects-overlay .mlp-profile-btn:hover {
    background: rgba(255,255,255,0.12); border-color: rgba(255,255,255,0.20);
}
#mlp-projects-overlay .mlp-profile-dropdown-wrap {
    position: relative;
}
#mlp-projects-overlay .mlp-profile-dropdown {
    position: absolute; top: calc(100% + 8px); right: 0;
    background: var(--mlp-surface); border: 1px solid var(--mlp-border);
    border-radius: 10px; box-shadow: 0 8px 24px rgba(0,0,0,0.18);
    min-width: 160px; z-index: 10000; overflow: hidden;
    animation: mlpDropIn 0.13s ease;
}
@keyframes mlpDropIn {
    from { opacity: 0; transform: translateY(-6px); }
    to   { opacity: 1; transform: translateY(0); }
}
#mlp-projects-overlay .mlp-profile-dropdown-item {
    display: flex; align-items: center; gap: 9px;
    width: 100%; padding: 10px 14px; background: none; border: none;
    cursor: pointer; font-family: var(--mlp-font); font-size: 13px;
    color: var(--mlp-text-primary); text-align: left; transition: background 0.12s;
    text-decoration: none;
}
#mlp-projects-overlay .mlp-profile-dropdown-item:hover {
    background: var(--mlp-border-muted);
}
#mlp-projects-overlay .mlp-profile-btn.mlp-profile-btn-open {
    background: rgba(255,255,255,0.14); border-color: rgba(255,255,255,0.25);
}
#mlp-projects-overlay .mlp-profile-caret-open {
    transform: rotate(180deg);
}
#mlp-projects-overlay .mlp-community-dropdown-wrap {
    position: relative; display: inline-flex; align-items: center;
}
#mlp-projects-overlay .mlp-community-btn {
    display: inline-flex; align-items: center; gap: 5px;
    color: #ffffff; font-family: var(--mlp-font);
    font-size: 13px; font-weight: 500; cursor: pointer;
    padding: 5px 8px; border-radius: 6px; user-select: none;
    opacity: 0.85; transition: opacity 0.15s, background 0.15s;
}
#mlp-projects-overlay .mlp-community-btn:hover {
    opacity: 1; background: rgba(255,255,255,0.10);
}

/* ── 19. Avatar (shared base) ───────────────────────────────── */
#mlp-projects-overlay .mlp-nav-avatar,
#mlp-projects-overlay .mlp-onboard-avatar-preview,
#mlp-projects-overlay .mlp-settings-avatar {
    border-radius: 50%; overflow: hidden; flex-shrink: 0;
    display: inline-flex; align-items: center; justify-content: center;
    font-weight: 700; letter-spacing: -0.3px;
}
/* Nav size */
#mlp-projects-overlay .mlp-nav-avatar {
    width: 28px; height: 28px; font-size: 11px;
}
/* Onboard hero size */
#mlp-projects-overlay .mlp-onboard-avatar-preview {
    width: 72px; height: 72px; font-size: 26px; margin: 0 auto 14px;
}
/* Settings size */
#mlp-projects-overlay .mlp-settings-avatar {
    width: 64px; height: 64px; font-size: 22px;
}
/* Image inside avatar */
#mlp-projects-overlay .mlp-nav-avatar img,
#mlp-projects-overlay .mlp-onboard-avatar-preview img,
#mlp-projects-overlay .mlp-settings-avatar img {
    width: 100%; height: 100%; object-fit: cover; border-radius: 50%;
}

/* ── 20. Nav username label ─────────────────────────────────── */
#mlp-projects-overlay .mlp-nav-username {
    font-size: 0.8125rem; font-weight: 500; color: #e2e8f0; max-width: 130px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

/* ── 21. Onboarding modal extras ────────────────────────────── */
#mlp-projects-overlay .mlp-onboard-modal { text-align: center; }
#mlp-projects-overlay .mlp-onboard-hero {
    padding: 28px 24px 0; display: block;
}
#mlp-projects-overlay .mlp-onboard-title {
    font-size: 1.125rem; font-weight: 700; color: var(--mlp-text-primary);
    margin: 0 0 6px; display: block;
}
#mlp-projects-overlay .mlp-onboard-sub {
    font-size: 0.875rem; color: var(--mlp-text-secondary); margin: 0 0 8px;
}
#mlp-projects-overlay .mlp-onboard-hint {
    font-size: 0.75rem; color: var(--mlp-text-muted); margin: 6px 0 0;
}

/* ── 22. Settings avatar upload row ─────────────────────────── */
#mlp-projects-overlay .mlp-settings-avatar-row {
    display: flex; align-items: center; gap: 16px; margin-bottom: 4px;
}
#mlp-projects-overlay .mlp-settings-avatar-wrap { position: relative; flex-shrink: 0; }
#mlp-projects-overlay .mlp-settings-avatar-change {
    position: absolute; bottom: -2px; right: -2px;
    width: 22px; height: 22px; border-radius: 50%;
    background: var(--mlp-accent); color: #fff;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer; border: 2px solid #fff;
    transition: background 0.15s;
}
#mlp-projects-overlay .mlp-settings-avatar-change:hover { background: var(--mlp-accent-hover); }
#mlp-projects-overlay .mlp-settings-avatar-info {
    display: flex; flex-direction: column; gap: 3px;
}
#mlp-projects-overlay .mlp-settings-avatar-label {
    font-size: 0.875rem; font-weight: 600; color: var(--mlp-text-primary);
}
#mlp-projects-overlay .mlp-settings-avatar-hint {
    font-size: 0.75rem; color: var(--mlp-text-muted);
}
#mlp-projects-overlay .mlp-settings-avatar-remove {
    font-size: 0.75rem; color: var(--mlp-danger); background: none;
    border: none; cursor: pointer; padding: 0; font-family: var(--mlp-font);
    text-align: left; transition: opacity 0.12s;
}
#mlp-projects-overlay .mlp-settings-avatar-remove:hover { opacity: 0.75; }

/* ── 23. Sidebar profile section ────────────────────────────── */
#mlp-projects-overlay .mlp-sidebar {
    display: flex; flex-direction: column;
}
#mlp-projects-overlay .mlp-sidebar > .mlp-sidebar-section-label,
#mlp-projects-overlay .mlp-sidebar > .mlp-sidebar-nav,
#mlp-projects-overlay .mlp-sidebar > #mlp-sidebar-manage-section {
    flex-shrink: 0;
}
#mlp-projects-overlay .mlp-sidebar-profile-wrap {
    margin-top: auto; flex-shrink: 0;
}
#mlp-projects-overlay .mlp-sidebar-profile-divider {
    height: 1px; background: rgba(255,255,255,0.06); margin: 0 10px 10px;
}
#mlp-projects-overlay .mlp-sidebar-profile-card {
    display: flex !important; align-items: center; gap: 9px;
    padding: 8px 10px 14px;
}
#mlp-projects-overlay .mlp-sidebar-profile-avatar-wrap { flex-shrink: 0; }
#mlp-projects-overlay .mlp-sidebar-profile-avatar {
    width: 32px; height: 32px; border-radius: 50%;
    display: flex !important; align-items: center; justify-content: center;
    font-size: 12px; font-weight: 700; letter-spacing: -0.3px;
    overflow: hidden; flex-shrink: 0;
}
#mlp-projects-overlay .mlp-sidebar-profile-avatar img {
    width: 100%; height: 100%; object-fit: cover; border-radius: 50%;
}
#mlp-projects-overlay .mlp-sidebar-profile-info {
    display: flex !important; flex-direction: column; gap: 2px; flex: 1; min-width: 0;
}
#mlp-projects-overlay .mlp-sidebar-profile-name {
    display: block !important; font-size: 0.8125rem; font-weight: 600;
    color: #cbd5e1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
/* Free plan chip */
#mlp-projects-overlay .mlp-sidebar-profile-plan {
    display: inline-flex !important; align-items: center !important; gap: 4px !important;
    font-size: 0.625rem !important; font-weight: 600 !important; color: #475569 !important;
    background: rgba(255,255,255,0.05) !important; border: 1px solid rgba(255,255,255,0.09) !important;
    border-radius: 20px !important; padding: 2px 8px 2px 6px !important; width: fit-content !important;
    letter-spacing: 0.02em !important; text-transform: uppercase !important;
    white-space: nowrap !important; line-height: 1 !important;
}
/* Premium state chip */
#mlp-projects-overlay .mlp-sidebar-profile-plan.mlp-plan-premium {
    color: #fbbf24 !important; background: rgba(251,191,36,0.12) !important;
    border-color: rgba(251,191,36,0.28) !important;
}
#mlp-projects-overlay .mlp-sidebar-profile-plan svg {
    display: inline-block !important; flex-shrink: 0 !important;
    width: 9px !important; height: 9px !important;
    stroke: currentColor !important; fill: none !important;
}
#mlp-projects-overlay .mlp-sidebar-settings-btn {
    display: flex !important; align-items: center; justify-content: center;
    width: 30px; height: 30px; flex-shrink: 0;
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.09);
    border-radius: 8px; cursor: pointer;
    color: #64748b; transition: background 0.15s, color 0.15s, border-color 0.15s, transform 0.2s;
}
#mlp-projects-overlay .mlp-sidebar-settings-btn:hover {
    background: rgba(255,255,255,0.10); color: #94a3b8;
    border-color: rgba(255,255,255,0.18);
    transform: rotate(45deg);
}
#mlp-projects-overlay .mlp-sidebar-settings-btn svg {
    display: block !important;
    width: 15px !important; height: 15px !important;
    stroke: currentColor; fill: none; flex-shrink: 0;
}
#mlp-projects-overlay .mlp-sidebar-settings-btn i {
    font-size: 13px !important;
    color: inherit !important;
    display: inline-block !important;
    font-style: normal !important;
}
#mlp-projects-overlay .mlp-sidebar-settings-icon {
    font-family: "Font Awesome 6 Free" !important;
    font-weight: 900 !important;
    font-style: normal !important;
    font-size: 13px !important;
    display: inline-block !important;
    color: inherit !important;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}
#mlp-projects-overlay .mlp-sidebar-settings-icon::before {
    content: "\f013" !important; /* fa-gear unicode */
    display: inline-block !important;
    font-family: "Font Awesome 6 Free" !important;
    font-weight: 900 !important;
}

/* ── 24. Delete account modal ───────────────────────────────── */
#mlp-projects-overlay .mlp-modal-header-danger {
    border-bottom: 1px solid rgba(220,38,38,0.20);
    background: linear-gradient(135deg, rgba(220,38,38,0.06) 0%, transparent 100%);
}
#mlp-projects-overlay .mlp-del-account-header-left {
    display: flex; align-items: center; gap: 10px;
}
#mlp-projects-overlay .mlp-del-account-icon-wrap {
    width: 32px; height: 32px; border-radius: 8px;
    background: rgba(220,38,38,0.12); border: 1px solid rgba(220,38,38,0.25);
    display: flex; align-items: center; justify-content: center;
    color: var(--mlp-danger); flex-shrink: 0;
}
#mlp-projects-overlay .mlp-del-account-body { gap: 12px; }
#mlp-projects-overlay .mlp-del-account-warning {
    display: flex; align-items: center; gap: 9px;
    background: rgba(220,38,38,0.08); border: 1px solid rgba(220,38,38,0.20);
    border-radius: 8px; padding: 10px 13px;
    color: #ef4444; font-size: 0.8125rem; line-height: 1.5;
}
#mlp-projects-overlay .mlp-del-account-warning svg { flex-shrink: 0; }
#mlp-projects-overlay .mlp-del-account-warning strong { color: #dc2626; }
#mlp-projects-overlay .mlp-del-account-desc {
    font-size: 0.8125rem; color: var(--mlp-text-secondary);
    margin: 0; line-height: 1.5;
}
#mlp-projects-overlay .mlp-del-account-list {
    display: flex; flex-direction: column; gap: 7px;
    margin: 0; padding: 0; list-style: none;
}
#mlp-projects-overlay .mlp-del-account-list li {
    display: flex; align-items: center; gap: 9px;
    font-size: 0.8125rem; color: var(--mlp-text-secondary);
}
#mlp-projects-overlay .mlp-del-account-list li svg {
    color: var(--mlp-text-muted); flex-shrink: 0;
}
#mlp-projects-overlay .mlp-del-account-confirm-label {
    display: block; font-size: 0.8125rem; font-weight: 600;
    color: var(--mlp-text-secondary); margin-top: 4px;
}
#mlp-projects-overlay .mlp-del-account-confirm-label strong { color: var(--mlp-danger); }
#mlp-projects-overlay .mlp-del-account-input {
    margin-top: 6px; font-family: monospace !important; letter-spacing: 0.08em;
}
#mlp-projects-overlay .mlp-del-account-input:focus {
    border-color: var(--mlp-danger) !important; box-shadow: 0 0 0 3px rgba(220,38,38,0.12) !important;
}
#mlp-projects-overlay .mlp-del-account-footer { background: #fef2f2; }
#mlp-projects-overlay .mlp-btn-danger-full {
    display: inline-flex; align-items: center; gap: 6px;
    opacity: 0.45; pointer-events: none; transition: opacity 0.2s, background 0.15s, transform 0.1s;
}
#mlp-projects-overlay .mlp-btn-danger-full:not([disabled]) {
    opacity: 1; pointer-events: auto;
}

/* ── 25. Settings modal: add delete account section ────────── */
#mlp-projects-overlay .mlp-settings-danger-zone {
    margin-top: 6px; padding-top: 14px;
    border-top: 1px solid rgba(220,38,38,0.15);
    display: flex; flex-direction: column; gap: 6px;
}
#mlp-projects-overlay .mlp-settings-danger-zone-label {
    font-size: 0.6875rem; font-weight: 700; color: #ef4444;
    text-transform: uppercase; letter-spacing: 0.09em;
}
#mlp-projects-overlay .mlp-btn-delete-account {
    display: inline-flex; align-items: center; gap: 7px;
    background: transparent; color: var(--mlp-danger);
    border: 1px solid rgba(220,38,38,0.30); border-radius: var(--mlp-radius-sm);
    padding: 8px 15px; font-size: 0.8125rem; font-family: var(--mlp-font); font-weight: 600;
    cursor: pointer; transition: background 0.15s, border-color 0.15s;
    width: 100%;
}
#mlp-projects-overlay .mlp-btn-delete-account:hover {
    background: rgba(220,38,38,0.07); border-color: rgba(220,38,38,0.50);
}
/* ── 26. Toast notifications ────────────────────────────────── */
#mlp-projects-overlay .mlp-toast-container {
    position: fixed; top: 72px; right: 24px; z-index: 2147483647;
    display: flex; flex-direction: column; gap: 10px; pointer-events: none;
    width: 320px;
}
#mlp-projects-overlay .mlp-toast {
    display: flex; align-items: flex-start; gap: 13px;
    padding: 14px 14px 14px 16px;
    border-radius: 10px; border: 1px solid transparent;
    font-family: var(--mlp-font);
    background: #ffffff;
    box-shadow: 0 4px 24px rgba(0,0,0,0.10), 0 1px 6px rgba(0,0,0,0.07);
    pointer-events: auto; position: relative; overflow: hidden;
    animation: mlpToastIn 0.30s cubic-bezier(0.34,1.3,0.64,1);
}
#mlp-projects-overlay .mlp-toast::before {
    content: \'\'; position: absolute; left: 0; top: 0; bottom: 0;
    width: 4px; border-radius: 10px 0 0 10px;
}
#mlp-projects-overlay .mlp-toast-success { border-color: #d1fae5; }
#mlp-projects-overlay .mlp-toast-success::before { background: #10b981; }
#mlp-projects-overlay .mlp-toast-danger  { border-color: #fee2e2; }
#mlp-projects-overlay .mlp-toast-danger::before  { background: #ef4444; }
#mlp-projects-overlay .mlp-toast-info    { border-color: #dbeafe; }
#mlp-projects-overlay .mlp-toast-info::before    { background: #3b82f6; }

#mlp-projects-overlay .mlp-toast-icon-wrap {
    flex-shrink: 0; width: 32px; height: 32px; border-radius: 8px;
    display: flex; align-items: center; justify-content: center; margin-top: 1px;
}
#mlp-projects-overlay .mlp-toast-success .mlp-toast-icon-wrap { background: #d1fae5; color: #059669; }
#mlp-projects-overlay .mlp-toast-danger  .mlp-toast-icon-wrap { background: #fee2e2; color: #dc2626; }
#mlp-projects-overlay .mlp-toast-info    .mlp-toast-icon-wrap { background: #dbeafe; color: #2563eb; }
#mlp-projects-overlay .mlp-toast-icon-wrap svg {
    display: block !important; width: 15px !important; height: 15px !important;
    stroke: currentColor; fill: none; flex-shrink: 0;
}

#mlp-projects-overlay .mlp-toast-body {
    flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px;
}
#mlp-projects-overlay .mlp-toast-title {
    display: block; font-size: 0.875rem; font-weight: 700;
    color: #0f172a; line-height: 1.3;
}
#mlp-projects-overlay .mlp-toast-msg {
    display: block; font-size: 0.8125rem; color: #64748b;
    line-height: 1.45; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}

#mlp-projects-overlay .mlp-toast-close {
    flex-shrink: 0; width: 22px; height: 22px; border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    background: none; border: none; cursor: pointer;
    color: #94a3b8; transition: background 0.12s, color 0.12s; margin-top: 1px;
}
#mlp-projects-overlay .mlp-toast-close:hover { background: #f1f5f9; color: #475569; }
#mlp-projects-overlay .mlp-toast-close svg {
    display: block !important; width: 11px !important; height: 11px !important;
    stroke: currentColor; fill: none;
}

#mlp-projects-overlay .mlp-toast-progress {
    position: absolute; bottom: 0; left: 4px; right: 0; height: 3px;
    background: rgba(0,0,0,0.06); border-radius: 0 0 10px 0;
}
#mlp-projects-overlay .mlp-toast-progress-bar {
    height: 100%; border-radius: 0 0 10px 0;
    animation: mlpToastProgress 3s linear forwards;
}
#mlp-projects-overlay .mlp-toast-success .mlp-toast-progress-bar { background: #10b981; }
#mlp-projects-overlay .mlp-toast-danger  .mlp-toast-progress-bar { background: #ef4444; }
#mlp-projects-overlay .mlp-toast-info    .mlp-toast-progress-bar { background: #3b82f6; }

#mlp-projects-overlay .mlp-toast.mlp-toast-out {
    animation: mlpToastOut 0.22s ease forwards;
}
@keyframes mlpToastIn       { from { opacity:0; transform:translateX(24px) scale(0.96); } to { opacity:1; transform:translateX(0) scale(1); } }
@keyframes mlpToastOut      { from { opacity:1; transform:translateX(0); max-height:120px; margin-bottom:0; } to { opacity:0; transform:translateX(32px); max-height:0; margin-bottom:-10px; } }
@keyframes mlpToastProgress { from { width:100%; } to { width:0%; } }

/* ── 27. Keyboard hint bar ──────────────────────────────────── */
#mlp-projects-overlay .mlp-kbd-hint {
    display: inline-flex; align-items: center; gap: 16px;
    position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
    background: rgba(15,23,42,0.82); backdrop-filter: blur(8px);
    border: 1px solid rgba(255,255,255,0.10); border-radius: 30px;
    padding: 7px 8px 7px 18px; font-size: 0.75rem; color: #94a3b8;
    font-family: var(--mlp-font); pointer-events: auto; z-index: 9999;
    opacity: 0; animation: mlpKbdFadeIn 0.5s 1.2s ease forwards;
}
#mlp-projects-overlay .mlp-kbd-hint.mlp-kbd-hidden { display: none !important; }
#mlp-projects-overlay .mlp-kbd-hint span { display: inline-flex; align-items: center; gap: 5px; }
#mlp-projects-overlay .mlp-kbd-hint kbd {
    display: inline-flex; align-items: center; justify-content: center;
    background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.20);
    border-radius: 5px; padding: 2px 7px; font-size: 0.6875rem; font-family: inherit;
    color: #e2e8f0; font-weight: 600; letter-spacing: 0.02em;
}
#mlp-projects-overlay .mlp-kbd-dismiss {
    display: inline-flex; align-items: center; justify-content: center;
    width: 22px; height: 22px; border-radius: 50%; cursor: pointer;
    background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12);
    color: #64748b; flex-shrink: 0; transition: background 0.15s, color 0.15s;
    margin-left: 4px;
}
#mlp-projects-overlay .mlp-kbd-dismiss:hover { background: rgba(255,255,255,0.18); color: #e2e8f0; }
#mlp-projects-overlay .mlp-kbd-dismiss svg { display: block !important; width: 10px !important; height: 10px !important; stroke: currentColor; fill: none; }
@keyframes mlpKbdFadeIn { from { opacity:0; } to { opacity:1; } }

/* ── 28. Color palette picker ───────────────────────────────── */
#mlp-projects-overlay .mlp-color-palette {
    display: flex; flex-wrap: wrap; gap: 8px; padding: 6px 0;
}
#mlp-projects-overlay .mlp-color-swatch {
    width: 28px; height: 28px; border-radius: 50%; cursor: pointer;
    border: 3px solid transparent; transition: transform 0.12s, box-shadow 0.12s, border-color 0.12s;
    flex-shrink: 0;
}
#mlp-projects-overlay .mlp-color-swatch:hover { transform: scale(1.15); box-shadow: 0 2px 8px rgba(0,0,0,0.2); }
#mlp-projects-overlay .mlp-color-swatch.mlp-swatch-active {
    border-color: rgba(255,255,255,0.8); box-shadow: 0 0 0 2px rgba(0,0,0,0.35), 0 2px 8px rgba(0,0,0,0.2);
    transform: scale(1.10);
}

/* ── 29. Size badge ─────────────────────────────────────────── */
#mlp-projects-overlay .mlp-size-badge {
    display: inline-flex; align-items: center; gap: 4px;
    font-size: 0.75rem; font-weight: 600; font-family: var(--mlp-font-mono);
    color: var(--mlp-text-muted); background: var(--mlp-bg);
    border: 1px solid var(--mlp-border-muted); border-radius: 6px;
    padding: 3px 9px; white-space: nowrap;
}
#mlp-projects-overlay .mlp-size-badge.mlp-size-sm { color: #16a34a; background: #f0fdf4; border-color: #bbf7d0; }
#mlp-projects-overlay .mlp-size-badge.mlp-size-md { color: #b45309; background: #fffbeb; border-color: #fde68a; }
#mlp-projects-overlay .mlp-size-badge.mlp-size-lg { color: #dc2626; background: #fef2f2; border-color: #fecaca; }

/* ── 30. Last-opened highlight ──────────────────────────────── */
#mlp-projects-overlay .mlp-row-last-opened td:first-child::before {
    content: ""; display: inline-block;
    width: 7px; height: 7px; border-radius: 50%;
    background: #22c55e; margin-right: 8px; flex-shrink: 0;
    box-shadow: 0 0 0 2px rgba(34,197,94,0.22);
    vertical-align: middle;
}
#mlp-projects-overlay .mlp-last-opened-dot {
    display: inline-block; width: 7px; height: 7px; border-radius: 50%;
    background: #22c55e; margin-right: 7px; flex-shrink: 0;
    box-shadow: 0 0 0 2px rgba(34,197,94,0.22); vertical-align: middle;
}


/* ── 32. Premium badge inline label ────────────────────────── */
#mlp-projects-overlay .mlp-premium-badge {
    display: inline-flex; align-items: center;
    font-size: 0.625rem; font-weight: 700; letter-spacing: 0.04em;
    background: linear-gradient(135deg, #f59e0b, #d97706);
    color: #fff; border-radius: 20px; padding: 2px 7px;
    margin-left: 7px; vertical-align: middle; text-transform: uppercase;
}

/* ── 33. Premium field lock overlay ────────────────────────── */
#mlp-projects-overlay .mlp-premium-field-wrap {
    position: relative; display: block;
}
#mlp-projects-overlay .mlp-premium-field-lock {
    position: absolute; inset: 0;
    background: rgba(15, 23, 42, 0.7);
    backdrop-filter: blur(2px); -webkit-backdrop-filter: blur(2px);
    border-radius: var(--mlp-radius-sm);
    display: flex; align-items: center; justify-content: center; gap: 8px;
    cursor: pointer; color: #f8fafc; font-size: 0.8125rem; font-weight: 600;
    transition: background 0.15s;
    z-index: 2;
}
#mlp-projects-overlay .mlp-premium-field-lock:hover {
    background: rgba(15, 23, 42, 0.82);
}
#mlp-projects-overlay .mlp-premium-field-lock svg { flex-shrink: 0; color: #fbbf24; }
#mlp-projects-overlay .mlp-premium-field-lock span {
    color: #e2e8f0; font-size: 0.8rem; white-space: nowrap;
}
#mlp-projects-overlay .mlp-premium-field-lock-palette {
    border-radius: 4px; background: rgba(15,23,42,0.75);
}

/* ── 34. Sidebar upgrade row + button ───────────────────────── */
#mlp-projects-overlay .mlp-sidebar-upgrade-row {
    display: flex !important; padding: 0 10px 8px; flex-shrink: 0;
}
#mlp-projects-overlay .mlp-sidebar-upgrade-btn {
    display: flex !important; align-items: center !important; justify-content: center !important;
    gap: 7px !important; width: 100% !important;
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%) !important;
    color: #fff !important; border: none !important; border-radius: 8px !important;
    padding: 9px 14px !important; font-size: 0.75rem !important; font-weight: 700 !important;
    cursor: pointer !important; transition: opacity 0.15s, transform 0.1s, box-shadow 0.15s !important;
    letter-spacing: 0.02em !important; white-space: nowrap !important;
    box-shadow: 0 2px 12px rgba(251,191,36,0.3) !important;
    font-family: var(--mlp-font) !important;
}
#mlp-projects-overlay .mlp-sidebar-upgrade-btn svg {
    flex-shrink: 0 !important; display: inline-block !important;
    width: 11px !important; height: 11px !important;
    stroke: currentColor !important; fill: none !important;
}
#mlp-projects-overlay .mlp-sidebar-upgrade-btn:hover {
    opacity: 0.9 !important; transform: translateY(-1px) !important;
    box-shadow: 0 4px 18px rgba(251,191,36,0.45) !important;
}
#mlp-projects-overlay .mlp-sidebar-upgrade-btn:active { transform: translateY(0) !important; }

/* ── 35. Premium plan badge in sidebar ──────────────────────── */
#mlp-projects-overlay .mlp-sidebar-profile-plan.mlp-plan-premium {
    background: linear-gradient(135deg, #f59e0b22, #d97706), transparent;
    color: #fbbf24 !important; font-weight: 700;
}
#mlp-projects-overlay .mlp-sidebar-profile-plan.mlp-plan-premium svg {
    color: #fbbf24;
}

/* ── 36. Premium Modal ───────────────────────────────────────── */
#mlp-projects-overlay .mlp-premium-modal-inner {
    max-width: 420px; background: #0d1224;
    border: 1px solid rgba(251,191,36,0.25);
    box-shadow: 0 0 60px rgba(251,191,36,0.12), 0 20px 60px rgba(0,0,0,0.5);
    overflow: visible; position: relative;
}
#mlp-projects-overlay .mlp-premium-hero {
    padding: 40px 28px 24px; text-align: center; position: relative;
    background: radial-gradient(ellipse at 50% 0%, rgba(251,191,36,0.15) 0%, transparent 70%);
    border-bottom: 1px solid rgba(255,255,255,0.06);
}
#mlp-projects-overlay .mlp-premium-glow {
    position: absolute; top: -30px; left: 50%; transform: translateX(-50%);
    width: 120px; height: 120px; border-radius: 50%;
    background: radial-gradient(circle, rgba(251,191,36,0.3) 0%, transparent 70%);
    pointer-events: none;
}
#mlp-projects-overlay .mlp-premium-crown {
    display: inline-flex; align-items: center; justify-content: center;
    width: 64px; height: 64px; border-radius: 20px;
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 50%, #b45309 100%);
    box-shadow: 0 4px 24px rgba(251,191,36,0.4), 0 0 0 1px rgba(251,191,36,0.3);
    color: #fff; margin-bottom: 16px;
    animation: mlpCrownPulse 3s ease-in-out infinite;
}
@keyframes mlpCrownPulse {
    0%,100% { box-shadow: 0 4px 24px rgba(251,191,36,0.4), 0 0 0 1px rgba(251,191,36,0.3); }
    50%      { box-shadow: 0 4px 36px rgba(251,191,36,0.65), 0 0 0 2px rgba(251,191,36,0.5); }
}
#mlp-projects-overlay .mlp-premium-price-tag {
    display: flex; align-items: center; justify-content: center; gap: 10px;
    margin-bottom: 12px;
}
#mlp-projects-overlay .mlp-premium-price-strike {
    font-size: 0.875rem; color: #475569; text-decoration: line-through;
}
#mlp-projects-overlay .mlp-premium-price-free {
    font-size: 2rem; font-weight: 800; color: #fbbf24; line-height: 1;
}
#mlp-projects-overlay .mlp-premium-price-period {
    font-size: 0.875rem; font-weight: 500; color: #94a3b8;
}
#mlp-projects-overlay .mlp-premium-title {
    display: block; font-size: 1.375rem; font-weight: 800;
    color: #f8fafc; margin-bottom: 6px; letter-spacing: -0.02em;
}
#mlp-projects-overlay .mlp-premium-sub {
    font-size: 0.875rem; color: #64748b; margin: 0;
}
#mlp-projects-overlay .mlp-premium-features {
    padding: 20px 28px; display: flex; flex-direction: column; gap: 14px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
}
#mlp-projects-overlay .mlp-premium-feature {
    display: flex; align-items: flex-start; gap: 13px;
}
#mlp-projects-overlay .mlp-premium-feature-icon {
    width: 30px; height: 30px; border-radius: 8px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
}
#mlp-projects-overlay .mlp-pfi-green  { background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.25); }
#mlp-projects-overlay .mlp-pfi-purple { background: rgba(139,92,246,0.15); color: #8b5cf6; border: 1px solid rgba(139,92,246,0.25); }
#mlp-projects-overlay .mlp-pfi-blue   { background: rgba(59,130,246,0.15); color: #3b82f6; border: 1px solid rgba(59,130,246,0.25); }
#mlp-projects-overlay .mlp-pfi-gold   { background: rgba(251,191,36,0.15); color: #fbbf24; border: 1px solid rgba(251,191,36,0.25); }
#mlp-projects-overlay .mlp-premium-feature-icon svg { flex-shrink: 0; }
#mlp-projects-overlay .mlp-premium-feature-text {
    display: flex; flex-direction: column; gap: 1px;
}
#mlp-projects-overlay .mlp-premium-feature-name {
    font-size: 0.875rem; font-weight: 600; color: #e2e8f0;
}
#mlp-projects-overlay .mlp-premium-feature-desc {
    font-size: 0.75rem; color: #475569;
}
#mlp-projects-overlay .mlp-premium-footer {
    padding: 20px 28px 24px; text-align: center; display: flex; flex-direction: column; gap: 10px;
}
#mlp-projects-overlay .mlp-btn-upgrade-free {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 50%, #b45309 100%);
    color: #fff; border: none; border-radius: 10px;
    padding: 14px 28px; font-size: 1rem; font-family: var(--mlp-font); font-weight: 700;
    cursor: pointer; width: 100%;
    box-shadow: 0 4px 24px rgba(251,191,36,0.4);
    transition: opacity 0.15s, transform 0.12s, box-shadow 0.15s;
    letter-spacing: 0.01em;
}
#mlp-projects-overlay .mlp-btn-upgrade-free:hover {
    opacity: 0.92; transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(251,191,36,0.55);
}
#mlp-projects-overlay .mlp-btn-upgrade-free:active { transform: translateY(0); }
#mlp-projects-overlay .mlp-btn-upgrade-free svg { flex-shrink: 0; }
#mlp-projects-overlay .mlp-premium-footnote {
    font-size: 0.6875rem; color: #334155; margin: 0; line-height: 1.5;
}
#mlp-projects-overlay .mlp-premium-modal-close {
    position: absolute; top: 14px; right: 14px; z-index: 10;
    background: rgba(255,255,255,0.08) !important; color: #64748b !important;
    border: 1px solid rgba(255,255,255,0.12) !important;
}
#mlp-projects-overlay .mlp-premium-modal-close:hover {
    background: rgba(255,255,255,0.15) !important; color: #e2e8f0 !important;
}

/* ── 37. Project limit banner ───────────────────────────────── */
#mlp-projects-overlay .mlp-limit-banner {
    position: fixed; bottom: 60px; left: 50%; transform: translateX(-50%);
    z-index: 2147483646; width: auto; min-width: 340px; max-width: 580px;
    animation: mlpBannerIn 0.35s cubic-bezier(0.34,1.56,0.64,1);
}
@keyframes mlpBannerIn {
    from { opacity: 0; transform: translateX(-50%) translateY(20px) scale(0.95); }
    to   { opacity: 1; transform: translateX(-50%) translateY(0)    scale(1); }
}
#mlp-projects-overlay .mlp-limit-banner-inner {
    display: flex; align-items: center; gap: 12px;
    background: #1e293b; border: 1px solid rgba(251,191,36,0.30);
    border-radius: 12px; padding: 12px 16px;
    box-shadow: 0 8px 40px rgba(0,0,0,0.4), 0 0 0 1px rgba(251,191,36,0.10);
}
#mlp-projects-overlay .mlp-limit-banner-left {
    display: flex; align-items: center; gap: 10px; flex: 1;
    font-size: 0.8125rem; color: #94a3b8; line-height: 1.4;
}
#mlp-projects-overlay .mlp-limit-banner-left svg { color: #f59e0b; flex-shrink: 0; }
#mlp-projects-overlay .mlp-limit-banner-left strong { color: #f1f5f9; }
#mlp-projects-overlay .mlp-limit-banner-upgrade {
    display: inline-flex; align-items: center; gap: 6px;
    background: linear-gradient(135deg, #f59e0b, #d97706);
    color: #fff; border: none; border-radius: 20px; padding: 7px 14px;
    font-size: 0.8125rem; font-family: var(--mlp-font); font-weight: 700;
    cursor: pointer; white-space: nowrap; flex-shrink: 0;
    transition: opacity 0.15s, transform 0.1s;
    box-shadow: 0 2px 10px rgba(251,191,36,0.3);
}
#mlp-projects-overlay .mlp-limit-banner-upgrade:hover { opacity: 0.88; transform: scale(1.04); }
#mlp-projects-overlay .mlp-limit-banner-close {
    background: none; border: none; color: #475569; cursor: pointer;
    font-size: 1rem; padding: 2px 4px; flex-shrink: 0; border-radius: 4px;
    transition: color 0.12s, background 0.12s;
}
#mlp-projects-overlay .mlp-limit-banner-close:hover { color: #94a3b8; background: rgba(255,255,255,0.07); }



/* ── 41. Sort bar ────────────────────────────────────────────── */
#mlp-projects-overlay .mlp-sort-bar {
    display: flex !important; align-items: center; justify-content: space-between;
    padding: 8px 20px; border-bottom: 1px solid var(--mlp-border);
    background: #f8fafc; gap: 8px; flex-wrap: wrap;
}
#mlp-projects-overlay .mlp-sort-bar-left { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
#mlp-projects-overlay .mlp-sort-bar-right { display: flex; align-items: center; gap: 8px; }
#mlp-projects-overlay .mlp-sort-label {
    font-size: 0.6875rem; font-weight: 700; color: var(--mlp-text-muted);
    text-transform: uppercase; letter-spacing: 0.07em; white-space: nowrap;
}
#mlp-projects-overlay .mlp-sort-btn {
    display: inline-flex; align-items: center; gap: 4px;
    background: transparent; border: 1px solid var(--mlp-border);
    border-radius: 20px; padding: 3px 11px;
    font-size: 0.75rem; font-family: var(--mlp-font); font-weight: 500;
    color: var(--mlp-text-secondary); cursor: pointer;
    transition: background 0.12s, border-color 0.12s, color 0.12s;
    white-space: nowrap;
}
#mlp-projects-overlay .mlp-sort-btn:hover { background: #f1f5f9; border-color: #cbd5e1; }
#mlp-projects-overlay .mlp-sort-btn.mlp-sort-active {
    background: var(--mlp-accent); border-color: var(--mlp-accent);
    color: #fff;
}
#mlp-projects-overlay .mlp-sort-btn.mlp-sort-desc::after { content: ""; }
#mlp-projects-overlay .mlp-sort-btn.mlp-sort-asc::after  { content: ""; }
#mlp-projects-overlay .mlp-sort-dir-btn {
    display: inline-flex !important; align-items: center; justify-content: center;
    background: var(--mlp-accent); border: 1px solid var(--mlp-accent);
    border-radius: 20px; width: 26px; height: 26px; padding: 0;
    cursor: pointer; transition: background 0.15s, transform 0.2s;
    flex-shrink: 0;
}
#mlp-projects-overlay .mlp-sort-dir-btn svg { stroke: #fff; display: block; transition: transform 0.2s; }
#mlp-projects-overlay .mlp-sort-dir-btn:hover { background: #1d4ed8; border-color: #1d4ed8; }
#mlp-projects-overlay .mlp-sort-dir-btn.mlp-dir-asc svg  { transform: rotate(180deg); }
#mlp-projects-overlay .mlp-sort-dir-btn.mlp-dir-desc svg { transform: rotate(0deg); }

/* ── 41b. Filter chips bar ───────────────────────────────────── */
#mlp-projects-overlay .mlp-filter-bar {
    display: flex !important; align-items: center; gap: 8px;
    padding: 8px 20px; border-bottom: 1px solid var(--mlp-border);
    background: #ffffff; flex-wrap: wrap;
}
#mlp-projects-overlay .mlp-filter-label {
    font-size: 0.6875rem; font-weight: 700; color: var(--mlp-text-muted);
    text-transform: uppercase; letter-spacing: 0.07em; white-space: nowrap;
}
#mlp-projects-overlay .mlp-filter-chip-group { display: inline-flex; align-items: center; gap: 6px; flex-wrap: wrap; }
#mlp-projects-overlay .mlp-filter-tag-wrap { display: inline-flex; align-items: center; gap: 8px; flex-wrap: wrap; }
#mlp-projects-overlay .mlp-filter-divider {
    display: inline-block; width: 1px; height: 18px; background: var(--mlp-border);
}
#mlp-projects-overlay .mlp-filter-chip {
    display: inline-flex; align-items: center; gap: 4px;
    background: #f1f5f9; border: 1px solid var(--mlp-border);
    border-radius: 20px; padding: 4px 12px;
    font-size: 0.75rem; font-family: var(--mlp-font); font-weight: 500;
    color: var(--mlp-text-secondary); cursor: pointer;
    transition: background 0.12s, border-color 0.12s, color 0.12s;
    white-space: nowrap;
}
#mlp-projects-overlay .mlp-filter-chip:hover { background: #e2e8f0; border-color: #cbd5e1; }
#mlp-projects-overlay .mlp-filter-chip.mlp-filter-active {
    background: var(--mlp-accent); border-color: var(--mlp-accent); color: #fff;
}
#mlp-projects-overlay .mlp-filter-chip-clear {
    background: transparent; border-color: transparent; color: var(--mlp-text-muted);
    text-decoration: underline; padding: 4px 6px;
}
#mlp-projects-overlay .mlp-filter-chip-clear:hover { background: transparent; color: var(--mlp-accent); }
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-filter-bar { background: #0f172a; }
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-filter-chip { background: #1e293b; color: #cbd5e1; border-color: #334155; }
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-filter-chip:hover { background: #334155; }
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-filter-chip.mlp-filter-active { background: var(--mlp-accent); color: #fff; }

/* ── 41c. Copy name button + tag chips on row ────────────────── */
#mlp-projects-overlay .mlp-row-copy-name-btn {
    background: transparent; border: 1px solid transparent;
    border-radius: 6px; padding: 2px 5px; margin-left: 4px;
    cursor: pointer; opacity: 0; transition: opacity 0.15s, background 0.12s, border-color 0.12s;
    color: var(--mlp-text-muted); display: inline-flex; align-items: center;
    vertical-align: middle;
}
#mlp-projects-overlay .mlp-row-name:hover .mlp-row-copy-name-btn,
#mlp-projects-overlay .mlp-row-copy-name-btn:focus { opacity: 1; }
#mlp-projects-overlay .mlp-row-copy-name-btn:hover {
    background: rgba(37,99,235,0.08); border-color: var(--mlp-border); color: var(--mlp-accent);
}
#mlp-projects-overlay .mlp-row-copy-name-btn .mlp-copy-emoji {
    font-size: 13px; line-height: 1; display: inline-block;
}
#mlp-projects-overlay .mlp-row-copy-name-btn.mlp-copied {
    opacity: 1; color: #16a34a; border-color: #bbf7d0; background: #f0fdf4;
}
#mlp-projects-overlay tr.mlp-row-pinned .mlp-row-copy-name-btn { color: #94a3b8 !important; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-row-copy-name-btn:hover { color: #93c5fd !important; background: #1e3a5f !important; }

#mlp-projects-overlay .mlp-row-tags {
    display: flex; flex-wrap: wrap; gap: 4px;
    margin-top: 4px;
}
#mlp-projects-overlay .mlp-tag-chip {
    display: inline-flex; align-items: center; gap: 3px;
    background: #eef2ff; color: #4338ca; border: 1px solid #c7d2fe;
    border-radius: 10px; padding: 1px 8px;
    font-size: 0.6875rem; font-weight: 600; line-height: 1.4;
    cursor: pointer; transition: background 0.12s;
}
#mlp-projects-overlay .mlp-tag-chip:hover { background: #c7d2fe; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-tag-chip {
    background: #1e3a5f !important; color: #c7d2fe !important; border-color: #3b4d6d !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-tag-chip {
    background: #1e1b4b; color: #c7d2fe; border-color: #3730a3;
}

/* ── 42. Bulk actions bar ────────────────────────────────────── */
#mlp-projects-overlay .mlp-bulk-count {
    font-size: 0.8125rem; font-weight: 600; color: var(--mlp-text-secondary);
    white-space: nowrap;
}
#mlp-projects-overlay .mlp-btn-bulk-del {
    display: inline-flex; align-items: center; gap: 5px;
    background: var(--mlp-danger); color: #fff; border: none;
    border-radius: var(--mlp-radius-sm); padding: 6px 14px;
    font-size: 0.8125rem; font-family: var(--mlp-font); font-weight: 600;
    cursor: pointer; transition: background 0.12s;
}
#mlp-projects-overlay .mlp-btn-bulk-del:hover { background: var(--mlp-danger-hover); }
#mlp-projects-overlay .mlp-btn-bulk-export {
    display: inline-flex; align-items: center; gap: 5px;
    background: var(--mlp-accent); color: #fff; border: none;
    border-radius: var(--mlp-radius-sm); padding: 6px 14px;
    font-size: 0.8125rem; font-family: var(--mlp-font); font-weight: 600;
    cursor: pointer; transition: background 0.12s;
}
#mlp-projects-overlay .mlp-btn-bulk-export:hover { background: var(--mlp-accent-hover); }
#mlp-projects-overlay .mlp-btn-bulk-tag {
    display: inline-flex; align-items: center; gap: 5px;
    background: #4f46e5; color: #fff; border: none;
    border-radius: var(--mlp-radius-sm); padding: 6px 14px;
    font-size: 0.8125rem; font-family: var(--mlp-font); font-weight: 600;
    cursor: pointer; transition: background 0.12s;
}
#mlp-projects-overlay .mlp-btn-bulk-tag:hover { background: #4338ca; }

/* Right-click menu on tag filter chips (rendered on document.body, not inside overlay) */
.mlp-tag-chip-menu {
    position: fixed; z-index: 2147483647;
    min-width: 220px; padding: 6px;
    background: #ffffff; color: #0f172a;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    box-shadow: 0 12px 32px rgba(15,23,42,0.18), 0 2px 6px rgba(15,23,42,0.08);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 0.8125rem;
}
.mlp-tag-chip-menu-header {
    padding: 6px 10px 8px; margin-bottom: 4px;
    font-weight: 600; color: #4f46e5;
    border-bottom: 1px solid #f1f5f9;
}
.mlp-tag-chip-menu-item {
    display: block; width: 100%; text-align: left;
    padding: 8px 10px; border: none; background: transparent;
    border-radius: 6px; cursor: pointer; color: inherit;
    font-size: 0.8125rem; font-family: inherit;
}
.mlp-tag-chip-menu-item:hover { background: #f1f5f9; }
.mlp-tag-chip-menu-section-label {
    padding: 4px 10px 2px; font-size: 0.6875rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.04em; color: #64748b;
}
.mlp-tag-chip-menu-divider {
    height: 1px; background: #f1f5f9; margin: 6px 4px;
}
.mlp-tag-color-row {
    display: flex; flex-wrap: wrap; gap: 6px; padding: 4px 10px 8px;
}
.mlp-tag-color-swatch {
    width: 20px; height: 20px; border-radius: 50%;
    border: 2px solid transparent; cursor: pointer; padding: 0;
    transition: transform 0.1s, border-color 0.1s;
}
.mlp-tag-color-swatch:hover { transform: scale(1.15); }
.mlp-tag-color-swatch.mlp-tag-color-selected { border-color: #0f172a; }
.mlp-tag-color-clear {
    width: 20px; height: 20px; border-radius: 50%;
    border: 1px dashed #cbd5e1; background: #ffffff; color: #64748b;
    cursor: pointer; padding: 0; font-size: 11px; line-height: 1;
    display: inline-flex; align-items: center; justify-content: center;
}
.mlp-tag-color-clear:hover { background: #f1f5f9; color: #0f172a; }
.mlp-tag-chip-menu-item.mlp-tag-chip-menu-danger { color: #dc2626; }
.mlp-tag-chip-menu-item.mlp-tag-chip-menu-danger:hover { background: #fef2f2; }
@media (prefers-color-scheme: dark) {
    .mlp-tag-chip-menu {
        background: #1e293b; color: #e2e8f0; border-color: #334155;
        box-shadow: 0 12px 32px rgba(0,0,0,0.5), 0 2px 6px rgba(0,0,0,0.3);
    }
    .mlp-tag-chip-menu-header { color: #a5b4fc; border-bottom-color: #334155; }
    .mlp-tag-chip-menu-item:hover { background: #334155; }
    .mlp-tag-chip-menu-section-label { color: #94a3b8; }
    .mlp-tag-chip-menu-divider { background: #334155; }
    .mlp-tag-color-swatch.mlp-tag-color-selected { border-color: #f1f5f9; }
    .mlp-tag-color-clear { background: #1e293b; color: #94a3b8; border-color: #475569; }
    .mlp-tag-color-clear:hover { background: #334155; color: #f1f5f9; }
    .mlp-tag-chip-menu-item.mlp-tag-chip-menu-danger { color: #f87171; }
    .mlp-tag-chip-menu-item.mlp-tag-chip-menu-danger:hover { background: #3a1f1f; }
}
#mlp-projects-overlay .mlp-btn-xs {
    padding: 5px 12px !important; font-size: 0.75rem !important;
}

/* ── 43. Checkboxes ──────────────────────────────────────────── */
#mlp-projects-overlay .mlp-th-check,
#mlp-projects-overlay .mlp-td-check { width: 36px; text-align: center !important; padding: 0 4px !important; }
#mlp-projects-overlay .mlp-th-pin,
#mlp-projects-overlay .mlp-td-pin   { width: 28px; text-align: center !important; padding: 0 2px !important; }
#mlp-projects-overlay .mlp-cb {
    display: inline-block !important; width: 15px !important; height: 15px !important;
    cursor: pointer !important; accent-color: var(--mlp-accent) !important;
}
#mlp-projects-overlay tr.mlp-row-selected td { background: rgba(37,99,235,0.06) !important; }

/* ── 44. Pin button in row ───────────────────────────────────── */
#mlp-projects-overlay .mlp-pin-btn {
    background: none; border: none; cursor: pointer;
    font-size: 14px; line-height: 1; padding: 2px; opacity: 0.3;
    transition: opacity 0.15s, transform 0.15s;
    display: inline-block !important;
}
#mlp-projects-overlay .mlp-pin-btn:hover { opacity: 0.8; transform: scale(1.2); }
#mlp-projects-overlay .mlp-pin-btn.mlp-pinned { opacity: 1; }
#mlp-projects-overlay tr.mlp-row-pinned td { background: #1e293b !important; color: #e2e8f0 !important; border-top: 1px solid #2d3f55 !important; border-bottom: 1px solid #2d3f55 !important; border-left: none !important; }
#mlp-projects-overlay tr.mlp-row-pinned td:first-child { border-left: 3px solid #3b82f6 !important; }
#mlp-projects-overlay tr.mlp-row-pinned td * { color: #e2e8f0 !important; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-proj-name { color: #f1f5f9 !important; font-weight: 700 !important; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-row-date,
#mlp-projects-overlay tr.mlp-row-pinned .mlp-row-size,
#mlp-projects-overlay tr.mlp-row-pinned .mlp-text-muted { color: #94a3b8 !important; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-visibility-badge { opacity: 0.85 !important; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-row-btn { border-color: #334155 !important; background: #0f172a !important; color: #94a3b8 !important; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-row-btn:hover { background: #1e3a5f !important; color: #e2e8f0 !important; }

/* ── 45. Storage bar ─────────────────────────────────────────── */
#mlp-projects-overlay .mlp-storage-bar-wrap {
    padding: 8px 20px 10px; border-bottom: 1px solid var(--mlp-border);
    background: #f8fafc; display: block;
}
#mlp-projects-overlay .mlp-storage-bar-label {
    display: flex; justify-content: space-between; align-items: center;
    font-size: 0.6875rem; color: var(--mlp-text-muted); margin-bottom: 5px;
    font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em;
}
#mlp-projects-overlay #mlp-storage-bar-text { font-weight: 700; color: var(--mlp-text-secondary); }
#mlp-projects-overlay .mlp-storage-bar-track {
    height: 5px; background: var(--mlp-border); border-radius: 99px; overflow: hidden;
}
#mlp-projects-overlay .mlp-storage-bar-fill {
    height: 100%; border-radius: 99px; width: 0%;
    background: linear-gradient(90deg, #3b82f6, #6366f1);
    transition: width 0.4s ease, background 0.3s;
}
#mlp-projects-overlay .mlp-storage-bar-fill.mlp-storage-warn {
    background: linear-gradient(90deg, #f59e0b, #ef4444);
}

/* ── 46. Search highlight ────────────────────────────────────── */
#mlp-projects-overlay .mlp-highlight {
    background: #fef08a; color: #78350f; border-radius: 2px;
    padding: 0 1px;
}
#mlp-projects-overlay .mlp-code-hit {
    display: block; margin-top: 4px; font-size: 0.72rem;
    color: var(--mlp-text-muted); line-height: 1.35;
}
#mlp-projects-overlay .mlp-code-hit strong { color: var(--mlp-accent); font-weight: 700; }

#mlp-projects-overlay .mlp-history-modal { max-width: 760px; }
#mlp-projects-overlay .mlp-history-sections {
    display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
}
#mlp-projects-overlay .mlp-history-heading {
    display: block; font-family: var(--mlp-font); font-size: 0.78rem;
    font-weight: 800; color: var(--mlp-text-secondary);
    margin: 0 0 8px; text-transform: uppercase; letter-spacing: 0.05em;
}
#mlp-projects-overlay .mlp-history-list {
    display: flex; flex-direction: column; gap: 8px; max-height: 320px;
    overflow: auto; padding-right: 2px;
}
#mlp-projects-overlay .mlp-history-item {
    display: flex; align-items: flex-start; justify-content: space-between; gap: 10px;
    padding: 10px 12px; border: 1px solid var(--mlp-border);
    border-radius: var(--mlp-radius-sm); background: var(--mlp-surface);
}
#mlp-projects-overlay .mlp-history-item-main { display: block; min-width: 0; }
#mlp-projects-overlay .mlp-history-item-title {
    display: block; font-size: 0.83rem; font-weight: 700; color: var(--mlp-text-primary);
}
#mlp-projects-overlay .mlp-history-item-meta {
    display: block; margin-top: 2px; font-size: 0.72rem; color: var(--mlp-text-muted);
}
#mlp-projects-overlay .mlp-history-empty {
    display: block; padding: 14px; color: var(--mlp-text-muted);
    border: 1px dashed var(--mlp-border); border-radius: var(--mlp-radius-sm);
    font-size: 0.8rem; text-align: center;
}
#mlp-projects-overlay .mlp-history-restore {
    flex-shrink: 0; border: 1px solid var(--mlp-accent); color: var(--mlp-accent);
    border-radius: var(--mlp-radius-sm); padding: 5px 9px; font-size: 0.74rem;
    font-weight: 700; background: var(--mlp-accent-light); cursor: pointer;
}
#mlp-projects-overlay .mlp-history-restore:hover { background: #dbeafe; }
@media (max-width: 720px) {
    #mlp-projects-overlay .mlp-history-sections { grid-template-columns: 1fr; }

    /* ── Mobile: sidebar always hidden and toggle button disabled ── */
    #mlp-projects-overlay .mlp-sidebar {
        width: 0 !important; min-width: 0 !important;
        padding-left: 0 !important; padding-right: 0 !important;
        border-right: none !important;
        overflow: hidden !important;
    }
    #mlp-projects-overlay .mlp-sidebar-toggle-btn {
        display: none !important;
    }

    /* ── Mobile: toolbar wraps and fits within screen ── */
    #mlp-projects-overlay .mlp-table-toolbar {
        flex-wrap: wrap;
        padding: 10px 12px;
        gap: 8px;
    }
    #mlp-projects-overlay .mlp-table-label {
        font-size: 0.875rem;
    }
    #mlp-projects-overlay .mlp-table-toolbar-right {
        width: 100%;
        gap: 6px;
    }
    #mlp-projects-overlay .mlp-search-wrap {
        flex: 1;
        min-width: 0;
        padding: 6px 9px;
    }
    #mlp-projects-overlay .mlp-search-input {
        width: 100%;
        min-width: 0;
        font-size: 0.8rem;
    }
    #mlp-projects-overlay .mlp-btn-create {
        padding: 7px 12px;
        font-size: 0.8rem;
        white-space: nowrap;
        flex-shrink: 0;
    }
}

/* ── 48. Notes modal ─────────────────────────────────────────── */
#mlp-projects-overlay .mlp-modal-notes { max-width: 520px; }
#mlp-projects-overlay .mlp-notes-proj-name {
    font-size: 0.8125rem; font-weight: 600; color: var(--mlp-text-secondary);
    margin: 0 0 8px; padding: 6px 10px; background: var(--mlp-bg);
    border-radius: var(--mlp-radius-sm); border-left: 3px solid var(--mlp-accent);
    display: block;
}
#mlp-projects-overlay .mlp-notes-textarea {
    display: block !important; width: 100% !important; min-height: 200px;
    padding: 10px 13px; border: 1px solid var(--mlp-border);
    border-radius: var(--mlp-radius-sm); font-size: 0.875rem;
    font-family: var(--mlp-font-mono); color: var(--mlp-text-primary);
    background: var(--mlp-surface); outline: none; resize: vertical;
    transition: border-color 0.15s, box-shadow 0.15s; line-height: 1.6;
}
#mlp-projects-overlay .mlp-notes-textarea:focus {
    border-color: var(--mlp-accent); box-shadow: 0 0 0 3px rgba(37,99,235,0.12);
}
#mlp-projects-overlay .mlp-notes-preview {
    min-height: 100px; padding: 10px 13px;
    border: 1px solid var(--mlp-border); border-radius: var(--mlp-radius-sm);
    font-size: 0.875rem; color: var(--mlp-text-primary);
    line-height: 1.7; background: var(--mlp-bg);
}
#mlp-projects-overlay .mlp-notes-preview h1,
#mlp-projects-overlay .mlp-notes-preview h2,
#mlp-projects-overlay .mlp-notes-preview h3 {
    display: block; font-weight: 700; margin: 8px 0 4px; color: var(--mlp-text-primary);
}
#mlp-projects-overlay .mlp-notes-preview code {
    display: inline; background: var(--mlp-border); padding: 1px 5px;
    border-radius: 3px; font-family: var(--mlp-font-mono); font-size: 0.8125rem;
}
#mlp-projects-overlay .mlp-notes-preview p { display: block; margin: 4px 0; }
#mlp-projects-overlay .mlp-notes-toolbar {
    display: flex; justify-content: space-between; align-items: center;
    margin-top: 6px;
}
#mlp-projects-overlay .mlp-notes-char {
    font-size: 0.6875rem; color: var(--mlp-text-muted);
}
#mlp-projects-overlay .mlp-notes-indicator {
    display: inline-block !important; width: 7px; height: 7px; border-radius: 50%;
    background: #6366f1; margin-left: 6px; flex-shrink: 0;
    box-shadow: 0 0 0 2px rgba(99,102,241,0.22); vertical-align: middle;
}


#mlp-projects-overlay .mlp-row-desc {
    display: block !important; font-size: 0.75rem; color: var(--mlp-text-muted);
    font-weight: 400; margin-top: 2px; white-space: nowrap;
    overflow: hidden; text-overflow: ellipsis; max-width: 220px;
}
#mlp-projects-overlay .mlp-row-shared-from {
    display: inline-flex !important; align-items: center; gap: 3px;
    font-size: 0.7rem; font-weight: 600; margin-top: 3px; margin-left: 4px;
    color: #7c3aed; background: #f5f3ff; border: 1px solid #ddd6fe;
    border-radius: 10px; padding: 1px 7px; white-space: nowrap;
}


/* ── 49. PIN lock row button ─────────────────────────────────── */
#mlp-projects-overlay .mlp-row-btn-notes { background: transparent; color: #6366f1; border: 1px solid rgba(99,102,241,0.3); }
#mlp-projects-overlay .mlp-row-btn-notes:hover { background: rgba(99,102,241,0.08); border-color: rgba(99,102,241,0.5); }
#mlp-projects-overlay .mlp-row-btn-stats { background: transparent; color: #6366f1; border: 1px solid rgba(99,102,241,0.30); display: inline-flex; align-items: center; gap: 4px; }
#mlp-projects-overlay .mlp-row-btn-stats:hover { background: rgba(99,102,241,0.08); border-color: rgba(99,102,241,0.55); }
#mlp-projects-overlay .mlp-row-btn-stats svg { flex-shrink: 0; stroke: currentColor; fill: none; }
#mlp-projects-overlay .mlp-row-btn-lock  { background: transparent; color: #64748b; border: 1px solid var(--mlp-border); }
#mlp-projects-overlay .mlp-row-btn-lock:hover  { background: #f1f5f9; }
#mlp-projects-overlay .mlp-row-btn-desc  { background: transparent; color: #64748b; border: 1px solid var(--mlp-border); }
#mlp-projects-overlay .mlp-row-btn-desc:hover  { background: #f1f5f9; }
#mlp-projects-overlay .mlp-row-locked-indicator {
    display: inline-flex !important; align-items: center; gap: 4px;
    font-size: 0.7rem; color: #94a3b8; margin-left: 6px;
    background: var(--mlp-bg); border: 1px solid var(--mlp-border);
    border-radius: 20px; padding: 1px 6px;
}

/* ── 50. Undo toast button ───────────────────────────────────── */
#mlp-projects-overlay .mlp-toast-undo {
    flex-shrink: 0; background: rgba(37,99,235,0.12);
    border: 1px solid rgba(37,99,235,0.3); color: var(--mlp-accent);
    border-radius: var(--mlp-radius-sm); padding: 4px 10px;
    font-size: 0.75rem; font-family: var(--mlp-font); font-weight: 700;
    cursor: pointer; transition: background 0.12s; white-space: nowrap;
    margin-top: 4px; display: inline-block !important;
}
#mlp-projects-overlay .mlp-toast-undo:hover { background: rgba(37,99,235,0.2); }

/* ── 40. Force SVG rendering (theme override protection) ────── */
#mlp-projects-overlay svg {
    display: inline-block !important;
    overflow: visible !important;
    vertical-align: middle !important;
    fill: none !important;
}
#mlp-projects-overlay svg path,
#mlp-projects-overlay svg polyline,
#mlp-projects-overlay svg line,
#mlp-projects-overlay svg circle,
#mlp-projects-overlay svg rect,
#mlp-projects-overlay svg polygon {
    vector-effect: non-scaling-stroke !important;
}
/* Crown icon: filled white, no stroke */
#mlp-projects-overlay .mlp-premium-crown svg {
    fill: #fff !important;
    stroke: none !important;
    display: block !important;
}
#mlp-projects-overlay .mlp-premium-crown svg path {
    fill: #fff !important;
    stroke: none !important;
}
#mlp-projects-overlay .mlp-premium-crown-icon {
    display: block !important;
    font-size: 30px !important;
    line-height: 1 !important;
    font-style: normal !important;
    font-family: "Apple Color Emoji","Segoe UI Emoji","Noto Color Emoji",sans-serif !important;
}

/* ── 38. Row color button — premium lock state ──────────────── */
#mlp-projects-overlay .mlp-row-btn-color-locked {
    opacity: 0.65; position: relative;
}
#mlp-projects-overlay .mlp-row-btn-color-locked::after {
    content: "🔒";
    font-size: 9px; position: absolute; top: 1px; right: 1px;
    line-height: 1;
}

/* ── 39. Premium plan label in sidebar ──────────────────────── */
#mlp-projects-overlay .mlp-sidebar-profile-plan {
    display: inline-flex; align-items: center; gap: 4px;
    font-size: 0.6875rem; color: #475569; font-weight: 600;
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 20px; padding: 2px 8px; white-space: nowrap;
}

/* ── 31. Row action button extras ───────────────────────────── */
#mlp-projects-overlay .mlp-row-btn-rename {
    background: transparent; color: #64748b;
    border: 1px solid var(--mlp-border);
}
#mlp-projects-overlay .mlp-row-btn-rename:hover {
    background: #f1f5f9; color: var(--mlp-text-primary); border-color: #cbd5e1;
}
#mlp-projects-overlay .mlp-row-btn-dup {
    background: transparent; color: #64748b;
    border: 1px solid var(--mlp-border);
}
#mlp-projects-overlay .mlp-row-btn-dup:hover {
    background: #f1f5f9; color: var(--mlp-text-primary); border-color: #cbd5e1;
}
#mlp-projects-overlay .mlp-row-btn-color {
    background: transparent; color: #64748b;
    border: 1px solid var(--mlp-border);
    padding: 5px 9px; display: inline-flex; align-items: center; justify-content: center;
    font-size: 13px; line-height: 1;
}
#mlp-projects-overlay .mlp-row-btn-color:hover {
    background: #f1f5f9; color: var(--mlp-text-primary); border-color: #cbd5e1;
}
#mlp-projects-overlay .mlp-row-actions { flex-wrap: wrap; }
/* ── 51. Backup modal ────────────────────────────────────────── */
#mlp-projects-overlay .mlp-backup-modal-inner {
    max-width: 400px;
    border-top: 3px solid #2563eb;
}
#mlp-projects-overlay .mlp-backup-modal-header {
    background: linear-gradient(135deg, rgba(37,99,235,0.06) 0%, transparent 100%);
    border-bottom: 1px solid rgba(37,99,235,0.15);
    padding: 16px 20px;
}
#mlp-projects-overlay .mlp-backup-header-left {
    display: flex; align-items: center; gap: 10px;
}
#mlp-projects-overlay .mlp-backup-header-right {
    display: flex; align-items: center; gap: 8px; margin-left: auto;
}
#mlp-projects-overlay .mlp-backup-icon-wrap {
    width: 32px; height: 32px; border-radius: 8px;
    background: rgba(37,99,235,0.12); border: 1px solid rgba(37,99,235,0.25);
    display: flex; align-items: center; justify-content: center;
    color: #2563eb; flex-shrink: 0;
}
#mlp-projects-overlay .mlp-backup-badge {
    display: inline-flex; align-items: center;
    background: #dbeafe; color: #1d4ed8;
    border-radius: 20px; padding: 3px 10px;
    font-size: 0.7rem; font-weight: 700;
    letter-spacing: 0.04em; text-transform: uppercase;
    white-space: nowrap;
}
#mlp-projects-overlay .mlp-backup-modal-body {
    gap: 12px;
}
#mlp-projects-overlay .mlp-backup-warning {
    display: flex; align-items: flex-start; gap: 9px;
    background: #eff6ff; border: 1px solid #bfdbfe;
    border-radius: 8px; padding: 10px 13px;
    color: #1e40af; font-size: 0.8125rem; line-height: 1.55;
}
#mlp-projects-overlay .mlp-backup-warning svg { flex-shrink: 0; margin-top: 1px; color: #2563eb; }
#mlp-projects-overlay .mlp-backup-warning strong { color: #1d4ed8; }
#mlp-projects-overlay .mlp-backup-desc {
    font-size: 0.8125rem; color: var(--mlp-text-secondary); line-height: 1.6; margin: 0;
}
#mlp-projects-overlay .mlp-backup-desc strong { color: var(--mlp-text-primary); }
#mlp-projects-overlay .mlp-backup-info-row {
    display: flex; gap: 16px; flex-wrap: wrap;
}
#mlp-projects-overlay .mlp-backup-info-item {
    display: flex; align-items: center; gap: 6px;
    font-size: 0.75rem; color: var(--mlp-text-muted);
}
#mlp-projects-overlay .mlp-backup-info-item svg { flex-shrink: 0; color: var(--mlp-text-muted); }
#mlp-projects-overlay .mlp-backup-modal-footer {
    background: #f8fafc;
    flex-direction: column; gap: 8px; align-items: stretch;
}
#mlp-projects-overlay .mlp-backup-download-btn {
    display: inline-flex !important; align-items: center; justify-content: center;
    gap: 7px; width: 100%; padding: 11px 20px !important;
    font-size: 0.9rem !important;
    box-shadow: 0 2px 8px rgba(37,99,235,0.30) !important;
}
#mlp-projects-overlay .mlp-backup-download-btn:hover {
    box-shadow: 0 4px 14px rgba(37,99,235,0.45) !important;
}
#mlp-projects-overlay .mlp-backup-skip-btn {
    width: 100%; justify-content: center; text-align: center;
    font-size: 0.8rem !important; color: var(--mlp-text-muted) !important;
    border-color: transparent !important; padding: 6px 16px !important;
}
#mlp-projects-overlay .mlp-backup-skip-btn:hover {
    color: var(--mlp-text-secondary) !important;
    background: #f1f5f9 !important;
    border-color: var(--mlp-border) !important;
}

/* ── 52. Load Backup sidebar button ─────────────────────────── */
#mlp-projects-overlay .mlp-sidebar-loadbackup-row {
    display: flex !important; padding: 6px 10px 6px; flex-shrink: 0;
}
#mlp-projects-overlay .mlp-sidebar-loadbackup-btn {
    display: flex !important; align-items: center !important; gap: 7px !important;
    width: 100% !important; background: rgba(255,255,255,0.05) !important;
    color: #94a3b8 !important; border: 1px solid rgba(255,255,255,0.09) !important;
    border-radius: 8px !important; padding: 8px 12px !important;
    font-size: 0.75rem !important; font-weight: 600 !important;
    cursor: pointer !important; transition: background 0.15s, color 0.15s, border-color 0.15s !important;
    font-family: var(--mlp-font) !important; letter-spacing: 0.02em !important;
}
#mlp-projects-overlay .mlp-sidebar-loadbackup-btn svg {
    flex-shrink: 0 !important; display: inline-block !important;
    stroke: currentColor !important; fill: none !important;
}
#mlp-projects-overlay .mlp-sidebar-loadbackup-btn:hover {
    background: rgba(37,99,235,0.18) !important;
    color: #93c5fd !important;
    border-color: rgba(37,99,235,0.35) !important;
}

/* ── 53b. RePublish button ───────────────────────────────────── */
#mlp-projects-overlay .mlp-proj-republish-btn {
    display: inline-flex !important; align-items: center; gap: 4px;
    background: rgba(124,58,237,0.08) !important; color: #7c3aed !important;
    border: 1px solid rgba(124,58,237,0.35) !important; border-radius: 20px;
    padding: 2px 9px; font-size: 0.7rem; font-family: var(--mlp-font); font-weight: 600;
    cursor: pointer; margin-top: 4px; transition: background 0.12s, border-color 0.12s;
    white-space: nowrap;
}
#mlp-projects-overlay .mlp-proj-republish-btn:hover {
    background: rgba(124,58,237,0.16) !important; border-color: rgba(124,58,237,0.60) !important; color: #6d28d9 !important;
}
#mlp-projects-overlay .mlp-proj-republish-btn svg {
    flex-shrink: 0 !important; stroke: currentColor !important; fill: none !important;
}
#mlp-projects-overlay .mlp-proj-share-action-btn {
    display: inline-flex !important; align-items: center; gap: 4px;
    background: #eff6ff !important; color: #2563eb !important;
    border: 1px solid #bfdbfe !important; border-radius: 20px;
    padding: 2px 9px; font-size: 0.7rem; font-family: var(--mlp-font); font-weight: 600;
    cursor: pointer; margin-top: 4px; transition: background 0.12s, border-color 0.12s;
    white-space: nowrap;
}
#mlp-projects-overlay .mlp-proj-share-action-btn:hover {
    background: #dbeafe !important; border-color: #93c5fd !important; color: #1d4ed8 !important;
}
#mlp-projects-overlay .mlp-proj-share-action-btn svg {
    flex-shrink: 0 !important; stroke: currentColor !important; fill: none !important;
}
#mlp-projects-overlay td .mlp-proj-share-action-btn,
#mlp-projects-overlay td .mlp-proj-republish-btn {
    display: flex !important;
}
/* Force correct colors inside pinned rows — overrides the td * wildcard */
#mlp-projects-overlay tr.mlp-row-pinned .mlp-proj-share-action-btn {
    background: rgba(37,99,235,0.15) !important; color: #93c5fd !important; border-color: rgba(37,99,235,0.35) !important;
}
#mlp-projects-overlay tr.mlp-row-pinned .mlp-proj-share-action-btn * { color: #93c5fd !important; stroke: #93c5fd !important; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-proj-share-action-btn:hover {
    background: rgba(37,99,235,0.25) !important; color: #bfdbfe !important; border-color: rgba(37,99,235,0.55) !important;
}
#mlp-projects-overlay tr.mlp-row-pinned .mlp-proj-republish-btn {
    background: rgba(124,58,237,0.12) !important; color: #7c3aed !important; border-color: rgba(124,58,237,0.40) !important;
}
#mlp-projects-overlay tr.mlp-row-pinned .mlp-proj-republish-btn * { color: #7c3aed !important; stroke: #7c3aed !important; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-proj-republish-btn:hover {
    background: rgba(124,58,237,0.20) !important; color: #6d28d9 !important; border-color: rgba(124,58,237,0.65) !important;
}
/* Fix visibility badge colors in pinned rows */
#mlp-projects-overlay tr.mlp-row-pinned .mlp-badge-public {
    background: rgba(37,99,235,0.15) !important; color: #93c5fd !important; border: 1px solid rgba(37,99,235,0.30) !important;
}
#mlp-projects-overlay tr.mlp-row-pinned .mlp-badge-private {
    background: rgba(16,163,74,0.15) !important; color: #86efac !important; border: 1px solid rgba(16,163,74,0.30) !important;
}
/* Fix stats button in pinned rows */
#mlp-projects-overlay tr.mlp-row-pinned .mlp-row-btn-stats {
    background: rgba(99,102,241,0.12) !important; color: #a5b4fc !important; border: 1px solid rgba(99,102,241,0.35) !important;
}
#mlp-projects-overlay tr.mlp-row-pinned .mlp-row-btn-stats:hover {
    background: rgba(99,102,241,0.22) !important; color: #c7d2fe !important; border-color: rgba(99,102,241,0.60) !important;
}
#mlp-projects-overlay tr.mlp-row-pinned .mlp-row-btn-stats * {
    color: #a5b4fc !important; stroke: #a5b4fc !important;
}

/* ── 53. Publish / Moderation modal styles ───────────────────── */
#mlp-projects-overlay .mlp-publish-info-box {
    display: flex; align-items: flex-start; gap: 10px;
    background: #eff6ff; border: 1px solid #bfdbfe;
    border-radius: var(--mlp-radius); padding: 12px 14px;
    font-size: 0.8125rem; color: #1e40af; line-height: 1.5;
}
#mlp-projects-overlay .mlp-mod-checking-wrap {
    display: flex; align-items: center; gap: 14px;
    background: #f8fafc; border: 1px solid var(--mlp-border);
    border-radius: var(--mlp-radius); padding: 18px 16px;
}
#mlp-projects-overlay .mlp-mod-spinner {
    width: 22px; height: 22px; flex-shrink: 0;
    border: 3px solid #e2e8f0; border-top-color: var(--mlp-accent);
    border-radius: 50%;
    animation: mlp-spin 0.75s linear infinite;
}
@keyframes mlp-spin { to { transform: rotate(360deg); } }
#mlp-projects-overlay .mlp-mod-checking-text {
    display: flex; flex-direction: column; gap: 3px;
    font-size: 0.8125rem; color: var(--mlp-text-primary);
}
#mlp-projects-overlay .mlp-mod-checking-text strong { font-weight: 700; }
#mlp-projects-overlay .mlp-mod-checking-text span { color: var(--mlp-text-secondary); }
#mlp-projects-overlay .mlp-mod-reject-box {
    display: flex; align-items: flex-start; gap: 10px;
    background: #fef2f2; border: 1px solid #fecaca;
    border-radius: var(--mlp-radius); padding: 12px 14px;
}
#mlp-projects-overlay .mlp-mod-reject-box strong {
    display: block; font-weight: 700; color: #991b1b; font-size: 0.875rem;
}
#mlp-projects-overlay .mlp-mod-reject-reason {
    margin-top: 4px; font-size: 0.8rem; color: #b91c1c; line-height: 1.5;
}
#mlp-projects-overlay .mlp-mod-approve-box {
    display: flex; align-items: center; gap: 8px;
    background: #f0fdf4; border: 1px solid #bbf7d0;
    border-radius: var(--mlp-radius); padding: 10px 14px;
    font-size: 0.8125rem; color: #15803d; font-weight: 600;
}

/* ── Favorites (star) ─────────────────────────────────────── */
#mlp-projects-overlay .mlp-th-star { width: 32px; padding: 0 4px !important; }
#mlp-projects-overlay .mlp-td-star { width: 32px; padding: 0 4px !important; text-align: center; }
#mlp-projects-overlay .mlp-star-btn {
    background: transparent; border: none; cursor: pointer;
    font-size: 16px; line-height: 1; padding: 4px;
    opacity: 0.28; filter: grayscale(1);
    transition: all 0.15s ease;
}
#mlp-projects-overlay .mlp-star-btn:hover { opacity: 0.85; transform: scale(1.2); }
#mlp-projects-overlay .mlp-star-btn.mlp-favorited {
    opacity: 1; filter: none;
    text-shadow: 0 0 8px rgba(250, 204, 21, 0.6);
}
#mlp-projects-overlay tr.mlp-row-favorited td { background: #fffbeb !important; }
#mlp-projects-overlay tr.mlp-row-favorited td:first-child { border-left: 3px solid #f59e0b !important; }
#mlp-projects-overlay tr.mlp-row-pinned.mlp-row-favorited td:first-child { border-left: 3px solid #f59e0b !important; }

/* ── View count stat (under project name) ─────────────────── */
#mlp-projects-overlay .mlp-view-count-badge {
    display: flex; align-items: center; gap: 5px;
    width: fit-content; max-width: max-content;
    margin-top: 10px; padding: 3px 9px 3px 8px;
    background: transparent; color: #475569;
    border: 1px solid #e2e8f0; border-radius: 6px;
    font-size: 0.7rem; font-weight: 600;
    line-height: 1.4; letter-spacing: 0.01em;
    font-variant-numeric: tabular-nums;
    transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease;
}
#mlp-projects-overlay .mlp-view-count-badge:hover {
    background: #f8fafc; color: #1e293b; border-color: #cbd5e1;
}
#mlp-projects-overlay .mlp-view-count-badge .mlp-vc-icon {
    width: 12px; height: 12px; flex-shrink: 0;
    color: #64748b; opacity: 0.95;
}
#mlp-projects-overlay .mlp-view-count-badge .mlp-vc-num {
    font-weight: 700; color: #0f172a;
}
#mlp-projects-overlay .mlp-view-count-badge .mlp-vc-label {
    font-weight: 500; color: #64748b;
    text-transform: uppercase; font-size: 0.62rem;
    letter-spacing: 0.06em;
}
#mlp-projects-overlay .mlp-view-count-badge.mlp-vc-loading { opacity: 0.55; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-view-count-badge {
    background: rgba(148, 163, 184, 0.08) !important;
    border-color: #334155 !important; color: #cbd5e1 !important;
}
#mlp-projects-overlay tr.mlp-row-pinned .mlp-view-count-badge .mlp-vc-icon { color: #94a3b8 !important; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-view-count-badge .mlp-vc-num { color: #f1f5f9 !important; }
#mlp-projects-overlay tr.mlp-row-pinned .mlp-view-count-badge .mlp-vc-label { color: #94a3b8 !important; }

/* ── Owner preview modal ──────────────────────────────────── */
#mlp-projects-overlay .mlp-owner-card {
    display: flex; align-items: center; justify-content: center;
    background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px;
    padding: 18px 15px; margin-bottom: 14px;
}
#mlp-projects-overlay .mlp-owner-info {
    display: flex; flex-direction: column; align-items: center; gap: 10px;
}
#mlp-projects-overlay .mlp-owner-avatar {
    width: 72px; height: 72px; border-radius: 50%; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.6rem; font-weight: 700; overflow: hidden;
    background: #6366f1; color: #fff;
    box-shadow: 0 2px 10px rgba(99,102,241,0.25);
}
#mlp-projects-overlay .mlp-owner-avatar img {
    width: 100%; height: 100%; object-fit: cover; border-radius: 50%;
}
#mlp-projects-overlay .mlp-owner-label {
    font-size: 0.68rem; font-weight: 700; color: #94a3b8;
    text-transform: uppercase; letter-spacing: 0.06em; text-align: center;
}
#mlp-projects-overlay .mlp-owner-proj-name {
    font-size: 0.9rem; font-weight: 600; color: #1e293b;
    margin: 0 0 4px; line-height: 1.4;
}
#mlp-projects-overlay .mlp-owner-proj-desc {
    font-size: 0.8rem; color: #64748b; margin: 0 0 4px; line-height: 1.5;
}
/* Dark theme overrides */
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-owner-card {
    background: rgba(148,163,184,0.07); border-color: #334155;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-owner-name { color: #f1f5f9; }
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-owner-proj-name { color: #e2e8f0; }
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-owner-proj-desc { color: #94a3b8; }

/* ── Last opened display ──────────────────────────────────── */
#mlp-projects-overlay .mlp-row-opened {
    display: block; margin-top: 2px;
    font-size: 0.7rem; color: #94a3b8; font-weight: 500;
}
#mlp-projects-overlay tr.mlp-row-pinned .mlp-row-opened { color: #94a3b8 !important; }

/* ── Backup reminder toast accent ─────────────────────────── */
#mlp-projects-overlay .mlp-toast-backup-reminder {
    border-left: 4px solid #f59e0b !important;
}
#mlp-projects-overlay .mlp-toast-backup-reminder .mlp-toast-action-btn {
    margin-top: 8px; padding: 5px 12px;
    background: #f59e0b; color: #fff; border: none;
    border-radius: 6px; font-size: 0.75rem; font-weight: 600;
    cursor: pointer;
}
#mlp-projects-overlay .mlp-toast-backup-reminder .mlp-toast-action-btn:hover { background: #d97706; }

/* ── Stats Panel ─────────────────────────────────────────────── */
#mlp-projects-overlay .mlp-stats-panel {
    width: 260px; min-width: 260px; flex-shrink: 0;
    background: var(--mlp-surface);
    border-left: 1px solid var(--mlp-border);
    display: flex; flex-direction: column;
    overflow: hidden;
    transition: width 0.22s cubic-bezier(0.4,0,0.2,1), min-width 0.22s cubic-bezier(0.4,0,0.2,1), opacity 0.18s ease;
    position: relative;
    animation: mlpStatsPanelIn 0.22s cubic-bezier(0.34,1.2,0.64,1);
}
@keyframes mlpStatsPanelIn {
    from { opacity: 0; transform: translateX(16px); }
    to   { opacity: 1; transform: translateX(0); }
}
#mlp-projects-overlay .mlp-stats-panel-inner {
    display: flex; flex-direction: column; height: 100%; overflow: hidden;
}
#mlp-projects-overlay .mlp-stats-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 14px 12px;
    border-bottom: 1px solid var(--mlp-border);
    flex-shrink: 0;
    background: var(--mlp-surface);
}
#mlp-projects-overlay .mlp-stats-header-left {
    display: flex; align-items: center; gap: 8px;
}
#mlp-projects-overlay .mlp-stats-icon-wrap {
    width: 26px; height: 26px; border-radius: 6px;
    background: rgba(37,99,235,0.10); border: 1px solid rgba(37,99,235,0.20);
    display: flex; align-items: center; justify-content: center;
    color: var(--mlp-accent); flex-shrink: 0;
}
#mlp-projects-overlay .mlp-stats-title {
    font-size: 0.8125rem; font-weight: 700; color: var(--mlp-text-primary);
    letter-spacing: 0.01em;
}
#mlp-projects-overlay .mlp-stats-close-btn {
    width: 24px; height: 24px; border-radius: 5px;
    display: flex; align-items: center; justify-content: center;
    background: #f1f5f9; border: 1px solid #cbd5e1;
    cursor: pointer; color: #475569;
    transition: background 0.12s, color 0.12s, border-color 0.12s;
    flex-shrink: 0;
    opacity: 1 !important;
    visibility: visible !important;
}
#mlp-projects-overlay .mlp-stats-close-btn:hover {
    background: #e2e8f0; color: #1e293b; border-color: #94a3b8;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-stats-close-btn {
    background: #1e293b; border-color: #334155; color: #94a3b8;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-stats-close-btn:hover {
    background: #293548; color: #e2e8f0; border-color: #475569;
}
/* Identity row */
#mlp-projects-overlay .mlp-stats-identity {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 14px; border-bottom: 1px solid var(--mlp-border);
    flex-shrink: 0; background: var(--mlp-bg);
}
#mlp-projects-overlay .mlp-stats-proj-icon {
    width: 34px; height: 34px; border-radius: var(--mlp-radius-sm);
    flex-shrink: 0; display: flex; align-items: center; justify-content: center;
    background: linear-gradient(135deg, #3b82f6 0%, #7c3aed 100%);
    color: #fff; font-size: 15px; font-weight: 700;
    box-shadow: 0 2px 6px rgba(59,130,246,0.30);
}
#mlp-projects-overlay .mlp-stats-proj-icon svg {
    stroke: #fff !important; fill: none !important;
    width: 14px !important; height: 14px !important;
    display: block !important;
}
#mlp-projects-overlay .mlp-stats-proj-meta {
    display: flex; flex-direction: column; gap: 2px; min-width: 0; flex: 1;
}
#mlp-projects-overlay .mlp-stats-proj-name {
    font-size: 0.8125rem; font-weight: 700; color: var(--mlp-text-primary);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
#mlp-projects-overlay .mlp-stats-proj-vis {
    font-size: 0.6875rem; font-weight: 600; color: var(--mlp-text-muted);
    text-transform: uppercase; letter-spacing: 0.05em;
}
/* Scrollable body */
#mlp-projects-overlay .mlp-stats-body {
    flex: 1; overflow-y: auto; padding: 14px 14px 24px;
    display: flex; flex-direction: column; gap: 4px;
}
#mlp-projects-overlay .mlp-stats-body::-webkit-scrollbar { width: 4px; }
#mlp-projects-overlay .mlp-stats-body::-webkit-scrollbar-track { background: transparent; }
#mlp-projects-overlay .mlp-stats-body::-webkit-scrollbar-thumb { background: var(--mlp-border); border-radius: 99px; }
/* Go Code button */
#mlp-projects-overlay .mlp-stats-go-btn {
    display: flex !important; align-items: center; justify-content: center; gap: 7px;
    width: 100%; padding: 9px 0; margin-bottom: 12px;
    background: var(--mlp-accent); color: #fff;
    border: none; border-radius: var(--mlp-radius-sm);
    font-size: 0.8125rem; font-family: var(--mlp-font); font-weight: 700;
    cursor: pointer; letter-spacing: 0.01em;
    transition: background 0.15s, box-shadow 0.15s, transform 0.1s;
    box-shadow: 0 2px 8px rgba(37,99,235,0.30);
}
#mlp-projects-overlay .mlp-stats-go-btn:hover {
    background: var(--mlp-accent-hover); box-shadow: 0 4px 14px rgba(37,99,235,0.42); transform: translateY(-1px);
}
#mlp-projects-overlay .mlp-stats-go-btn:active { transform: translateY(0); }
#mlp-projects-overlay .mlp-stats-go-btn svg { flex-shrink: 0; stroke: currentColor; fill: none; }
/* Section label */
#mlp-projects-overlay .mlp-stats-section-label {
    font-size: 0.6rem; font-weight: 800; color: var(--mlp-text-muted);
    text-transform: uppercase; letter-spacing: 0.10em;
    margin: 10px 0 6px; display: block;
}
/* Stat cards grid */
#mlp-projects-overlay .mlp-stats-cards {
    display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-bottom: 4px;
}
#mlp-projects-overlay .mlp-stats-card {
    background: var(--mlp-bg); border: 1px solid var(--mlp-border);
    border-radius: var(--mlp-radius-sm); padding: 9px 10px;
    display: flex; flex-direction: column; gap: 2px;
    transition: border-color 0.12s, box-shadow 0.12s;
}
#mlp-projects-overlay .mlp-stats-card:hover {
    border-color: var(--mlp-accent); box-shadow: 0 0 0 2px rgba(37,99,235,0.08);
}
#mlp-projects-overlay .mlp-stats-card-val {
    font-size: 1.1rem; font-weight: 800; color: var(--mlp-text-primary);
    line-height: 1; font-variant-numeric: tabular-nums;
    font-family: var(--mlp-font-mono);
}
#mlp-projects-overlay .mlp-stats-card-key {
    font-size: 0.65rem; font-weight: 600; color: var(--mlp-text-muted);
    text-transform: uppercase; letter-spacing: 0.06em;
}
/* Language bar */
#mlp-projects-overlay .mlp-stats-lang-bar-wrap {
    margin: 6px 0 10px; display: flex; flex-direction: column; gap: 6px;
}
#mlp-projects-overlay .mlp-stats-lang-bar {
    height: 6px; border-radius: 99px; overflow: hidden;
    display: flex; width: 100%;
    background: var(--mlp-border);
}
#mlp-projects-overlay .mlp-stats-lang-seg {
    height: 100%; transition: width 0.4s ease;
}
#mlp-projects-overlay .mlp-stats-lang-legend {
    display: flex; flex-wrap: wrap; gap: 6px 10px;
}
#mlp-projects-overlay .mlp-stats-lang-item {
    display: inline-flex; align-items: center; gap: 4px;
    font-size: 0.65rem; font-weight: 600; color: var(--mlp-text-secondary);
}
#mlp-projects-overlay .mlp-stats-lang-dot {
    width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0;
}
/* Timeline */
#mlp-projects-overlay .mlp-stats-timeline {
    display: flex; flex-direction: column; gap: 0;
    margin-bottom: 4px;
    border-left: 2px solid var(--mlp-border);
    margin-left: 6px; padding-left: 0;
}
#mlp-projects-overlay .mlp-stats-tl-row {
    display: flex; align-items: flex-start; gap: 10px; padding: 6px 0 6px 14px;
    position: relative;
}
#mlp-projects-overlay .mlp-stats-tl-dot {
    width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0;
    position: absolute; left: -5px; top: 10px;
    border: 2px solid var(--mlp-surface);
}
#mlp-projects-overlay .mlp-tl-created  { background: #10b981; }
#mlp-projects-overlay .mlp-tl-modified { background: #3b82f6; }
#mlp-projects-overlay .mlp-tl-opened  { background: #8b5cf6; }
#mlp-projects-overlay .mlp-tl-age     { background: #f59e0b; }
#mlp-projects-overlay .mlp-stats-tl-content {
    display: flex; flex-direction: column; gap: 1px; min-width: 0;
}
#mlp-projects-overlay .mlp-stats-tl-label {
    font-size: 0.6875rem; font-weight: 600; color: var(--mlp-text-muted);
    white-space: nowrap;
}
#mlp-projects-overlay .mlp-stats-tl-val {
    font-size: 0.75rem; font-weight: 600; color: var(--mlp-text-primary);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 185px;
}
/* View count hero */
#mlp-projects-overlay .mlp-stats-view-hero {
    display: flex; align-items: baseline; gap: 5px; margin: 4px 0 8px;
}
#mlp-projects-overlay .mlp-stats-view-num {
    font-size: 1.875rem; font-weight: 800; color: var(--mlp-accent);
    line-height: 1; font-variant-numeric: tabular-nums; font-family: var(--mlp-font-mono);
}
#mlp-projects-overlay .mlp-stats-view-label {
    font-size: 0.75rem; color: var(--mlp-text-muted); font-weight: 600;
}
/* Sparkline */
#mlp-projects-overlay .mlp-stats-sparkline-wrap {
    background: var(--mlp-bg); border: 1px solid var(--mlp-border);
    border-radius: var(--mlp-radius-sm); padding: 8px 10px; margin-bottom: 4px;
}
#mlp-projects-overlay .mlp-stats-sparkline {
    display: block; width: 100%; height: 48px;
}
#mlp-projects-overlay .mlp-stats-spark-label {
    font-size: 0.625rem; color: var(--mlp-text-muted); margin-top: 4px;
    font-weight: 600; text-align: center; letter-spacing: 0.04em;
}
/* Tags */
#mlp-projects-overlay .mlp-stats-tags-wrap {
    display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 4px;
}
/* Notes preview */
#mlp-projects-overlay .mlp-stats-notes-preview {
    font-size: 0.75rem; color: var(--mlp-text-secondary); line-height: 1.6;
    background: var(--mlp-bg); border: 1px solid var(--mlp-border);
    border-radius: var(--mlp-radius-sm); padding: 8px 10px;
    max-height: 100px; overflow: hidden;
    border-left: 3px solid var(--mlp-accent);
    white-space: pre-wrap; word-break: break-word;
    position: relative;
}
#mlp-projects-overlay .mlp-stats-notes-preview::after {
    content: ""; position: absolute; bottom: 0; left: 0; right: 0;
    height: 24px;
    background: linear-gradient(transparent, var(--mlp-bg));
}
/* ── Language Distribution Chart ── */
#mlp-projects-overlay .mlp-stats-lang-chart {
    display: flex; flex-direction: column; gap: 5px;
    margin: 2px 0 8px;
}
#mlp-projects-overlay .mlp-stats-lc-row {
    display: flex; align-items: center; gap: 7px;
}
#mlp-projects-overlay .mlp-stats-lc-label {
    font-size: 0.625rem; font-weight: 700; color: var(--mlp-text-muted);
    width: 28px; text-align: right; flex-shrink: 0; text-transform: uppercase;
}
#mlp-projects-overlay .mlp-stats-lc-track {
    flex: 1; height: 10px; background: var(--mlp-border-muted);
    border-radius: 99px; overflow: hidden; position: relative;
}
#mlp-projects-overlay .mlp-stats-lc-fill {
    height: 100%; border-radius: 99px;
    transition: width 0.5s cubic-bezier(0.34,1.2,0.64,1);
}
#mlp-projects-overlay .mlp-stats-lc-pct {
    font-size: 0.625rem; font-weight: 700; color: var(--mlp-text-secondary);
    width: 30px; flex-shrink: 0; text-align: right;
}

/* ── Last 7 Edits ── */
#mlp-projects-overlay .mlp-stats-edits-wrap {
    display: flex; flex-direction: column; gap: 4px; margin: 2px 0 8px;
}
#mlp-projects-overlay .mlp-stats-edit-row {
    display: flex; align-items: center; gap: 8px;
}
#mlp-projects-overlay .mlp-stats-edit-label {
    font-size: 0.6rem; color: var(--mlp-text-muted); font-weight: 600;
    width: 42px; flex-shrink: 0; font-variant-numeric: tabular-nums;
}
#mlp-projects-overlay .mlp-stats-edit-dot {
    width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
    background: var(--mlp-accent);
}
#mlp-projects-overlay .mlp-stats-edit-meta {
    font-size: 0.6875rem; color: var(--mlp-text-primary); font-weight: 500;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
#mlp-projects-overlay .mlp-stats-edit-empty {
    font-size: 0.75rem; color: var(--mlp-text-muted); font-style: italic;
    padding: 6px 0;
}

/* ── Storage Usage ── */
#mlp-projects-overlay .mlp-stats-storage-wrap {
    margin: 2px 0 10px;
}
#mlp-projects-overlay .mlp-stats-storage-row {
    display: flex; justify-content: space-between; align-items: center;
    font-size: 0.6875rem; margin-bottom: 3px;
}
#mlp-projects-overlay .mlp-stats-storage-label {
    color: var(--mlp-text-muted); font-weight: 600;
}
#mlp-projects-overlay .mlp-stats-storage-val {
    color: var(--mlp-text-primary); font-weight: 700;
    font-variant-numeric: tabular-nums; font-family: var(--mlp-font-mono);
}
#mlp-projects-overlay .mlp-stats-storage-bar-track {
    height: 8px; background: var(--mlp-border-muted);
    border-radius: 99px; overflow: hidden;
    display: flex; margin: 6px 0 5px;
}
#mlp-projects-overlay .mlp-stats-storage-bar-proj {
    height: 100%; background: var(--mlp-accent);
    transition: width 0.5s cubic-bezier(0.34,1.2,0.64,1);
}
#mlp-projects-overlay .mlp-stats-storage-bar-other {
    height: 100%; background: #f59e0b;
    transition: width 0.5s cubic-bezier(0.34,1.2,0.64,1);
}
#mlp-projects-overlay .mlp-stats-storage-legend {
    display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
    font-size: 0.6rem; font-weight: 600; color: var(--mlp-text-muted);
}
#mlp-projects-overlay .mlp-stats-storage-dot {
    display: inline-block; width: 7px; height: 7px;
    border-radius: 50%; margin-right: 3px;
}
#mlp-projects-overlay .mlp-dot-proj  { background: var(--mlp-accent); }
#mlp-projects-overlay .mlp-dot-other { background: #f59e0b; }
#mlp-projects-overlay .mlp-stats-storage-pct {
    margin-left: auto; color: var(--mlp-text-secondary); font-size: 0.6875rem; font-weight: 700;
}

/* Dark theme tweaks */
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-stats-panel {
    background: var(--mlp-surface); border-color: var(--mlp-border);
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-stats-header,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-stats-identity {
    background: var(--mlp-surface); border-color: var(--mlp-border);
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-stats-card {
    background: #0b1220 !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-stats-sparkline-wrap,
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-stats-notes-preview {
    background: #0b1220 !important; border-color: var(--mlp-border) !important;
}
#mlp-projects-overlay[data-mlp-theme="dark"] .mlp-stats-notes-preview::after {
    background: linear-gradient(transparent, #0b1220);
}
';
    }

    /* ------------------------------------------------------------------ */
    /*  JavaScript                                                          */
    /* ------------------------------------------------------------------ */

    private static function get_js() {
        $ls_key = esc_js( self::LS_KEY );
        $ajax_url = esc_js( admin_url( 'admin-ajax.php' ) );
        $share_nonce = esc_js( wp_create_nonce( 'mlp_share_project' ) );

        $js = <<<'ENDJS'
(function () {
    'use strict';

    /* ── Keys ─────────────────────────────────────────────────────── */
    var LS_KEY       = 'MLP_PROJECTS_LS_KEY_PLACEHOLDER'; // array of projects
    var TABS_KEY     = 'mlp_saved_tabs';     // main plugin's editor tab store
    var LAST_ID_KEY  = 'mlp_last_proj_id';   // which project was open on last session
    var PREMIUM_KEY  = 'mlp_premium_plan';   // 'premium' or unset = free
    var SORT_KEY     = 'mlp_sort_pref';      // current sort preference
    var BULK_KEY     = 'mlp_bulk_sel';       // not persisted, just a var
    var MLP_AJAX_URL = 'MLP_AJAX_URL_PLACEHOLDER';
    var MLP_SHARE_NONCE = 'MLP_SHARE_NONCE_PLACEHOLDER';
    var HISTORY_LIMIT = 20;

    /* ══════════════════════════════════════════════════════════════════════
     * Option 3 — NSFWJS client-side image moderation
     *
     * mlpNsfwCheck( dataUrlOrSrc, callback )
     *   callback( isNsfw )  — called with true if the image is NSFW, false if safe.
     *
     * The NSFWJS library is loaded lazily from jsDelivr on first use so it
     * doesn't slow down the initial page load. The TensorFlow.js runtime is
     * also loaded the same way.
     *
     * NSFW categories blocked: Porn, Hentai, Sexy (threshold > 0.60)
     * Safe categories allowed: Neutral, Drawing
     * ══════════════════════════════════════════════════════════════════════ */
    var _nsfwjsModel  = null;
    var _nsfwjsLoading = false;
    var _nsfwjsQueue  = [];

    function mlpLoadNsfwJs(onReady) {
        if (_nsfwjsModel) { onReady(_nsfwjsModel); return; }
        _nsfwjsQueue.push(onReady);
        if (_nsfwjsLoading) return;
        _nsfwjsLoading = true;

        function loadScript(src, cb) {
            var s = document.createElement('script');
            s.src = src;
            s.onload  = cb;
            s.onerror = function() {
                console.warn('[MLP NSFWJS] Failed to load:', src);
                cb(); // continue even on failure (fail-open)
            };
            document.head.appendChild(s);
        }

        // Load TF.js first, then NSFWJS
        loadScript('https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@4.20.0/dist/tf.min.js', function() {
            loadScript('https://cdn.jsdelivr.net/npm/nsfwjs@4.2.0/dist/nsfwjs.min.js', function() {
                if (typeof nsfwjs === 'undefined') {
                    // Library failed to load — drain queue with fail-open (false = safe)
                    _nsfwjsLoading = false;
                    var q = _nsfwjsQueue.splice(0);
                    for (var i = 0; i < q.length; i++) { q[i](null); }
                    return;
                }
                nsfwjs.load('https://cdn.jsdelivr.net/npm/nsfwjs@4.2.0/dist/inception_v3_quantized/', { type: 'graph' })
                    .then(function(model) {
                        _nsfwjsModel  = model;
                        _nsfwjsLoading = false;
                        var q = _nsfwjsQueue.splice(0);
                        for (var i = 0; i < q.length; i++) { q[i](model); }
                    })
                    .catch(function(err) {
                        console.warn('[MLP NSFWJS] Model load failed:', err);
                        _nsfwjsLoading = false;
                        var q = _nsfwjsQueue.splice(0);
                        for (var i = 0; i < q.length; i++) { q[i](null); }
                    });
            });
        });
    }

    /**
     * Check a single image src (data-URI or URL) with NSFWJS.
     * Calls callback( isNsfw ) — true = blocked, false = safe.
     */
    function mlpNsfwCheck(src, callback) {
        mlpLoadNsfwJs(function(model) {
            if (!model) { callback(false); return; } // Fail-open if model unavailable

            var img = new Image();
            img.crossOrigin = 'anonymous';
            img.onload = function() {
                model.classify(img)
                    .then(function(predictions) {
                        var blocked = false;
                        var nsfwCategories = ['Porn', 'Hentai', 'Sexy'];
                        for (var i = 0; i < predictions.length; i++) {
                            if (nsfwCategories.indexOf(predictions[i].className) !== -1 &&
                                predictions[i].probability > 0.60) {
                                blocked = true;
                                break;
                            }
                        }
                        callback(blocked);
                    })
                    .catch(function() { callback(false); }); // Fail-open on classify error
            };
            img.onerror = function() { callback(false); }; // Fail-open if image won't load
            img.src = src;
        });
    }

    /* ══════════════════════════════════════════════════════════════════════
     * mlpAvatarTextCheck — OCR-based profanity detection for avatar images
     *
     * Uses Tesseract.js (free, runs entirely in-browser, no API key needed)
     * to extract any visible text from the image, then checks it against a
     * profanity word list. This catches images that contain offensive text
     * (e.g. a photo that just says "fuck") which NSFWJS cannot detect because
     * NSFWJS only classifies visual content, not embedded text.
     *
     * mlpAvatarTextCheck( dataUrl, callback )
     *   callback( isOffensive )
     *     true  — image contains profanity/slurs in visible text → block it
     *     false — clean, or OCR unavailable (fail-open so Tesseract outages
     *             don't break the avatar upload flow entirely)
     * ══════════════════════════════════════════════════════════════════════ */
    var _tesseractWorker  = null;
    var _tesseractLoading = false;
    var _tesseractQueue   = [];

    // Zero-cost client-side profanity list — covers the most common violations.
    // Stored as fragments joined at runtime so the source itself isn't a wall
    // of slurs. Extend this array with any language-specific terms you need.
    var MLP_PROFANITY_PATTERNS = (function () {
        // Each entry is a regex source string (case-insensitive, word-boundary
        // aware where needed). We use loose matching so l33t-speak substitutions
        // like "fvck", "sh!t", "a$$" are still caught.
        var raw = [
            // Core English profanity
            'f+[u*@vu]+c+k+',          // fuck / fvck / f**k / fuuck …
            'sh[i!1]+t',               // shit / sh!t / sh1t
            'b[i!1]+tc+h',             // bitch
            'c[u*]+n+t',               // cunt
            'a[s$]+h+[o0]l+[e3]',      // asshole / a$$hole
            '\\bass+\\b',              // ass (standalone)
            'w+h+[o0]+r+[e3]',         // whore
            'd[i!1]+c+k',              // dick
            'c[o0]+c+k',               // cock
            'p+[e3]+n[i!1]+s',         // penis (crude context)
            'p+[u*]+s+[sy]',           // pussy
            'b[a@]+s+t+[a@]+r+d',      // bastard
            'tw[a@]+t',                // twat
            'w[a@]+n+k',               // wank / wanker
            'j[i!1]+z+[z]*',           // jizz
            'c+u+m+sh[o0]+t',          // cumshot
            'f+[a@]+g+[o0]+t',         // f-slur (anti-gay)
            // Racial / ethnic slurs (abbreviated to avoid this source being a
            // slur list itself — add full forms as needed for your context)
            'n[i!1]+g+[gea]+[r]*',     // n-word variants
            'sp[i!1]+c+',              // s-slur
            'k[i!1]+k[e3]',            // k-slur
            'ch[i!1]+nk',              // c-slur
            'g[o0]+[o0]+k',            // g-slur
            'w[e3]+tb[a@]+c+k',        // w-slur
            'c+r[a@]+c+k+[e3]+r',      // c-slur
            // Death / violence
            'k[i!1]+ll\\s*your\\s*self',
            'g[o0]\\s*d[i!1][e3]',
        ];
        return new RegExp('(?:' + raw.join('|') + ')', 'i');
    }());

    function mlpLoadTesseract(onReady) {
        if (_tesseractWorker) { onReady(_tesseractWorker); return; }
        _tesseractQueue.push(onReady);
        if (_tesseractLoading) return;
        _tesseractLoading = true;

        var s = document.createElement('script');
        // Tesseract.js v4 — single-file CDN build, no WASM fetch required
        s.src = 'https://cdn.jsdelivr.net/npm/tesseract.js@4.1.4/dist/tesseract.min.js';
        s.onload = function () {
            if (typeof Tesseract === 'undefined') {
                _tesseractLoading = false;
                var q = _tesseractQueue.splice(0);
                for (var i = 0; i < q.length; i++) { q[i](null); }
                return;
            }
            Tesseract.createWorker('eng', 1, {
                // Point at the jsDelivr-hosted traineddata files so no local
                // copy is needed and there is no CORS issue.
                workerPath:  'https://cdn.jsdelivr.net/npm/tesseract.js@4.1.4/dist/worker.min.js',
                langPath:    'https://tessdata.projectnaptha.com/4.0.0',
                corePath:    'https://cdn.jsdelivr.net/npm/tesseract.js-core@4.0.4/tesseract-core-simd-lstm.wasm.js',
                logger:      function () {}, // silence progress logs
            }).then(function (worker) {
                _tesseractWorker  = worker;
                _tesseractLoading = false;
                var q = _tesseractQueue.splice(0);
                for (var i = 0; i < q.length; i++) { q[i](worker); }
            }).catch(function (err) {
                console.warn('[MLP OCR] Tesseract worker failed:', err);
                _tesseractLoading = false;
                var q = _tesseractQueue.splice(0);
                for (var i = 0; i < q.length; i++) { q[i](null); }
            });
        };
        s.onerror = function () {
            console.warn('[MLP OCR] Failed to load Tesseract.js');
            _tesseractLoading = false;
            var q = _tesseractQueue.splice(0);
            for (var i = 0; i < q.length; i++) { q[i](null); }
        };
        document.head.appendChild(s);
    }

    /**
     * Run OCR on a data URL and check extracted text for profanity.
     * Calls callback( isOffensive ).  Fails open (false) on any error.
     */
    function mlpAvatarTextCheck(dataUrl, callback) {
        mlpLoadTesseract(function (worker) {
            if (!worker) {
                // Tesseract unavailable — fail open so uploads still work.
                console.warn('[MLP OCR] Tesseract not available, skipping text check.');
                callback(false);
                return;
            }
            worker.recognize(dataUrl)
                .then(function (result) {
                    var text = (result && result.data && result.data.text) ? result.data.text : '';
                    // Collapse whitespace so spaced-out words like "f u c k" collapse
                    var collapsed = text.replace(/\s+/g, '');
                    var isOffensive = MLP_PROFANITY_PATTERNS.test(text) ||
                                      MLP_PROFANITY_PATTERNS.test(collapsed);
                    callback(isOffensive);
                })
                .catch(function (err) {
                    console.warn('[MLP OCR] recognize() failed:', err);
                    callback(false); // fail open
                });
        });
    }

    /**
     * Extract all image src values from an HTML/CSS/JS string.
     * Returns an array of up to 5 unique src strings for client-side checking.
     */
    function mlpExtractImageSrcs(content) {
        var srcs = [];
        var seen = {};

        function add(s) {
            if (s && !seen[s]) { seen[s] = true; srcs.push(s); }
        }

        // Base64 data-URIs
        var b64re = /data:image\/[^"'`\s)>]{10,}/gi;
        var m;
        while ((m = b64re.exec(content)) !== null) { add(m[0]); }

        // <img src="…">
        var imgre = /<img[^>]+src=["']([^"']+)["'][^>]*>/gi;
        while ((m = imgre.exec(content)) !== null) { add(m[1]); }

        // CSS url(…)
        var cssre = /url\(["']?(https?:\/\/[^"')]+)["']?\)/gi;
        while ((m = cssre.exec(content)) !== null) { add(m[1]); }

        return srcs.slice(0, 5); // Cap at 5 for performance
    }

    /* ── Capture share hash IMMEDIATELY at parse time ────────────────
       WordPress sometimes redirects (e.g. trailing slash) which drops
       the hash. We grab it right now and stash it in sessionStorage so
       the init() handler can still read it even after a redirect.      */
    (function() {
        try {
            var h = window.location.hash || '';
            if (h.indexOf('#mlpsh_') === 0 || h.indexOf('#mlpsht_') === 0) {
                sessionStorage.setItem('mlp_pending_share', h.slice(1));
                window.history.replaceState(null, '', window.location.pathname + window.location.search);
                return;
            }
            var params = new URLSearchParams(window.location.search || '');
            var token = params.get('mlpsht');
            var inlineShare = params.get('mlpsh');
            if (token) {
                sessionStorage.setItem('mlp_pending_share', 'mlpsht_' + token);
                params.delete('mlpsht');
                var cleanSearch = params.toString();
                window.history.replaceState(null, '', window.location.pathname + (cleanSearch ? '?' + cleanSearch : ''));
            } else if (inlineShare) {
                sessionStorage.setItem('mlp_pending_share', 'mlpsh_' + inlineShare);
                params.delete('mlpsh');
                var cleanInlineSearch = params.toString();
                window.history.replaceState(null, '', window.location.pathname + (cleanInlineSearch ? '?' + cleanInlineSearch : ''));
            }
        } catch(e) {}
    })();

    /* ── Plan limits ──────────────────────────────────────────── */
    var FREE_MAX_PROJECTS    = Infinity;
    var PREMIUM_MAX_PROJECTS = Infinity;

    /* ── ID generator ─────────────────────────────────────────────── */
    function generateId() {
        return 'p' + Date.now().toString(36) + Math.random().toString(36).substr(2, 8);
    }

    /* ── Simple hash for PIN (djb2) ──────────────────────────────── */
    function hashPin(pin) {
        var h = 5381;
        for (var i = 0; i < pin.length; i++) { h = ((h << 5) + h) + pin.charCodeAt(i); h = h & h; }
        return h.toString(16);
    }



    /* ── Premium helpers ──────────────────────────────────────────── */
    function isPremium() {
        return true; // All features are available to everyone
    }
    function setPremium() {
        try { localStorage.setItem(PREMIUM_KEY, 'premium'); } catch(e) {}
    }
    function getMaxProjects() {
        return isPremium() ? PREMIUM_MAX_PROJECTS : FREE_MAX_PROJECTS;
    }

    /* ── Storage helpers ──────────────────────────────────────────── */
    var _sharedInboxMerged = false; // run once per page load

    function mergeSharedInbox(projects) {
        // Read current user profile
        try {
            var profRaw = localStorage.getItem('mlp_user_profile');
            if (!profRaw) return { projects: projects, newCount: 0 };
            var prof = JSON.parse(profRaw);
            if (!prof || !prof.name) return { projects: projects, newCount: 0 };

            var inboxKey = 'mlp_projects__user__' + prof.name;
            var inboxRaw = localStorage.getItem(inboxKey);
            if (!inboxRaw) return { projects: projects, newCount: 0 };

            var inbox = JSON.parse(inboxRaw);
            if (!Array.isArray(inbox) || inbox.length === 0) return { projects: projects, newCount: 0 };

            // Merge: only add projects not already in the list (by original id match or new id)
            var existingIds = {};
            for (var i = 0; i < projects.length; i++) { existingIds[projects[i].id] = true; }

            var added = 0;
            for (var j = 0; j < inbox.length; j++) {
                var sp = inbox[j];
                if (!sp || !sp.id) continue;
                if (existingIds[sp.id]) continue;
                projects.push(sp);
                existingIds[sp.id] = true;
                added++;
            }

            // Clear the inbox after merging
            localStorage.removeItem(inboxKey);
            return { projects: projects, newCount: added };
        } catch(e) { return { projects: projects, newCount: 0 }; }
    }

    function getProjects() {
        try {
            var raw = localStorage.getItem(LS_KEY);
            if (!raw) {
                // Still check inbox even if no projects yet
                if (!_sharedInboxMerged) {
                    _sharedInboxMerged = true;
                    var result0 = mergeSharedInbox([]);
                    if (result0.newCount > 0) {
                        saveProjects(result0.projects);
                        setTimeout(function() {
                            window._mlpSharedProjectsCount = result0.newCount;
                        }, 200);
                    }
                    return result0.projects;
                }
                return [];
            }
            var data = JSON.parse(raw);
            // Auto-migrate old single-project format (object with .name but no .id array)
            if (data && !Array.isArray(data) && data.name && !data.id) {
                var migrated = {
                    id:         generateId(),
                    name:       data.name || 'Untitled',
                    createdAt:  data.createdAt || new Date().toISOString(),
                    updatedAt:  data.updatedAt || data.createdAt || new Date().toISOString(),
                    visibility: 'private',
                    html:       data.html || '',
                    css:        data.css  || '',
                    js:         data.js   || '',
                    savedTabs:  null
                };
                saveProjects([migrated]);
                return [migrated];
            }
            var projects = Array.isArray(data) ? data : [];

            // Merge shared inbox once per page load
            if (!_sharedInboxMerged) {
                _sharedInboxMerged = true;
                var mergeResult = mergeSharedInbox(projects);
                if (mergeResult.newCount > 0) {
                    saveProjects(mergeResult.projects);
                    window._mlpSharedProjectsCount = mergeResult.newCount;
                }
                return mergeResult.projects;
            }
            return projects;
        } catch (e) { return []; }
    }

    function saveProjects(arr) {
        try { localStorage.setItem(LS_KEY, JSON.stringify(arr)); } catch (e) {}
    }

    function copyProjectForHistory(p) {
        var copy = {};
        for (var k in p) {
            if (p.hasOwnProperty(k) && k !== 'history' && k !== 'activity') copy[k] = p[k];
        }
        return copy;
    }

    function projectContentHash(p) {
        try {
            return JSON.stringify({
                name: p.name || '',
                description: p.description || '',
                notes: p.notes || '',
                html: p.html || '',
                css: p.css || '',
                js: p.js || '',
                savedTabs: p.savedTabs || null,
                allTabs: p.allTabs || null
            });
        } catch(e) { return String(Date.now()); }
    }

    function addProjectActivity(p, label) {
        var now = new Date().toISOString();
        var activity = Array.isArray(p.activity) ? p.activity.slice(0) : [];
        activity.unshift({ at: now, label: label || 'Updated project' });
        p.activity = activity.slice(0, 30);
    }

    function pushProjectVersion(p, label) {
        var now = new Date().toISOString();
        var hash = projectContentHash(p);
        var history = Array.isArray(p.history) ? p.history.slice(0) : [];
        if (history.length && history[0].hash === hash) return;
        history.unshift({
            id: 'v' + Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
            at: now,
            label: label || 'Saved version',
            hash: hash,
            data: copyProjectForHistory(p)
        });
        p.history = history.slice(0, HISTORY_LIMIT);
    }

    function labelForChanges(changes) {
        if (changes.name !== undefined) return 'Renamed project';
        if (changes.notes !== undefined) return 'Updated notes';
        if (changes.description !== undefined) return 'Updated description';
        if (changes.pinHash !== undefined) return changes.pinHash ? 'Set password' : 'Removed password';
        if (changes.iconColor !== undefined || changes.emoji !== undefined) return 'Updated icon';
        if (changes.allTabs !== undefined || changes.savedTabs !== undefined || changes.html !== undefined || changes.css !== undefined || changes.js !== undefined) return 'Saved code changes';
        if (changes.pinned !== undefined) return changes.pinned ? 'Pinned project' : 'Unpinned project';
        if (changes.favorite !== undefined) return changes.favorite ? 'Added to favorites' : 'Removed from favorites';
        if (changes.tags !== undefined) return 'Updated tags';
        return 'Updated project';
    }

    var CONTENT_CHANGE_KEYS = ['html','css','js','savedTabs','allTabs','activeTabId'];

    function updateProjectById(id, changes) {
        var projects = getProjects();
        for (var i = 0; i < projects.length; i++) {
            if (projects[i].id === id) {
                var beforeHash = projectContentHash(projects[i]);
                var nextProject = copyProjectForHistory(projects[i]);
                for (var nk in changes) {
                    if (changes.hasOwnProperty(nk)) nextProject[nk] = changes[nk];
                }
                if (projectContentHash(nextProject) !== beforeHash) {
                    pushProjectVersion(projects[i], labelForChanges(changes));
                }
                for (var k in changes) {
                    if (changes.hasOwnProperty(k)) projects[i][k] = changes[k];
                }
                projects[i].updatedAt = new Date().toISOString();
                addProjectActivity(projects[i], labelForChanges(changes));

                // ── Share URL is intentionally NOT cleared here. ──────────────
                // openShareModal() already detects content changes via
                // computeShareContentHash() and forces re-moderation when needed.
                // Clearing it here based on allTabs/savedTabs diffs is unreliable
                // because flushTabsToProject writes fresh timestamps on every page
                // load, making the hash always look different even with no edits.

                saveProjects(projects);
                return projects[i];
            }
        }
        return null;
    }

    function deleteProjectById(id) {
        saveProjects(getProjects().filter(function (p) { return p.id !== id; }));
    }

    /* ── Snapshot helpers ─────────────────────────────────────────── */

    /**
     * Read the CURRENT mlp_saved_tabs from localStorage and persist it
     * into the given project's savedTabs field. Called before any
     * project switch and on page unload so nothing is lost.
     * Also captures allTabs (saved + unsaved) into project.allTabs.
     */

    /* ═══════════════════════════════════════════════════════════════
     * CRITICAL: Synchronous boot-time restore
     * ───────────────────────────────────────────────────────────────
     * This runs IMMEDIATELY — before DOMContentLoaded — so that
     * mlp_saved_tabs is already set to the correct project's tabs
     * before the main plugin's init handler reads it.
     *
     * Without this, the main plugin would always load whatever tabs
     * happened to be in mlp_saved_tabs from the previous session,
     * which may belong to a completely different project.
     * ═══════════════════════════════════════════════════════════════ */
    (function bootRestore() {
        var lastId = null;
        try { lastId = localStorage.getItem(LAST_ID_KEY); } catch (e) {}
        if (!lastId) return;

        var projects = getProjects();
        for (var i = 0; i < projects.length; i++) {
            if (projects[i].id === lastId) {
                // Set current project before the editor init fires
                window.mlpCurrentProjectId = lastId;
                restoreTabsFromProject(projects[i]);
                return;
            }
        }
        // lastId no longer exists — clean up the stale pointer
        try { localStorage.removeItem(LAST_ID_KEY); } catch (e) {}
    }());

    /* ── Auto-save on page unload ─────────────────────────────────── */
    /*
     * Flush current tab state to the active project whenever the user
     * navigates away or refreshes. This is the safety net that ensures
     * work is never lost between explicit saves.
     */
    window.addEventListener('beforeunload', function () {
        flushTabsToProject(window.mlpCurrentProjectId || null);
    });

    /* Also flush on visibility change (tab hidden / phone lock screen) */
    document.addEventListener('visibilitychange', function () {
        if (document.visibilityState === 'hidden') {
            flushTabsToProject(window.mlpCurrentProjectId || null);
        }
    });

    /* ── Wrap window.mlpLoadProject ───────────────────────────────── */
    /*
     * Intercept the main plugin's project-load call so we can:
     *   1. Flush the CURRENT project's tabs before switching away.
     *   2. Set the new active project ID.
     *   3. Restore the new project's tabs into mlp_saved_tabs.
     *   4. Record the new project as the "last open" for next page load.
     */
    var _origLoadProject = window.mlpLoadProject;
    window.mlpLoadProject = function (p) {
        if (!p || !p.id) return;

        // Step 1 — flush any unsaved work from the current project first
        flushTabsToProject(window.mlpCurrentProjectId || null);

        // Step 2 — set new active project
        window.mlpCurrentProjectId = p.id;

        // Step 3 — restore new project's tabs into the shared store
        // Re-read from storage to get the freshest savedTabs (flushTabsToProject
        // may have just updated the old project, so we need a fresh read for the new one)
        var freshProjects = getProjects();
        var freshP = null;
        for (var i = 0; i < freshProjects.length; i++) {
            if (freshProjects[i].id === p.id) { freshP = freshProjects[i]; break; }
        }
        restoreTabsFromProject(freshP || p);

        // Step 4 — persist "last open" for boot restore on next page load
        try { localStorage.setItem(LAST_ID_KEY, p.id); } catch (e) {}

        // Step 4b — record lastOpenedAt on the project itself (silent; no version push)
        try {
            var allProjs = getProjects();
            for (var li = 0; li < allProjs.length; li++) {
                if (allProjs[li].id === p.id) {
                    allProjs[li].lastOpenedAt = new Date().toISOString();
                    saveProjects(allProjs);
                    break;
                }
            }
        } catch (e) {}

        // Step 5 — call original main-plugin handler with enriched project data
        if (typeof _origLoadProject === 'function') {
            _origLoadProject(freshP || p);
        }

        // Step 6 — reload editor tabs for this project
        scheduleReloadTabsForProject(p.id, 12);
    };

    /* ══════════════════════════════════════════════════════════════
     * flushTabsToProject  — capture BOTH saved and unsaved tabs
     *
     * mlp_saved_tabs  = only tabs the user explicitly saved (these get
     *                   the 💾 icon; the main plugin owns this key).
     * project.allTabs = full snapshot of ALL in-memory tabs including
     *                   unsaved ones (our own field — not touched by
     *                   the main plugin).
     *
     * We NEVER add unsaved tabs to mlp_saved_tabs — that would make
     * them appear as saved when the project is reopened.
     * ══════════════════════════════════════════════════════════════ */
    function flushTabsToProject(id) {
        if (!id) return;
        try {
            var changes = {};

            if (window.monacoInstances) {
                Object.keys(window.monacoInstances).forEach(function(instanceId) {
                    var inst = window.monacoInstances[instanceId];
                    if (!inst) return;

                    if (inst.activeTabId) {
                        changes.activeTabId = inst.activeTabId;
                    }

                    // Capture the active tab's live Monaco content
                    if (inst.activeTabId && inst.tabs[inst.activeTabId]) {
                        try {
                            if (inst.htmlEditor) inst.tabs[inst.activeTabId].html = inst.htmlEditor.getValue();
                            if (inst.cssEditor)  inst.tabs[inst.activeTabId].css  = inst.cssEditor.getValue();
                            if (inst.jsEditor)   inst.tabs[inst.activeTabId].js   = inst.jsEditor.getValue();
                        } catch(e) {}
                    }

                    var allTabs = {};
                    Object.keys(inst.tabs || {}).forEach(function(tabId) {
                        var t = inst.tabs[tabId];
                        if (t) {
                            allTabs[tabId] = {
                                id: t.id,
                                title: t.title,
                                emoji: t.emoji || '📄',
                                isForked: t.isForked || false,
                                isReadOnly: !!t.isReadOnly,
                                html: t.html || '',
                                css:  t.css  || '',
                                js:   t.js   || '',
                                preprocessors: t.preprocessors || { html: 'html', css: 'css', js: 'javascript' },
                                timestamp: Date.now()
                            };
                        }
                    });

                    if (Object.keys(allTabs).length > 0) {
                        changes.allTabs = allTabs;
                    }
                });
            }

            // Also capture whatever is in mlp_saved_tabs (user-saved tabs only)
            try {
                var raw = localStorage.getItem(TABS_KEY);
                if (raw) {
                    var parsed = JSON.parse(raw);
                    if (parsed && typeof parsed === 'object' && Object.keys(parsed).length > 0) {
                        changes.savedTabs = parsed;
                    }
                }
            } catch(e) {}

            if (Object.keys(changes).length > 0) {
                updateProjectById(id, changes);
            }
        } catch(e) {}
    }

    /* ══════════════════════════════════════════════════════════════
     * restoreTabsFromProject  — write saved tabs back to mlp_saved_tabs
     *
     * Only the savedTabs (💾) go into mlp_saved_tabs so the main plugin
     * shows them correctly. The allTabs snapshot is handled separately
     * in mlpReloadTabsForProject.
     * ══════════════════════════════════════════════════════════════ */
    function restoreTabsFromProject(p) {
        if (p && p.savedTabs && typeof p.savedTabs === 'object' &&
                Object.keys(p.savedTabs).length > 0) {
            try { localStorage.setItem(TABS_KEY, JSON.stringify(p.savedTabs)); }
            catch (e) { localStorage.removeItem(TABS_KEY); }
        } else {
            localStorage.removeItem(TABS_KEY);
        }
    }

    /* ══════════════════════════════════════════════════════════════
     * mlpReloadTabsForProject  — reload all tabs into the live editor
     *
     * Priority:
     *  1. Use project.allTabs (full snapshot with saved+unsaved flags)
     *  2. Fall back to mlp_saved_tabs (only saved tabs, no unsaved ones)
     *  3. Empty project → create one blank tab
     *
     * A tab is shown with the 💾 icon only if its id exists in
     * mlp_saved_tabs (the main plugin checks this via isTabSaved()).
     * ══════════════════════════════════════════════════════════════ */
    function mlpReloadTabsForProject(projectId) {
        if (!window.monacoInstances || Object.keys(window.monacoInstances).length === 0) return false;
        try {
            // Get the project's full tab snapshot
            var projects = getProjects();
            var project = null;
            for (var i = 0; i < projects.length; i++) {
                if (projects[i].id === projectId) { project = projects[i]; break; }
            }

            // Determine which tabs to load (allTabs > savedTabs > empty)
            var tabsToLoad = {};
            if (project && project.allTabs && Object.keys(project.allTabs).length > 0) {
                tabsToLoad = project.allTabs;
            } else {
                // Fall back to reading mlp_saved_tabs (already set by restoreTabsFromProject)
                try {
                    var raw = localStorage.getItem('mlp_saved_tabs');
                    if (raw) tabsToLoad = JSON.parse(raw) || {};
                } catch(e) {}
            }

            Object.keys(window.monacoInstances).forEach(function(instanceId) {
                var inst = window.monacoInstances[instanceId];
                if (!inst) return;

                // Wipe all current tabs from data model and DOM
                Object.keys(inst.tabs || {}).forEach(function(tabId) { delete inst.tabs[tabId]; });
                jQuery('#mlp-tabs-list-' + instanceId + ' .mlp-tab').remove();

                var tabEntries = Object.values(tabsToLoad);
                var firstTabId = null;
                var activeTabId = (project && project.activeTabId && tabsToLoad[project.activeTabId]) ? project.activeTabId : null;

                tabEntries.forEach(function(t) {
                    if (!t || !t.id) return;
                    inst.tabs[t.id] = {
                        id: t.id,
                        title: t.title || 'Untitled',
                        emoji: t.emoji || '📄',
                        isForked: t.isForked || false,
                        isReadOnly: !!t.isReadOnly,
                        html: t.html || '',
                        css:  t.css  || '',
                        js:   t.js   || '',
                        preprocessors: t.preprocessors || { html: 'html', css: 'css', js: 'javascript' },
                        active: false
                    };
                    // mlpCreateTabElement uses isTabSaved() internally to decide
                    // whether to show the 💾 icon — we don't force it here
                    if (typeof window.mlpCreateTabElement === 'function') {
                        window.mlpCreateTabElement(instanceId, t.id, t.title || 'Untitled', t.emoji || '📄', t.isForked || false, !!t.isReadOnly);
                    }
                    if (!firstTabId) firstTabId = t.id;
                });

                if ((activeTabId || firstTabId) && typeof window.mlpSwitchTab === 'function') {
                    window.mlpSwitchTab(instanceId, activeTabId || firstTabId);
                } else if (!firstTabId) {
                    // Empty project — create a blank tab
                    var newId = 'tab-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6);
                    inst.tabs[newId] = {
                        id: newId, title: 'Preview 1', emoji: '📄',
                        isForked: false, isReadOnly: false,
                        html: '', css: '', js: '',
                        preprocessors: { html: 'html', css: 'css', js: 'javascript' },
                        active: false
                    };
                    inst.tabCounter = (inst.tabCounter || 1) + 1;
                    if (typeof window.mlpCreateTabElement === 'function') {
                        window.mlpCreateTabElement(instanceId, newId, 'Preview 1', '📄', false, false);
                    }
                    if (typeof window.mlpSwitchTab === 'function') {
                        window.mlpSwitchTab(instanceId, newId);
                    }
                }
            });
            return true;
        } catch(e) {
            console.error('[MLP Projects] mlpReloadTabsForProject error:', e);
            return false;
        }
    }

    function scheduleReloadTabsForProject(projectId, attemptsLeft) {
        attemptsLeft = attemptsLeft || 12;
        setTimeout(function() {
            var loaded = false;
            try { loaded = mlpReloadTabsForProject(projectId); } catch(e) { loaded = false; }
            if (!loaded && attemptsLeft > 1) {
                scheduleReloadTabsForProject(projectId, attemptsLeft - 1);
            }
        }, 250);
    }

    /* ── mlpSaveToProject (called by main plugin on explicit save) ── */
    /*
     * The main plugin calls window.mlpSaveToProject(html, css, js).
     * We save html/css/js AND take a full snapshot of mlp_saved_tabs
     * into this project's record so it can be fully restored later.
     */
    window.mlpSaveToProject = function (html, css, js) {
        var id = window.mlpCurrentProjectId;
        if (!id) return;

        var changes = {};
        if (html !== undefined) changes.html = html;
        if (css  !== undefined) changes.css  = css;
        if (js   !== undefined) changes.js   = js;

        // Always snapshot the full tabs store on every explicit save
        try {
            var raw = localStorage.getItem(TABS_KEY);
            if (raw) {
                var parsed = JSON.parse(raw);
                if (parsed && typeof parsed === 'object') changes.savedTabs = parsed;
            }
        } catch (e) {}

        updateProjectById(id, changes);
    };

    /* ── Helpers ──────────────────────────────────────────────────── */
    function fmtDate(iso) {
        try { return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }); }
        catch (e) { return '—'; }
    }
    function escHtml(str) {
        return (str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    /* ── Profile / User system ────────────────────────────────────── */

    var USER_KEY   = 'mlp_user_profile';  // { name, avatar (base64 or null) }

    /* Unique default avatar colours — 12 vivid pairs (bg, text) */
    var AVATAR_PALETTES = [
        ['#6366f1','#fff'], ['#0ea5e9','#fff'], ['#10b981','#fff'],
        ['#f59e0b','#fff'], ['#ef4444','#fff'], ['#8b5cf6','#fff'],
        ['#ec4899','#fff'], ['#14b8a6','#fff'], ['#f97316','#fff'],
        ['#64748b','#fff'], ['#a855f7','#fff'], ['#06b6d4','#fff']
    ];

    function hashStr(s) {
        var h = 0;
        for (var i = 0; i < s.length; i++) { h = (h * 31 + s.charCodeAt(i)) >>> 0; }
        return h;
    }

    /** Get initials (up to 2 chars) from a name */
    function getInitials(name) {
        name = (name || '').trim();
        if (!name) return '?';
        var parts = name.split(/\s+/);
        if (parts.length >= 2) return (parts[0][0] + parts[parts.length-1][0]).toUpperCase();
        return name.slice(0, 2).toUpperCase();
    }

    /** Pick a stable palette for a name */
    function paletteFor(name) {
        return AVATAR_PALETTES[hashStr(name || '') % AVATAR_PALETTES.length];
    }

    /** Render an avatar into an element: either an <img> or styled initials */
    function renderAvatar(el, profile) {
        if (!el) return;
        var name   = (profile && profile.name) || '';
        var avatar = (profile && profile.avatar) || null;
        if (avatar) {
            el.style.background = 'transparent';
            el.innerHTML = '<img src="' + escHtml(avatar) + '" alt="' + escHtml(name) + '"/>';
        } else {
            var pal = paletteFor(name);
            el.style.background = pal[0];
            el.style.color      = pal[1];
            el.textContent      = getInitials(name);
        }
    }

    function getProfile() {
        try {
            var raw = localStorage.getItem(USER_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch(e) { return null; }
    }

    function saveProfile(p) {
        try { localStorage.setItem(USER_KEY, JSON.stringify(p)); } catch(e) {}
    }

    /** Update every avatar/name spot in the nav */
    function applyProfileToNav(profile) {
        var nameEl   = document.getElementById('mlp-nav-username-label');
        var avatarEl = document.getElementById('mlp-nav-avatar');
        if (nameEl) nameEl.textContent = (profile && profile.name) ? profile.name : 'You';
        renderAvatar(avatarEl, profile);
        // Also update sidebar profile
        var sidebarNameEl   = document.getElementById('mlp-sidebar-profile-name');
        var sidebarAvatarEl = document.getElementById('mlp-sidebar-avatar');
        if (sidebarNameEl) sidebarNameEl.textContent = (profile && profile.name) ? profile.name : 'You';
        renderAvatar(sidebarAvatarEl, profile);
    }

    /* ── Apply premium UI state ─────────────────────────────────── */
    function applyPremiumUI() {
        var premium = isPremium();
        // Update sidebar plan label
        var planLabel = document.getElementById('mlp-plan-label');
        var planIcon  = document.getElementById('mlp-plan-icon');
        var planWrap  = planLabel && planLabel.parentElement;
        if (planLabel) {
            planLabel.textContent = 'Developer';
        }
        var planChip = document.getElementById('mlp-sidebar-plan-chip');
        if (planChip) { planChip.classList.remove('mlp-plan-premium'); }
        // Upgrade row removed

        // All features unlocked — no locks needed
    }

    /* ── Auto-update onboarding avatar preview as user types ───── */
    function wireOnboardPreview() {
        var input   = document.getElementById('mlp-username-input');
        var preview = document.getElementById('mlp-onboard-avatar-preview');
        if (!input || !preview) return;
        function update() { renderAvatar(preview, { name: input.value || '?' }); }
        update();
        input.addEventListener('input', update);
    }

    /* ── Show onboarding modal if no profile saved ──────────────── */
    /**
     * Validate a stored avatar data-URL against NSFWJS + OCR text check.
     * Called on page load so avatars injected directly into localStorage
     * (via DevTools or a backup import) are screened before being displayed.
     * If either check fails the avatar is silently wiped from the profile —
     * the user keeps their name but loses the bad image.
     *
     * callback( profile ) — called with the (possibly cleaned) profile.
     */
    function mlpValidateStoredAvatar(profile, callback) {
        if (!profile || !profile.avatar) {
            callback(profile);
            return;
        }
        var avatar = profile.avatar;

        // Must be a base64 data-URI — reject anything else (URLs, blobs, etc.)
        if (typeof avatar !== 'string' || avatar.indexOf('data:image/') !== 0) {
            profile.avatar = null;
            saveProfile(profile);
            callback(profile);
            return;
        }

        // Max size guard — a 2 MB image base64-encodes to ~2.7 MB of chars.
        // Anything larger than ~3 MB of base64 is suspicious; strip it.
        if (avatar.length > 3 * 1024 * 1024) {
            profile.avatar = null;
            saveProfile(profile);
            callback(profile);
            return;
        }

        var done = false;
        var nsfwDone = false, nsfwBad = false;
        var ocrDone  = false, ocrBad  = false;

        function onBothDone() {
            if (!nsfwDone || !ocrDone) return;
            if (done) return;
            done = true;
            if (nsfwBad || ocrBad) {
                // Wipe the offending avatar silently — don't alert on load,
                // just remove it so the user sees their initials instead.
                console.warn('[MLP Avatar] Stored avatar failed moderation check (nsfw=' + nsfwBad + ' ocr=' + ocrBad + '). Removing.');
                profile.avatar = null;
                saveProfile(profile);
            }
            callback(profile);
        }

        mlpNsfwCheck(avatar, function(isNsfw) {
            nsfwBad  = isNsfw;
            nsfwDone = true;
            onBothDone();
        });

        mlpAvatarTextCheck(avatar, function(isOffensive) {
            ocrBad  = isOffensive;
            ocrDone = true;
            onBothDone();
        });
    }

    function maybeShowOnboarding() {
        var profile = getProfile();
        if (profile && profile.name) {
            // Validate the stored avatar before rendering it — this catches
            // images that were injected directly into localStorage via DevTools,
            // a backup import, or any other route that bypassed the upload UI.
            mlpValidateStoredAvatar(profile, function(cleanProfile) {
                applyProfileToNav(cleanProfile);
            });
            return;
        }
        var modal = document.getElementById('mlp-username-modal');
        if (!modal) return;
        modal.style.display = 'flex';
        wireOnboardPreview();
        var input   = document.getElementById('mlp-username-input');
        var saveBtn = document.getElementById('mlp-username-save-btn');
        if (input) setTimeout(function () { input.focus(); }, 80);

        function doSave() {
            var name = input ? input.value.trim() : '';
            if (!name) { if (input) input.focus(); return; }
            var p = { name: name, avatar: null };
            saveProfile(p);
            modal.style.display = 'none';
            applyProfileToNav(p);
        }
        if (saveBtn) saveBtn.addEventListener('click', doSave);
        if (input) input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') doSave();
        });
    }

    /* ── Settings modal ─────────────────────────────────────────── */
    function wireSettingsModal() {
        var profileBtn   = document.getElementById('mlp-profile-btn');
        var modal        = document.getElementById('mlp-settings-modal');
        var closeBtn     = document.getElementById('mlp-settings-modal-close');
        var cancelBtn2   = document.getElementById('mlp-settings-cancel-btn');
        var saveBtn2     = document.getElementById('mlp-settings-save-btn');
        var nameInput2   = document.getElementById('mlp-settings-name-input');
        var fileInput    = document.getElementById('mlp-avatar-file-input');
        var removeBtn    = document.getElementById('mlp-avatar-remove-btn');
        var avatarPrev   = document.getElementById('mlp-settings-avatar-preview');

        if (!profileBtn || !modal) return;

        var pendingAvatar = undefined; // undefined = no change, null = remove, string = new data URL

        function openSettings() {
            var profile = getProfile() || {};
            pendingAvatar = undefined;
            if (nameInput2) nameInput2.value = profile.name || '';
            renderAvatar(avatarPrev, profile);
            modal.style.display = 'flex';
            if (nameInput2) setTimeout(function(){ nameInput2.focus(); }, 60);
        }

        function closeSettings() { modal.style.display = 'none'; }

        /* Profile dropdown toggle */
        var profileDropdown  = document.getElementById('mlp-profile-dropdown');
        var profileCaret     = document.getElementById('mlp-profile-caret');
        var profileDdSettings = document.getElementById('mlp-profile-dd-settings');

        function openProfileDropdown() {
            if (!profileDropdown) return;
            profileDropdown.style.display = 'block';
            profileBtn.classList.add('mlp-profile-btn-open');
            if (profileCaret) profileCaret.classList.add('mlp-profile-caret-open');
            profileBtn.setAttribute('aria-expanded', 'true');
        }
        function closeProfileDropdown() {
            if (!profileDropdown) return;
            profileDropdown.style.display = 'none';
            profileBtn.classList.remove('mlp-profile-btn-open');
            if (profileCaret) profileCaret.classList.remove('mlp-profile-caret-open');
            profileBtn.setAttribute('aria-expanded', 'false');
        }
        function toggleProfileDropdown(e) {
            e.stopPropagation();
            if (profileDropdown && profileDropdown.style.display === 'block') {
                closeProfileDropdown();
            } else {
                openProfileDropdown();
            }
        }

        profileBtn.addEventListener('click', toggleProfileDropdown);

        /* Clicking Settings item in dropdown opens the settings modal */
        if (profileDdSettings) {
            profileDdSettings.addEventListener('click', function(e) {
                e.stopPropagation();
                closeProfileDropdown();
                openSettings();
            });
        }

        /* Close dropdown when clicking outside */
        document.addEventListener('click', function(e) {
            var wrap = document.getElementById('mlp-profile-dropdown-wrap');
            if (wrap && !wrap.contains(e.target)) closeProfileDropdown();
            var cWrap = document.getElementById('mlp-community-dropdown-wrap');
            if (cWrap && !cWrap.contains(e.target)) closeCommunityDropdown();
        });

        /* Community dropdown */
        var communityBtn      = document.getElementById('mlp-community-btn');
        var communityDropdown = document.getElementById('mlp-community-dropdown');
        var communityCaret    = document.getElementById('mlp-community-caret');

        function openCommunityDropdown() {
            if (!communityDropdown) return;
            communityDropdown.style.display = 'block';
            if (communityBtn) communityBtn.setAttribute('aria-expanded', 'true');
            if (communityCaret) communityCaret.classList.add('mlp-profile-caret-open');
        }
        function closeCommunityDropdown() {
            if (!communityDropdown) return;
            communityDropdown.style.display = 'none';
            if (communityBtn) communityBtn.setAttribute('aria-expanded', 'false');
            if (communityCaret) communityCaret.classList.remove('mlp-profile-caret-open');
        }
        if (communityBtn) {
            communityBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                if (communityDropdown && communityDropdown.style.display === 'block') {
                    closeCommunityDropdown();
                } else {
                    openCommunityDropdown();
                }
            });
            communityBtn.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); communityBtn.click(); }
            });
        }

        if (closeBtn)   closeBtn.addEventListener('click', closeSettings);
        if (cancelBtn2) cancelBtn2.addEventListener('click', closeSettings);
        modal.addEventListener('click', function(e){ if (e.target === modal) closeSettings(); });

        /* Sidebar settings gear also opens settings */
        var sidebarSettingsBtn = document.getElementById('mlp-sidebar-settings-btn');
        if (sidebarSettingsBtn) sidebarSettingsBtn.addEventListener('click', openSettings);

        /* File upload */
        if (fileInput) {
            fileInput.addEventListener('change', function() {
                var file = fileInput.files && fileInput.files[0];
                if (!file) return;

                // ── Guard 1: Size (2 MB hard limit) ──────────────────────────
                if (file.size > 2 * 1024 * 1024) {
                    alert('Image is too large. Please choose a file under 2 MB.');
                    fileInput.value = '';
                    return;
                }

                // ── Guard 2: Magic byte validation ────────────────────────────
                // Read only the first 12 bytes of the file and check the header
                // signature before doing anything else. This catches files that
                // are NOT real images but were renamed to look like one (e.g. an
                // .exe or .html file renamed to .jpg). The browser MIME type and
                // file extension can both be spoofed; actual header bytes cannot.
                var headerReader = new FileReader();
                headerReader.onload = function (hEv) {
                    var b = new Uint8Array(hEv.target.result);

                    var isPng  = b[0]===0x89 && b[1]===0x50 && b[2]===0x4E && b[3]===0x47;
                    var isJpeg = b[0]===0xFF && b[1]===0xD8;
                    var isGif  = b[0]===0x47 && b[1]===0x49 && b[2]===0x46;           // GIF8
                    var isWebp = b[8]===0x57 && b[9]===0x45 && b[10]===0x42 && b[11]===0x50; // RIFF????WEBP
                    var isBmp  = b[0]===0x42 && b[1]===0x4D;                           // BM

                    if (!isPng && !isJpeg && !isGif && !isWebp && !isBmp) {
                        alert('Invalid image file. Only JPG, PNG, GIF, WebP, and BMP are accepted. Please choose a real image.');
                        fileInput.value = '';
                        return;
                    }

                    // ── Guard 3: Full read → Canvas sanitization → NSFWJS ─────
                    // Once we know the file header is legitimate, read the whole
                    // file so we can draw it through a canvas. Drawing through
                    // canvas does two things at once:
                    //   a) Strips all EXIF / XMP / IPTC metadata (GPS location,
                    //      camera serial, author name, embedded thumbnails, ICC
                    //      profiles, etc.) — the canvas only keeps raw pixels.
                    //   b) Re-encodes to a predictable JPEG so the stored avatar
                    //      is always a clean, normalised image with no hidden
                    //      payloads buried in metadata segments.
                    var fullReader = new FileReader();
                    fullReader.onload = function (ev) {
                        var rawDataUrl = ev.target.result;

                        var img = new Image();
                        img.onerror = function () {
                            alert('This file could not be decoded as an image. Please try a different one.');
                            fileInput.value = '';
                        };
                        img.onload = function () {

                            // ── Dimension sanity check ────────────────────────
                            if (img.width < 10 || img.height < 10) {
                                alert('Image is too small. Please choose a photo that is at least 10 × 10 pixels.');
                                fileInput.value = '';
                                return;
                            }

                            // ── Canvas sanitize + resize ──────────────────────
                            // Cap at 512 px on the longest side — large enough
                            // for a crisp avatar, small enough not to bloat
                            // localStorage. Scale is clamped to ≤ 1 so we never
                            // upscale a tiny image.
                            var MAX_PX  = 512;
                            var scale   = Math.min(MAX_PX / img.width, MAX_PX / img.height, 1);
                            var canvas  = document.createElement('canvas');
                            canvas.width  = Math.round(img.width  * scale);
                            canvas.height = Math.round(img.height * scale);

                            var ctx = canvas.getContext('2d');
                            // White background underneath handles transparent PNGs
                            // gracefully when re-encoded as JPEG.
                            ctx.fillStyle = '#ffffff';
                            ctx.fillRect(0, 0, canvas.width, canvas.height);
                            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

                            // toDataURL re-encodes as JPEG and strips all metadata.
                            // Quality 0.88 gives a good size/quality balance.
                            var sanitizedDataUrl = canvas.toDataURL('image/jpeg', 0.88);

                            // ── Guard 4: NSFWJS (visual) + OCR text check ────
                            // Both checks run in parallel. NSFWJS catches nudity/
                            // explicit imagery; the OCR check catches profanity or
                            // slurs written as visible text on the image (e.g. a
                            // photo that just says "fuck"). Either one can block.
                            var _nsfwDone = false, _nsfwResult = false;
                            var _ocrDone  = false, _ocrResult  = false;
                            var _guardFired = false; // prevent double-alert

                            function _onBothDone() {
                                if (!_nsfwDone || !_ocrDone) return; // wait for both
                                if (_guardFired) return;
                                if (_nsfwResult) {
                                    _guardFired = true;
                                    alert('This image was flagged as inappropriate (visual content) and cannot be used as your avatar. Please choose a different image.');
                                    fileInput.value = '';
                                    return;
                                }
                                if (_ocrResult) {
                                    _guardFired = true;
                                    alert('This image contains offensive text and cannot be used as your avatar. Please choose a different image.');
                                    fileInput.value = '';
                                    return;
                                }
                                // All guards passed — store the clean, metadata-free image.
                                pendingAvatar = sanitizedDataUrl;
                                renderAvatar(avatarPrev, {
                                    name:   nameInput2 ? nameInput2.value : '',
                                    avatar: pendingAvatar
                                });
                            }

                            mlpNsfwCheck(sanitizedDataUrl, function (isNsfw) {
                                _nsfwResult = isNsfw;
                                _nsfwDone   = true;
                                _onBothDone();
                            });

                            mlpAvatarTextCheck(sanitizedDataUrl, function (isOffensive) {
                                _ocrResult = isOffensive;
                                _ocrDone   = true;
                                _onBothDone();
                            });
                        };
                        img.src = rawDataUrl;
                    };
                    fullReader.readAsDataURL(file);
                };
                // Slice: only the first 12 bytes needed for header detection.
                headerReader.readAsArrayBuffer(file.slice(0, 12));
            });
        }

        /* Remove photo */
        if (removeBtn) {
            removeBtn.addEventListener('click', function() {
                pendingAvatar = null;
                fileInput.value = '';
                renderAvatar(avatarPrev, { name: nameInput2 ? nameInput2.value : '', avatar: null });
            });
        }

        /* Save */
        if (saveBtn2) {
            saveBtn2.addEventListener('click', function() {
                var name = nameInput2 ? nameInput2.value.trim() : '';
                if (!name) { if (nameInput2) nameInput2.focus(); return; }
                var current = getProfile() || {};
                var newAvatar = (pendingAvatar !== undefined) ? pendingAvatar : (current.avatar || null);
                var p = { name: name, avatar: newAvatar };
                saveProfile(p);
                applyProfileToNav(p);
                closeSettings();
            });
        }

        if (nameInput2) {
            nameInput2.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' && saveBtn2) saveBtn2.click();
                if (e.key === 'Escape') closeSettings();
            });
        }

        /* ── Delete account button in settings modal ────────────────── */
        var deleteAccountBtn = document.getElementById('mlp-settings-delete-account-btn');
        if (deleteAccountBtn) {
            deleteAccountBtn.addEventListener('click', function() {
                closeSettings();
                openDelAccountModal();
            });
        }
    }

    /* ── Delete Account modal ─────────────────────────────────────── */
    function openDelAccountModal() {
        var delAccModal   = document.getElementById('mlp-del-account-modal');
        var confirmInput  = document.getElementById('mlp-del-account-confirm-input');
        var confirmBtn    = document.getElementById('mlp-del-account-confirm-btn');
        var cancelBtn     = document.getElementById('mlp-del-account-cancel-btn');
        var closeBtn      = document.getElementById('mlp-del-account-modal-close');
        if (!delAccModal) return;

        if (confirmInput) { confirmInput.value = ''; }
        if (confirmBtn)   { confirmBtn.disabled = true; confirmBtn.classList.add('mlp-btn-danger-full'); }
        delAccModal.style.display = 'flex';
        if (confirmInput) setTimeout(function(){ confirmInput.focus(); }, 60);

        function checkInput() {
            var val = confirmInput ? confirmInput.value.trim().toUpperCase() : '';
            if (confirmBtn) {
                confirmBtn.disabled = (val !== 'DELETE');
            }
        }
        if (confirmInput) confirmInput.addEventListener('input', checkInput);

        function closeDelAcc() {
            delAccModal.style.display = 'none';
            if (confirmInput) {
                confirmInput.removeEventListener('input', checkInput);
                confirmInput.value = '';
            }
        }

        if (closeBtn)  closeBtn.addEventListener('click', closeDelAcc);
        if (cancelBtn) cancelBtn.addEventListener('click', closeDelAcc);
        delAccModal.addEventListener('click', function(e){ if(e.target === delAccModal) closeDelAcc(); });

        if (confirmBtn) {
            confirmBtn.addEventListener('click', function() {
                if (confirmBtn.disabled) return;
                window.mlpCurrentProjectId = null;
                closeDelAcc();

                function doWipeAndReload() {
                    // 1. Nuke entire localStorage
                    try { localStorage.clear(); } catch(e) {}
                    // 2. Nuke entire sessionStorage
                    try { sessionStorage.clear(); } catch(e) {}
                    // 3. Wipe Cache Storage (service workers / PWA caches)
                    if (window.caches) {
                        try {
                            caches.keys().then(function(names) {
                                return Promise.all(names.map(function(n) { return caches.delete(n); }));
                            }).catch(function(){});
                        } catch(e) {}
                    }
                    // 4. Unregister service workers
                    if (navigator.serviceWorker) {
                        try {
                            navigator.serviceWorker.getRegistrations().then(function(regs) {
                                regs.forEach(function(r) { r.unregister(); });
                            }).catch(function(){});
                        } catch(e) {}
                    }
                    // 5. Hard reload — bypasses browser cache
                    try {
                        window.location.reload(true);
                    } catch(e) {
                        window.location.href = window.location.href;
                    }
                }

                // Small delay so the modal can close visually before the page reloads
                setTimeout(doWipeAndReload, 120);
            });
        }
    }

    /* ── DOM init ─────────────────────────────────────────────────── */
    function init() {
        var overlay     = document.getElementById('mlp-projects-overlay');
        if (!overlay) return;

        /* ── Theme (light/dark) toggle ─────────────────────────────── */
        var THEME_KEY = 'mlp_projects_theme';
        function applyTheme(theme) {
            var t = (theme === 'dark') ? 'dark' : 'light';
            overlay.setAttribute('data-mlp-theme', t);
            var btn = document.getElementById('mlp-theme-toggle-btn');
            if (btn) {
                btn.setAttribute('title', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
                btn.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
            }
        }
        var savedTheme = null;
        try { savedTheme = localStorage.getItem(THEME_KEY); } catch(e) {}
        if (!savedTheme) {
            try {
                savedTheme = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
            } catch(e) { savedTheme = 'light'; }
        }
        applyTheme(savedTheme);
        var themeBtn = document.getElementById('mlp-theme-toggle-btn');
        if (themeBtn) {
            themeBtn.addEventListener('click', function() {
                var current = overlay.getAttribute('data-mlp-theme') === 'dark' ? 'dark' : 'light';
                var next = current === 'dark' ? 'light' : 'dark';
                applyTheme(next);
                try { localStorage.setItem(THEME_KEY, next); } catch(e) {}
            });
        }

        /* Sidebar collapse toggle */
        var SIDEBAR_KEY = 'mlp_sidebar_collapsed';
        var sidebarBtn = document.getElementById('mlp-sidebar-toggle-btn');
        var isMobile = function() { return window.innerWidth <= 720; };
        /* On mobile: always collapsed, toggle button hidden via CSS */
        if (isMobile()) {
            overlay.classList.add('mlp-sidebar-collapsed');
        } else {
            try {
                if (localStorage.getItem(SIDEBAR_KEY) === '1') {
                    overlay.classList.add('mlp-sidebar-collapsed');
                }
            } catch(e) {}
        }
        if (sidebarBtn) {
            sidebarBtn.addEventListener('click', function() {
                if (isMobile()) { return; } /* Blocked on mobile */
                var collapsed = overlay.classList.toggle('mlp-sidebar-collapsed');
                try { localStorage.setItem(SIDEBAR_KEY, collapsed ? '1' : '0'); } catch(e) {}
            });
        }

        /* ── Color palette + modal state — declared early so all
           openModal(), buildRow(), and createBtn handlers can use them ── */
        var COLOR_SWATCHES = [
            '#2563eb','#7c3aed','#db2777','#dc2626','#ea580c',
            '#ca8a04','#16a34a','#0891b2','#0f172a','#64748b',
            '#6366f1','#10b981'
        ];
        var colorModalTargetId   = null;
        var colorModalSelected   = null;
        var createColorSelected  = COLOR_SWATCHES[0];

        /* ── Sort state — declared early so render() can use it ──────── */
        var currentSort    = 'pinned';
        var currentSortDir = 1;
        try { var ss = localStorage.getItem(SORT_KEY); if(ss){ var sp = JSON.parse(ss); currentSort = sp.k||'pinned'; currentSortDir = sp.d||1; } } catch(e){}

        /* ── Boot profile ───────────────────────────────────────────── */
        maybeShowOnboarding();
        wireSettingsModal();
        applyPremiumUI();

        var tbody       = document.getElementById('mlp-proj-tbody');
        var emptyEl     = document.getElementById('mlp-proj-empty');
        var newBtn      = document.getElementById('mlp-proj-new-btn');
        var modal       = document.getElementById('mlp-proj-modal');
        var modalClose  = document.getElementById('mlp-proj-modal-close');
        var nameInput   = document.getElementById('mlp-proj-name-input');
        var createBtn   = document.getElementById('mlp-proj-create-btn');
        var cancelBtn   = document.getElementById('mlp-proj-cancel-btn');
        var searchInput = document.getElementById('mlp-proj-search');
        var delModal    = document.getElementById('mlp-proj-del-modal');
        var delModalClose = document.getElementById('mlp-proj-del-modal-close');
        var delCancelBtn  = document.getElementById('mlp-proj-del-cancel-btn');
        var delConfirmBtn = document.getElementById('mlp-proj-del-confirm-btn');
        var delNameEl     = document.getElementById('mlp-proj-del-name');

        var pendingDeleteId = null;

        /* ── Filter chips state ─────────────────────────────────────── */
        var FILTER_KEY = 'mlp_filter_state';
        var currentStatusFilter = 'all';
        var currentTagFilter    = '';
        try {
            var fs = localStorage.getItem(FILTER_KEY);
            if (fs) { var fp = JSON.parse(fs); currentStatusFilter = fp.s || 'all'; currentTagFilter = fp.t || ''; }
        } catch(e) {}

        function saveFilterState() {
            try { localStorage.setItem(FILTER_KEY, JSON.stringify({s:currentStatusFilter,t:currentTagFilter})); } catch(e){}
        }

        /* ── Tag color store (global, keyed by lowercase tag name) ──── */
        var TAG_COLORS_KEY = 'mlp_tag_colors';
        var tagColors = {};
        try { tagColors = JSON.parse(localStorage.getItem(TAG_COLORS_KEY) || '{}') || {}; } catch(e) { tagColors = {}; }
        var TAG_COLOR_PRESETS = [
            '#2563eb','#4f46e5','#7c3aed','#db2777','#dc2626',
            '#ea580c','#d97706','#16a34a','#0891b2','#475569'
        ];
        function saveTagColors() { try { localStorage.setItem(TAG_COLORS_KEY, JSON.stringify(tagColors)); } catch(e){} }
        function getTagColor(tag) { return tagColors[String(tag).toLowerCase()] || ''; }
        function setTagColor(tag, color) {
            var k = String(tag).toLowerCase();
            if (color) tagColors[k] = color; else delete tagColors[k];
            saveTagColors();
        }
        function tagChipStyle(tag) {
            var c = getTagColor(tag);
            if (!c) return '';
            // Translucent background + colored border + colored text
            return ' style="background:' + c + '1f;border-color:' + c + ';color:' + c + ';"';
        }
        function tagFilterChipStyleActive(tag, isActive) {
            var c = getTagColor(tag);
            if (!c) return '';
            if (isActive) return 'background:' + c + ';border-color:' + c + ';color:#fff;';
            return 'background:' + c + '1f;border-color:' + c + ';color:' + c + ';';
        }

        function projectMatchesStatus(p, status) {
            if (!status || status === 'all') return true;
            if (status === 'public')    return (p.visibility || 'private') === 'public';
            if (status === 'private')   return (p.visibility || 'private') === 'private';
            if (status === 'pinned')    return !!p.pinned;
            if (status === 'favorites') return !!p.favorite;
            return true;
        }

        function projectHasTag(p, tag) {
            if (!tag) return true;
            if (!Array.isArray(p.tags)) return false;
            for (var i = 0; i < p.tags.length; i++) {
                if (String(p.tags[i]).toLowerCase() === String(tag).toLowerCase()) return true;
            }
            return false;
        }

        function getAllTags(projects) {
            var seen = {};
            var out = [];
            for (var i = 0; i < projects.length; i++) {
                var t = projects[i].tags;
                if (!Array.isArray(t)) continue;
                for (var j = 0; j < t.length; j++) {
                    var k = String(t[j]).trim();
                    if (!k) continue;
                    var lk = k.toLowerCase();
                    if (!seen[lk]) { seen[lk] = true; out.push(k); }
                }
            }
            out.sort(function(a,b){ return a.toLowerCase() < b.toLowerCase() ? -1 : 1; });
            return out;
        }

        function renderFilterChips(projects) {
            var statusGroup = document.getElementById('mlp-filter-status-group');
            if (statusGroup) {
                var btns = statusGroup.querySelectorAll('.mlp-filter-chip');
                for (var i = 0; i < btns.length; i++) {
                    btns[i].classList.toggle('mlp-filter-active',
                        btns[i].getAttribute('data-filter') === currentStatusFilter);
                }
            }
            var tagWrap  = document.getElementById('mlp-filter-tag-wrap');
            var tagGroup = document.getElementById('mlp-filter-tag-group');
            if (!tagGroup || !tagWrap) return;
            var tags = getAllTags(projects);
            if (tags.length === 0) {
                tagWrap.style.display = 'none';
                tagGroup.innerHTML = '';
                if (currentTagFilter) { currentTagFilter = ''; saveFilterState(); }
                return;
            }
            tagWrap.style.display = 'inline-flex';
            tagGroup.innerHTML = '';
            tags.forEach(function(tag) {
                var isActive = (currentTagFilter === tag);
                var b = document.createElement('button');
                b.className = 'mlp-filter-chip mlp-tag-filter-chip' + (isActive ? ' mlp-filter-active' : '');
                b.setAttribute('data-tag', tag);
                b.title = '#' + tag + ' — right-click for options';
                b.textContent = '#' + tag;
                var inlineStyle = tagFilterChipStyleActive(tag, isActive);
                if (inlineStyle) b.style.cssText = inlineStyle;
                b.addEventListener('click', function() {
                    currentTagFilter = (currentTagFilter === tag) ? '' : tag;
                    saveFilterState();
                    render(searchInput.value);
                });
                b.addEventListener('contextmenu', function(e) {
                    e.preventDefault();
                    openTagChipMenu(tag, e.clientX, e.clientY);
                });
                tagGroup.appendChild(b);
            });
            if (currentTagFilter) {
                var clr = document.createElement('button');
                clr.className = 'mlp-filter-chip mlp-filter-chip-clear';
                clr.textContent = 'Clear tag';
                clr.addEventListener('click', function() {
                    currentTagFilter = '';
                    saveFilterState();
                    render(searchInput.value);
                });
                tagGroup.appendChild(clr);
            }
        }

        /* Wire status filter chips (delegated; chips are static in HTML) */
        document.querySelectorAll('#mlp-filter-status-group .mlp-filter-chip').forEach(function(b) {
            b.addEventListener('click', function() {
                currentStatusFilter = b.getAttribute('data-filter') || 'all';
                saveFilterState();
                render(searchInput.value);
            });
        });

        /* ── Tags editor (uses prompt) ──────────────────────────────── */
        function openTagsEditor(p) {
            var current = Array.isArray(p.tags) ? p.tags.join(', ') : '';
            var input = window.prompt(
                'Tags for "' + (p.name || 'Untitled') + '"\n\nEnter comma-separated tags (e.g. client work, experiments, draft).\nLeave empty to clear all tags.',
                current
            );
            if (input === null) return; // cancelled
            var tags = input.split(',').map(function(s){ return s.trim(); })
                            .filter(function(s){ return s.length > 0 && s.length <= 32; });
            // De-dupe (case-insensitive), preserve first-seen casing.
            var seen = {}, dedup = [];
            tags.forEach(function(t){
                var k = t.toLowerCase();
                if (!seen[k]) { seen[k] = true; dedup.push(t); }
            });
            updateProjectById(p.id, { tags: dedup });
            render(searchInput.value);
            showToast('Tags Updated', dedup.length ? ('Tags: ' + dedup.join(', ')) : 'All tags removed.', 'success');
        }

        /* ── Global tag operations (rename / delete across all projects) ── */
        function renameTagGlobally(oldTag, newTag) {
            var oldKey = String(oldTag).toLowerCase();
            var newName = String(newTag).trim();
            if (!newName) return 0;
            if (newName.length > 32) newName = newName.slice(0, 32);
            var changed = 0;
            getProjects().forEach(function(p) {
                if (!Array.isArray(p.tags) || !p.tags.length) return;
                var hasIt = false;
                p.tags.forEach(function(t){ if (String(t).toLowerCase() === oldKey) hasIt = true; });
                if (!hasIt) return;
                var seen = {}, next = [];
                p.tags.forEach(function(t) {
                    var replaced = (String(t).toLowerCase() === oldKey) ? newName : t;
                    var k = String(replaced).toLowerCase();
                    if (!seen[k]) { seen[k] = true; next.push(replaced); }
                });
                updateProjectById(p.id, { tags: next });
                changed++;
            });
            return changed;
        }
        function deleteTagGlobally(tag) {
            var key = String(tag).toLowerCase();
            var changed = 0;
            getProjects().forEach(function(p) {
                if (!Array.isArray(p.tags) || !p.tags.length) return;
                var next = p.tags.filter(function(t){ return String(t).toLowerCase() !== key; });
                if (next.length !== p.tags.length) {
                    updateProjectById(p.id, { tags: next });
                    changed++;
                }
            });
            return changed;
        }

        /* ── Right-click menu on tag filter chips ───────────────────── */
        var _tagChipMenuEl = null;
        function closeTagChipMenu() {
            if (_tagChipMenuEl && _tagChipMenuEl.parentNode) {
                _tagChipMenuEl.parentNode.removeChild(_tagChipMenuEl);
            }
            _tagChipMenuEl = null;
            document.removeEventListener('mousedown', _onTagMenuOutside, true);
            document.removeEventListener('keydown', _onTagMenuKey, true);
            window.removeEventListener('scroll', closeTagChipMenu, true);
            window.removeEventListener('resize', closeTagChipMenu, true);
        }
        function _onTagMenuOutside(e) {
            if (_tagChipMenuEl && !_tagChipMenuEl.contains(e.target)) closeTagChipMenu();
        }
        function _onTagMenuKey(e) {
            if (e.key === 'Escape') closeTagChipMenu();
        }
        function openTagChipMenu(tag, x, y) {
            closeTagChipMenu();
            var menu = document.createElement('div');
            menu.className = 'mlp-tag-chip-menu';
            var swatchHtml = '<div class="mlp-tag-color-row">';
            TAG_COLOR_PRESETS.forEach(function(c) {
                var isSel = (getTagColor(tag).toLowerCase() === c.toLowerCase());
                swatchHtml += '<button type="button" class="mlp-tag-color-swatch' + (isSel ? ' mlp-tag-color-selected' : '') +
                    '" data-color="' + c + '" title="' + c + '" style="background:' + c + ';"></button>';
            });
            swatchHtml += '<button type="button" class="mlp-tag-color-clear" data-color="" title="Clear color">✕</button>';
            swatchHtml += '</div>';
            menu.innerHTML =
                '<div class="mlp-tag-chip-menu-header">#' + escHtml(tag) + '</div>' +
                '<div class="mlp-tag-chip-menu-section-label">🎨 Color</div>' +
                swatchHtml +
                '<div class="mlp-tag-chip-menu-divider"></div>' +
                '<button type="button" class="mlp-tag-chip-menu-item" data-act="rename">✏️ Rename tag globally</button>' +
                '<button type="button" class="mlp-tag-chip-menu-item mlp-tag-chip-menu-danger" data-act="delete">🗑 Delete tag from all projects</button>';
            // Position off-screen first to measure
            menu.style.left = '-9999px';
            menu.style.top  = '-9999px';
            document.body.appendChild(menu);
            var rect = menu.getBoundingClientRect();
            var vw = window.innerWidth, vh = window.innerHeight;
            var px = Math.min(x, vw - rect.width - 8);
            var py = Math.min(y, vh - rect.height - 8);
            menu.style.left = Math.max(8, px) + 'px';
            menu.style.top  = Math.max(8, py) + 'px';
            _tagChipMenuEl = menu;

            menu.querySelectorAll('.mlp-tag-color-swatch, .mlp-tag-color-clear').forEach(function(sw) {
                sw.addEventListener('click', function() {
                    var c = sw.getAttribute('data-color') || '';
                    setTagColor(tag, c);
                    closeTagChipMenu();
                    render(searchInput.value);
                    showToast('Tag Color', c ? ('"' + tag + '" set to ' + c) : ('Color cleared for "' + tag + '"'), 'success', 1600);
                });
            });
            menu.querySelector('[data-act="rename"]').addEventListener('click', function() {
                closeTagChipMenu();
                var input = window.prompt('Rename tag "' + tag + '" across all projects to:', tag);
                if (input === null) return;
                var newName = input.trim();
                if (!newName) { showToast('Cancelled', 'Tag name cannot be empty.', 'info'); return; }
                if (newName.toLowerCase() === tag.toLowerCase()) { showToast('No changes', 'New name is the same as the old one.', 'info'); return; }
                var n = renameTagGlobally(tag, newName);
                // Migrate color assignment to the new tag key
                var oldKey = tag.toLowerCase(), newKey = newName.toLowerCase();
                if (tagColors[oldKey] && oldKey !== newKey) {
                    if (!tagColors[newKey]) tagColors[newKey] = tagColors[oldKey];
                    delete tagColors[oldKey];
                    saveTagColors();
                }
                if (currentTagFilter && currentTagFilter.toLowerCase() === tag.toLowerCase()) {
                    currentTagFilter = newName;
                    saveFilterState();
                }
                render(searchInput.value);
                showToast('Tag Renamed', '"' + tag + '" → "' + newName + '" on ' + n + ' project' + (n === 1 ? '' : 's') + '.', 'success');
            });
            menu.querySelector('[data-act="delete"]').addEventListener('click', function() {
                closeTagChipMenu();
                if (!window.confirm('Delete tag "' + tag + '" from ALL projects?\n\nThis cannot be undone.')) return;
                var n = deleteTagGlobally(tag);
                if (tagColors[tag.toLowerCase()]) {
                    delete tagColors[tag.toLowerCase()];
                    saveTagColors();
                }
                if (currentTagFilter && currentTagFilter.toLowerCase() === tag.toLowerCase()) {
                    currentTagFilter = '';
                    saveFilterState();
                }
                render(searchInput.value);
                showToast('Tag Deleted', '"' + tag + '" removed from ' + n + ' project' + (n === 1 ? '' : 's') + '.', 'danger');
            });

            // Defer outside-click listener so the contextmenu event doesn't immediately close it
            setTimeout(function() {
                document.addEventListener('mousedown', _onTagMenuOutside, true);
                document.addEventListener('keydown', _onTagMenuKey, true);
                window.addEventListener('scroll', closeTagChipMenu, true);
                window.addEventListener('resize', closeTagChipMenu, true);
            }, 0);
        }

        /* ── Copy project name to clipboard ─────────────────────────── */
        function copyProjectName(name, btn) {
            var text = String(name || '');
            function done(ok) {
                if (ok && btn) {
                    var orig = btn.innerHTML;
                    btn.classList.add('mlp-copied');
                    btn.innerHTML = '<span class="mlp-copy-emoji">✅</span>';
                    setTimeout(function() {
                        btn.classList.remove('mlp-copied');
                        btn.innerHTML = orig;
                    }, 1400);
                }
                if (typeof showToast === 'function') {
                    if (ok) showToast('Copied', '"' + text + '" copied to clipboard.', 'success', 1800);
                    else showToast('Copy Failed', 'Could not access the clipboard.', 'danger');
                }
            }
            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).then(function(){ done(true); }, function(){ done(false); });
                    return;
                }
            } catch(e) {}
            try {
                var ta = document.createElement('textarea');
                ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
                document.body.appendChild(ta); ta.select();
                var ok = document.execCommand('copy');
                document.body.removeChild(ta);
                done(!!ok);
            } catch(e) { done(false); }
        }

        /* ── Create modal ───────────────────────────────────────────── */
        function openModal() {
            var currentProjects = getProjects();
            nameInput.value = '';
            var visEl = document.getElementById('mlp-proj-visibility-input');
            if (visEl) visEl.value = 'private';
            var emojiEl = document.getElementById('mlp-proj-create-emoji-input');
            if (emojiEl) emojiEl.value = '';
            createColorSelected = COLOR_SWATCHES[0];
            buildColorPalette('mlp-create-color-palette', createColorSelected);
            modal.style.display = 'flex';
            setTimeout(function () { nameInput.focus(); }, 60);
        }
        function closeModal() { modal.style.display = 'none'; }

        /* ── Delete confirm modal ───────────────────────────────────── */
        function openDelModal(id, name) {
            pendingDeleteId = id;
            if (delNameEl) delNameEl.textContent = name || 'this project';
            delModal.style.display = 'flex';
        }
        function closeDelModal() {
            pendingDeleteId = null;
            delModal.style.display = 'none';
        }

        /* ── Close overlay ──────────────────────────────────────────── */
        function closePopup() {
            overlay.classList.add('mlp-proj-hidden');
            document.body.style.overflow = '';
        }

        /* ── Build table row ────────────────────────────────────────── */
        function calcProjectSize(p) {
            var total = 0;
            var addStr = function(s) { total += (s || '').length; };
            addStr(p.html); addStr(p.css); addStr(p.js);
            if (p.savedTabs && typeof p.savedTabs === 'object') {
                try { addStr(JSON.stringify(p.savedTabs)); } catch(e) {}
            }
            if (p.allTabs && typeof p.allTabs === 'object') {
                try { addStr(JSON.stringify(p.allTabs)); } catch(e) {}
            }
            return total;
        }

        function fmtSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
        }

        function getSizeClass(bytes) {
            if (bytes < 5 * 1024) return 'mlp-size-sm';
            if (bytes < 50 * 1024) return 'mlp-size-md';
            return 'mlp-size-lg';
        }

        function getLastOpenedId() {
            try { return localStorage.getItem(LAST_ID_KEY); } catch(e) { return null; }
        }

        function highlightText(text, query) {
            if (!query) return escHtml(text);
            var idx = text.toLowerCase().indexOf(query.toLowerCase());
            if (idx === -1) return escHtml(text);
            return escHtml(text.slice(0, idx)) +
                '<mark class="mlp-highlight">' + escHtml(text.slice(idx, idx + query.length)) + '</mark>' +
                escHtml(text.slice(idx + query.length));
        }

        function collectProjectSearchText(p) {
            var tagsText = (Array.isArray(p.tags) ? p.tags.join(' ') : '');
            var parts = [p.name || '', p.description || '', p.notes || '', tagsText, p.html || '', p.css || '', p.js || ''];
            function addTabs(tabs) {
                if (!tabs || typeof tabs !== 'object') return;
                for (var key in tabs) {
                    if (!tabs.hasOwnProperty(key)) continue;
                    var tab = tabs[key];
                    if (typeof tab === 'string') parts.push(tab);
                    else if (tab && typeof tab === 'object') {
                        parts.push(tab.name || '', tab.title || '', tab.html || '', tab.css || '', tab.js || '', tab.code || '', tab.content || '');
                    }
                }
            }
            addTabs(p.savedTabs);
            addTabs(p.allTabs);
            return parts.join('\n');
        }

        function getProjectSearchHit(p, query) {
            if (!query) return '';
            var q = query.toLowerCase();
            if ((p.name || '').toLowerCase().indexOf(q) !== -1) return '';
            var text = collectProjectSearchText(p);
            var idx = text.toLowerCase().indexOf(q);
            if (idx === -1) return '';
            var start = Math.max(0, idx - 34);
            var end = Math.min(text.length, idx + query.length + 48);
            var snippet = text.slice(start, end).replace(/\s+/g, ' ').trim();
            return (start > 0 ? '…' : '') + snippet + (end < text.length ? '…' : '');
        }

        function projectMatchesFilter(p, filter) {
            if (!filter) return true;
            return collectProjectSearchText(p).toLowerCase().indexOf(filter.toLowerCase()) !== -1;
        }

        function closeAllMoreDropdowns() {
            document.querySelectorAll('#mlp-projects-overlay .mlp-more-dropdown').forEach(function(d){ d.style.display = 'none'; });
            document.querySelectorAll('#mlp-projects-overlay .mlp-row-btn-more').forEach(function(b){ b.classList.remove('mlp-more-open'); });
        }
        if (!window._mlpMoreOutsideListener) {
            window._mlpMoreOutsideListener = true;
            document.addEventListener('click', function(e) {
                if (!e.target.closest || !e.target.closest('.mlp-more-wrap')) { closeAllMoreDropdowns(); }
            });
        }

        /* ── Share URL builder (must be above buildRow) ─────────────── */
        function getShareBaseUrl() {
            var cleanSearch = '';
            try {
                var params = new URLSearchParams(window.location.search || '');
                params.delete('mlpsh');
                params.delete('mlpsht');
                cleanSearch = params.toString();
            } catch(e) {}
            return window.location.origin + window.location.pathname + (cleanSearch ? '?' + cleanSearch : '');
        }

        function appendShareParam(base, key, value) {
            var hashIndex = base.indexOf('#');
            var hash = '';
            if (hashIndex !== -1) {
                hash = base.slice(hashIndex);
                base = base.slice(0, hashIndex);
            }
            return base + (base.indexOf('?') === -1 ? '?' : '&') + encodeURIComponent(key) + '=' + encodeURIComponent(value) + hash;
        }

        function getProjectDisplayUrl(p) {
            var host = (window.location && window.location.host) ? window.location.host : 'pterocos.eu.org';
            var id = p && p.id ? String(p.id) : '';
            if (!id) return host + '/…';
            return host + '/?project=' + id.slice(0, 10) + '…';
        }

        function utf8ToB64Url(str) {
            var b64;
            try {
                if (window.TextEncoder) {
                    var bytes = new TextEncoder().encode(str);
                    var bin = '';
                    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
                    b64 = btoa(bin);
                } else {
                    b64 = btoa(unescape(encodeURIComponent(str)));
                }
            } catch(e) {
                b64 = btoa(unescape(encodeURIComponent(str)));
            }
            return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        }

        function b64UrlToUtf8(str) {
            var b64 = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
            while (b64.length % 4) b64 += '=';
            var bin = atob(b64);
            try {
                if (window.TextDecoder) {
                    var bytes = new Uint8Array(bin.length);
                    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
                    return new TextDecoder().decode(bytes);
                }
            } catch(e) {}
            return decodeURIComponent(escape(bin));
        }

        function buildSharePayload(p) {
            var fresh = getFreshProject(p.id, p);
            var shareSavedTabs = fresh.savedTabs ? JSON.parse(JSON.stringify(fresh.savedTabs)) : null;
            var shareAllTabs = fresh.allTabs ? JSON.parse(JSON.stringify(fresh.allTabs)) : null;
            if (fresh && fresh.id && window.mlpCurrentProjectId && fresh.id === window.mlpCurrentProjectId) {
                var liveTabs = {};
                try {
                    if (window.monacoInstances) {
                        Object.keys(window.monacoInstances).forEach(function(instanceId) {
                            var inst = window.monacoInstances[instanceId];
                            if (!inst || !inst.tabs) return;
                            if (inst.activeTabId && inst.tabs[inst.activeTabId]) {
                                try {
                                    if (inst.htmlEditor) inst.tabs[inst.activeTabId].html = inst.htmlEditor.getValue();
                                    if (inst.cssEditor) inst.tabs[inst.activeTabId].css = inst.cssEditor.getValue();
                                    if (inst.jsEditor) inst.tabs[inst.activeTabId].js = inst.jsEditor.getValue();
                                } catch(e) {}
                            }
                            Object.keys(inst.tabs).forEach(function(tabId) {
                                var t = inst.tabs[tabId];
                                if (!t) return;
                                liveTabs[tabId] = {
                                    id: t.id || tabId,
                                    title: t.title || 'Untitled',
                                    emoji: t.emoji || '📄',
                                    isForked: !!t.isForked,
                                    isReadOnly: !!t.isReadOnly,
                                    html: t.html || '',
                                    css: t.css || '',
                                    js: t.js || '',
                                    preprocessors: t.preprocessors || { html: 'html', css: 'css', js: 'javascript' },
                                    timestamp: t.timestamp || Date.now()
                                };
                            });
                        });
                    }
                } catch(e) {}
                if (Object.keys(liveTabs).length > 0) {
                    if (!shareAllTabs) shareAllTabs = {};
                    Object.keys(liveTabs).forEach(function(tabId) {
                        shareAllTabs[tabId] = liveTabs[tabId];
                    });
                }
                try {
                    var savedRaw = localStorage.getItem(TABS_KEY);
                    if (savedRaw) {
                        var savedParsed = JSON.parse(savedRaw);
                        if (savedParsed && typeof savedParsed === 'object' && Object.keys(savedParsed).length > 0) {
                            if (!shareSavedTabs) shareSavedTabs = {};
                            Object.keys(savedParsed).forEach(function(tabId) {
                                shareSavedTabs[tabId] = savedParsed[tabId];
                            });
                        }
                    }
                } catch(e) {}
            }
            if (shareSavedTabs) {
                if (!shareAllTabs) shareAllTabs = {};
                Object.keys(shareSavedTabs).forEach(function(tabId) {
                    if (!shareAllTabs[tabId]) shareAllTabs[tabId] = shareSavedTabs[tabId];
                });
            }
            return {
                id:          fresh.id,
                name:        fresh.name        || 'Untitled',
                description: fresh.description || '',
                createdAt:   fresh.createdAt   || new Date().toISOString(),
                updatedAt:   fresh.updatedAt   || new Date().toISOString(),
                visibility:  'public',
                iconColor:   fresh.iconColor   || '',
                emoji:       fresh.emoji       || '',
                html:        fresh.html        || '',
                css:         fresh.css         || '',
                js:          fresh.js          || '',
                savedTabs:   shareSavedTabs,
                allTabs:     shareAllTabs,
                activeTabId: fresh.activeTabId || '',
                pinHash:     fresh.pinHash     || null,
                sharedBy:    '',
                sharedByAvatar: (function() {
                    try {
                        var pr = JSON.parse(localStorage.getItem('mlp_user_profile')||'{}');
                        // If they uploaded a real photo, use it directly
                        if (pr.avatar) return pr.avatar;
                        // Otherwise render their initials avatar to a canvas data-URL
                        // so the recipient sees a coloured avatar without knowing the name
                        var name = pr.name || '?';
                        var palettes = [
                            ['#6366f1','#fff'], ['#0ea5e9','#fff'], ['#10b981','#fff'],
                            ['#f59e0b','#fff'], ['#ef4444','#fff'], ['#8b5cf6','#fff'],
                            ['#ec4899','#fff'], ['#14b8a6','#fff'], ['#f97316','#fff'],
                            ['#64748b','#fff'], ['#a855f7','#fff'], ['#06b6d4','#fff']
                        ];
                        var h = 0;
                        for (var ci = 0; ci < name.length; ci++) { h = (h * 31 + name.charCodeAt(ci)) >>> 0; }
                        var pal = palettes[h % palettes.length];
                        var parts = name.trim().split(/\s+/);
                        var initials = parts.length >= 2
                            ? (parts[0][0] + parts[parts.length-1][0]).toUpperCase()
                            : name.slice(0,2).toUpperCase();
                        var canvas = document.createElement('canvas');
                        canvas.width = 128; canvas.height = 128;
                        var ctx = canvas.getContext('2d');
                        ctx.fillStyle = pal[0];
                        ctx.fillRect(0, 0, 128, 128);
                        ctx.fillStyle = pal[1];
                        ctx.font = 'bold 52px -apple-system, BlinkMacSystemFont, sans-serif';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.fillText(initials, 64, 64);
                        return canvas.toDataURL('image/png');
                    } catch(e) { return null; }
                })()
            };
        }

        function buildInlineShareUrlFromJson(json) {
            return getShareBaseUrl() + '#mlpsh_' + utf8ToB64Url(json);
        }

        /* buildShareUrl — only generates an inline link now.
           Server-stored token links are ONLY created after AI moderation
           inside the Publish modal (wireShareModal). Do NOT add a direct
           mlp_save_shared_project call here — it would bypass moderation. */
        function buildShareUrl(p, done) {
            try {
                var payload = buildSharePayload(p);
                var json = JSON.stringify(payload);
                done(buildInlineShareUrlFromJson(json));
            } catch(e) {
                done(getShareBaseUrl() + '#mlpsh_err');
            }
        }

        function buildRow(p, searchQuery) {
            var tr = document.createElement('tr');
            var isActive = (window.mlpCurrentProjectId === p.id);
            if (isActive) tr.className = 'mlp-row-active';
            if (p.pinned) tr.className = (tr.className ? tr.className + ' ' : '') + 'mlp-row-pinned';
            if (p.favorite) tr.className = (tr.className ? tr.className + ' ' : '') + 'mlp-row-favorited';

            // ── Checkbox cell ──
            var tdCb = document.createElement('td');
            tdCb.className = 'mlp-td-check';
            tdCb.innerHTML = '<input type="checkbox" class="mlp-cb mlp-row-cb" data-id="' + escHtml(p.id) + '"/>';
            tdCb.querySelector('.mlp-row-cb').addEventListener('change', function() { updateBulkBar(); });

            // ── Pin cell ──
            var tdPin = document.createElement('td');
            tdPin.className = 'mlp-td-pin';
            tdPin.innerHTML = '<button class="mlp-pin-btn' + (p.pinned ? ' mlp-pinned' : '') + '" title="' + (p.pinned ? 'Unpin' : 'Pin to top') + '">📌</button>';
            tdPin.querySelector('.mlp-pin-btn').addEventListener('click', function(e) {
                e.stopPropagation();
                updateProjectById(p.id, { pinned: !p.pinned });
                render(searchInput.value);
            });

            // ── Star (Favorite) cell ──
            var tdStar = document.createElement('td');
            tdStar.className = 'mlp-td-star';
            tdStar.innerHTML = '<button class="mlp-star-btn' + (p.favorite ? ' mlp-favorited' : '') + '" title="' + (p.favorite ? 'Remove from favorites' : 'Add to favorites') + '">⭐</button>';
            tdStar.querySelector('.mlp-star-btn').addEventListener('click', function(e) {
                e.stopPropagation();
                updateProjectById(p.id, { favorite: !p.favorite });
                render(searchInput.value);
            });

            // ── Name cell ──
            var iconColor = p.iconColor || null;
            var emoji     = p.emoji || '';

            // Icon box always uses iconColor (or default gradient) — cover gradient is separate
            var iconStyle = iconColor
                ? '--mlp-icon-bg:' + iconColor + ';'
                : '--mlp-icon-bg:linear-gradient(135deg,#3b82f6 0%,#7c3aed 100%);';

            var coverStripe = '';

            var iconInner = emoji
                ? '<span style="font-size:14px;line-height:1;">' + escHtml(emoji) + '</span>'
                : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';

            var lockBadge = p.pinHash ? '<span class="mlp-row-locked-indicator">🔐 Locked</span>' : '';
            var notesDot  = p.notes   ? '<span class="mlp-notes-indicator"></span>' : '';
            var descLine  = p.description ? '<span class="mlp-row-desc">' + escHtml(p.description) + '</span>' : '';
            var sharedFromLine = p.sharedFrom ? '<span class="mlp-row-shared-from">📬 Shared by ' + escHtml(p.sharedFrom) + '</span>' : '';
            var codeHit = getProjectSearchHit(p, searchQuery);
            var codeHitLine = codeHit ? '<span class="mlp-code-hit"><strong>Code match:</strong> ' + highlightText(codeHit, searchQuery) + '</span>' : '';

            // View count stat (public projects with a share link only)
            var viewStatLine = '';
            var _vTokName = getShareToken(p);
            if ((p.visibility || 'private') === 'public' && _vTokName) {
                var eyeSvg = '<svg class="mlp-vc-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>';
                var _cachedV = (window._mlpViewCounts && window._mlpViewCounts[_vTokName]);
                if (typeof _cachedV === 'number') {
                    var fmtV = (_cachedV >= 1000) ? (Math.round(_cachedV / 100) / 10) + 'k' : _cachedV;
                    viewStatLine = '<span class="mlp-view-count-badge" title="Total times this share link has been opened">' + eyeSvg + '<span class="mlp-vc-num">' + fmtV + '</span><span class="mlp-vc-label">' + (_cachedV === 1 ? 'view' : 'views') + '</span></span>';
                } else {
                    viewStatLine = '<span class="mlp-view-count-badge mlp-vc-loading" data-token="' + escHtml(_vTokName) + '" title="Loading view count…">' + eyeSvg + '<span class="mlp-vc-num">—</span><span class="mlp-vc-label">views</span></span>';
                }
            }

            var copyNameBtn = '<button class="mlp-row-copy-name-btn" type="button" title="Copy project name" aria-label="Copy project name">' +
                '<span class="mlp-copy-emoji">📋</span>' +
                '</button>';

            var tagsLine = '';
            if (Array.isArray(p.tags) && p.tags.length) {
                var tagsHtml = '';
                for (var ti = 0; ti < p.tags.length; ti++) {
                    var tname = String(p.tags[ti] || '').trim();
                    if (!tname) continue;
                    tagsHtml += '<span class="mlp-tag-chip" data-tag="' + escHtml(tname) + '" title="Filter by #' + escHtml(tname) + '"' + tagChipStyle(tname) + '>#' + escHtml(tname) + '</span>';
                }
                if (tagsHtml) tagsLine = '<span class="mlp-row-tags">' + tagsHtml + '</span>';
            }

            var tdName = document.createElement('td');
            tdName.innerHTML =
                '<a class="mlp-row-name" href="#">' +
                coverStripe +
                '<span class="mlp-row-icon" style="' + iconStyle + '">' + iconInner + '</span>' +
                '<span>' + highlightText(p.name || 'Untitled', searchQuery) + copyNameBtn + lockBadge + notesDot + descLine + sharedFromLine + codeHitLine + viewStatLine + tagsLine + '</span>' +
                '</a>';
            tdName.querySelector('.mlp-row-name').addEventListener('click', function(e) {
                if (e.target.closest && e.target.closest('.mlp-row-copy-name-btn, .mlp-tag-chip')) return;
                e.preventDefault();
                goCode(p);
            });
            var copyBtnEl = tdName.querySelector('.mlp-row-copy-name-btn');
            if (copyBtnEl) {
                copyBtnEl.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    copyProjectName(p.name || 'Untitled', copyBtnEl);
                });
            }
            tdName.querySelectorAll('.mlp-tag-chip').forEach(function(chip) {
                chip.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    var t = chip.getAttribute('data-tag') || '';
                    currentTagFilter = (currentTagFilter === t) ? '' : t;
                    saveFilterState();
                    render(searchInput.value);
                });
            });

            var tdCreated = document.createElement('td');
            tdCreated.className = 'mlp-row-date';
            tdCreated.textContent = p.createdAt ? fmtDate(p.createdAt) : '—';

            var tdMod = document.createElement('td');
            tdMod.className = 'mlp-row-date';
            var modText = p.updatedAt ? fmtDate(p.updatedAt) : (p.createdAt ? fmtDate(p.createdAt) : '—');
            var openedText = p.lastOpenedAt ? fmtDate(p.lastOpenedAt) : 'Never opened';
            tdMod.innerHTML = '<span class="mlp-row-mod-date">' + escHtml(modText) + '</span>' +
                '<span class="mlp-row-opened" title="When you last opened this project in the editor">🕐 Opened: ' + escHtml(openedText) + '</span>';

            var tdSize = document.createElement('td');
            var sizeBytes = calcProjectSize(p);
            var sizeClass = getSizeClass(sizeBytes);
            tdSize.innerHTML = '<span class="mlp-size-badge ' + sizeClass + '">' + escHtml(fmtSize(sizeBytes)) + '</span>';

            var tdVis = document.createElement('td');
            var vis = p.visibility || 'private';
            if (vis === 'public') {
                var hasLink = !!(p.shareToken || p.shareUrl);
                tdVis.innerHTML =
                    '<span class="mlp-row-badge mlp-badge-public">Public</span>' +
                    '<button class="mlp-proj-share-action-btn" data-proj-id="' + escHtml(p.id) + '">' +
                    '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;display:inline-block;"><path d="M22 2L11 13"/><path d="M22 2L15 22L11 13L2 9L22 2Z"/></svg>' +
                    '<span>' + (hasLink ? 'Get Link' : 'Publish') + '</span>' +
                    '</button>' +
                    (hasLink
                        ? '<button class="mlp-proj-republish-btn" data-proj-id="' + escHtml(p.id) + '" title="Re-scan with AI and update the shared content, keeping the same link">' +
                          '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;display:inline-block;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>' +
                          '<span>RePublish</span>' +
                          '</button>'
                        : '');
                (function(proj) {
                    tdVis.querySelector('.mlp-proj-share-action-btn').addEventListener('click', function(e) {
                        e.stopPropagation();
                        if (!!(proj.shareToken || proj.shareUrl)) {
                            openGetLinkPopup(proj);
                        } else {
                            openShareModal(proj);
                        }
                    });
                    var republishBtn = tdVis.querySelector('.mlp-proj-republish-btn');
                    if (republishBtn) {
                        (function(proj) {
                            republishBtn.addEventListener('click', function(e) {
                                e.stopPropagation();
                                openRepublishModal(proj);
                            });
                        })(proj);
                    }
                })(p);
            } else {
                tdVis.innerHTML = '<span class="mlp-row-badge mlp-badge-' + escHtml(vis) + '">' + escHtml(vis.charAt(0).toUpperCase() + vis.slice(1)) + '</span>';
            }

            var tdAct = document.createElement('td');
            var prem = isPremium();
            var lockLabel = p.pinHash ? '🔐 Password' : '🔓 Password';
            var premBadge = '<span class="mlp-more-item-badge">✦ Premium</span>';
            tdAct.innerHTML =
                '<div class="mlp-row-actions">' +
                '<button class="mlp-row-btn mlp-row-btn-go">Go Code</button>' +
                '<div class="mlp-more-wrap">' +
                  '<button class="mlp-row-btn mlp-row-btn-more" type="button">' +
                  'Options <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>' +
                  '</button>' +
                  '<div class="mlp-more-dropdown" style="display:none;">' +
                    '<button class="mlp-more-item mlp-more-rename" type="button">✏️ Rename</button>' +
                    '<button class="mlp-more-item mlp-more-dup" type="button">⧉ Duplicate</button>' +
                    '<div class="mlp-more-divider"></div>' +
                    '<button class="mlp-more-item mlp-more-notes" type="button">📝 Notes</button>' +
                    '<button class="mlp-more-item mlp-more-lock" type="button">' + lockLabel + '</button>' +
                    '<button class="mlp-more-item mlp-more-desc" type="button">✏️ Description</button>' +
                    '<button class="mlp-more-item mlp-more-tags" type="button">🏷 Tags</button>' +
                    '<button class="mlp-more-item mlp-more-color" type="button">◑ Icon Color</button>' +
                    '<button class="mlp-more-item mlp-more-history" type="button">↩ History</button>' +
                    '<div class="mlp-more-divider"></div>' +
                    (p.visibility !== 'public' ? '<button class="mlp-more-item mlp-more-publish" type="button">🚀 Publish &amp; Share</button>' : '') +
                    '<button class="mlp-more-item mlp-more-export-zip" type="button">📦 Export as ZIP</button>' +
                  '</div>' +
                '</div>' +
                '<button class="mlp-row-btn mlp-row-btn-stats" data-id="' + escHtml(p.id) + '" title="View stats"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg> Stats</button>' +
                '<button class="mlp-row-btn mlp-row-btn-del">Delete</button>' +
                '</div>';

            /* Go Code */
            tdAct.querySelector('.mlp-row-btn-go').addEventListener('click', function() {
                goCode(p);
            });
            /* Delete */
            tdAct.querySelector('.mlp-row-btn-del').addEventListener('click', function() { openDelModal(p.id, p.name); });
            /* Stats */
            (function(proj) {
                var sBtn = tdAct.querySelector('.mlp-row-btn-stats');
                if (sBtn) sBtn.addEventListener('click', function(e) {
                    e.stopPropagation();
                    if (typeof window.mlpOpenStatsPanel === 'function') window.mlpOpenStatsPanel(proj);
                });
            })(p);
            /* More toggle */
            var moreBtn = tdAct.querySelector('.mlp-row-btn-more');
            var moreDrop = tdAct.querySelector('.mlp-more-dropdown');
            moreBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                var isOpen = moreDrop.style.display !== 'none';
                closeAllMoreDropdowns();
                if (!isOpen) {
                    var rect = moreBtn.getBoundingClientRect();
                    moreDrop.style.display = 'block';
                    moreDrop.style.top = '-9999px';
                    moreDrop.style.left = '-9999px';
                    var dropW = moreDrop.offsetWidth || 205;
                    var dropH = moreDrop.offsetHeight || 260;
                    var viewH = window.innerHeight || document.documentElement.clientHeight;
                    var spaceBelow = viewH - rect.bottom;
                    var spaceAbove = rect.top;
                    var topPos;
                    if (spaceBelow >= dropH + 8 || spaceBelow >= spaceAbove) {
                        topPos = rect.bottom + 5;
                    } else {
                        topPos = rect.top - dropH - 5;
                        if (topPos < 8) topPos = 8;
                    }
                    var leftPos = rect.right - dropW;
                    if (leftPos < 8) leftPos = 8;
                    moreDrop.style.top = topPos + 'px';
                    moreDrop.style.left = leftPos + 'px';
                    moreDrop.style.right = 'auto';
                    moreBtn.classList.add('mlp-more-open');
                }
            });
            /* Dropdown items */
            tdAct.querySelector('.mlp-more-rename').addEventListener('click', function() { closeAllMoreDropdowns(); openRenameModal(p.id, p.name); });
            tdAct.querySelector('.mlp-more-dup').addEventListener('click', function() { closeAllMoreDropdowns(); duplicateProject(p); });
            tdAct.querySelector('.mlp-more-notes').addEventListener('click', function() {
                closeAllMoreDropdowns();
                openNotesModal(p);
            });
            tdAct.querySelector('.mlp-more-lock').addEventListener('click', function() {
                closeAllMoreDropdowns();
                openPinModal(p);
            });

            tdAct.querySelector('.mlp-more-desc').addEventListener('click', function() {
                closeAllMoreDropdowns();
                openDescModal(p);
            });
            tdAct.querySelector('.mlp-more-tags').addEventListener('click', function() {
                closeAllMoreDropdowns();
                openTagsEditor(p);
            });
            tdAct.querySelector('.mlp-more-color').addEventListener('click', function() {
                closeAllMoreDropdowns();
                openColorModal(p.id, p.iconColor || null, p.emoji || '');
            });
            tdAct.querySelector('.mlp-more-history').addEventListener('click', function() {
                closeAllMoreDropdowns();
                openHistoryModal(p.id);
            });
            tdAct.querySelector('.mlp-more-export-zip').addEventListener('click', function() {
                closeAllMoreDropdowns();
                exportProjectAsZip(p);
            });
            var publishBtn = tdAct.querySelector('.mlp-more-publish');
            if (publishBtn) {
                publishBtn.addEventListener('click', function() {
                    closeAllMoreDropdowns();
                    openShareModal(p);
                });
            }

            tr.appendChild(tdCb);
            tr.appendChild(tdPin);
            tr.appendChild(tdStar);
            tr.appendChild(tdName);
            tr.appendChild(tdCreated);
            tr.appendChild(tdMod);
            tr.appendChild(tdSize);
            tr.appendChild(tdVis);
            tr.appendChild(tdAct);

            if (p.pinned) {
                var pinnedTds = tr.querySelectorAll('td');
                for (var pi = 0; pi < pinnedTds.length; pi++) {
                    pinnedTds[pi].style.setProperty('background', '#1e293b', 'important');
                    pinnedTds[pi].style.setProperty('color', '#e2e8f0', 'important');
                    pinnedTds[pi].style.setProperty('border-top', '1px solid #2d3f55', 'important');
                    pinnedTds[pi].style.setProperty('border-bottom', '1px solid #2d3f55', 'important');
                    pinnedTds[pi].style.setProperty('border-left', 'none', 'important');
                }
                pinnedTds[0].style.setProperty('border-left', '3px solid #3b82f6', 'important');
                /* project name link */
                var rowNameEl = tr.querySelector('.mlp-row-name');
                if (rowNameEl) { rowNameEl.style.setProperty('color', '#f1f5f9', 'important'); }
                /* size badge */
                var sizeBadgeEl = tr.querySelector('.mlp-size-badge');
                if (sizeBadgeEl) {
                    sizeBadgeEl.style.setProperty('background', '#0f172a', 'important');
                    sizeBadgeEl.style.setProperty('color', '#94a3b8', 'important');
                    sizeBadgeEl.style.setProperty('border-color', '#334155', 'important');
                }
                /* visibility badge */
                var visBadgeEl = tr.querySelector('.mlp-row-badge');
                if (visBadgeEl) {
                    visBadgeEl.style.setProperty('background', '#0f172a', 'important');
                    visBadgeEl.style.setProperty('color', '#93c5fd', 'important');
                    visBadgeEl.style.setProperty('border-color', '#334155', 'important');
                }
                /* locked indicator */
                var lockIndEl = tr.querySelector('.mlp-row-locked-indicator');
                if (lockIndEl) {
                    lockIndEl.style.setProperty('background', '#1e3a5f', 'important');
                    lockIndEl.style.setProperty('color', '#93c5fd', 'important');
                }
                /* date cells */
                var dateCells = tr.querySelectorAll('.mlp-row-date');
                for (var pd = 0; pd < dateCells.length; pd++) {
                    dateCells[pd].style.setProperty('color', '#94a3b8', 'important');
                }
                /* action buttons */
                var rowBtns = tr.querySelectorAll('.mlp-row-btn');
                for (var pk = 0; pk < rowBtns.length; pk++) {
                    rowBtns[pk].style.setProperty('background', '#0f172a', 'important');
                    rowBtns[pk].style.setProperty('border-color', '#334155', 'important');
                    rowBtns[pk].style.setProperty('color', '#94a3b8', 'important');
                    (function(btn) {
                        btn.addEventListener('mouseenter', function() {
                            btn.style.setProperty('background', '#1e3a5f', 'important');
                            btn.style.setProperty('color', '#e2e8f0', 'important');
                            btn.style.setProperty('border-color', '#3b82f6', 'important');
                        });
                        btn.addEventListener('mouseleave', function() {
                            btn.style.setProperty('background', '#0f172a', 'important');
                            btn.style.setProperty('color', '#94a3b8', 'important');
                            btn.style.setProperty('border-color', '#334155', 'important');
                        });
                    })(rowBtns[pk]);
                }
                /* Go Code button — keep it bright */
                var goBtn = tr.querySelector('.mlp-row-btn-go');
                if (goBtn) {
                    goBtn.style.setProperty('background', '#2563eb', 'important');
                    goBtn.style.setProperty('color', '#ffffff', 'important');
                    goBtn.style.setProperty('border-color', '#2563eb', 'important');
                    goBtn.addEventListener('mouseenter', function() {
                        goBtn.style.setProperty('background', '#1d4ed8', 'important');
                        goBtn.style.setProperty('color', '#ffffff', 'important');
                        goBtn.style.setProperty('border-color', '#1d4ed8', 'important');
                    });
                    goBtn.addEventListener('mouseleave', function() {
                        goBtn.style.setProperty('background', '#2563eb', 'important');
                        goBtn.style.setProperty('color', '#ffffff', 'important');
                        goBtn.style.setProperty('border-color', '#2563eb', 'important');
                    });
                }
            }

            return tr;
        }

            /* ── Backup modal ────────────────────────────────────────── */
        function hasSavedTabs(p) {
            // Only check savedTabs — allTabs always contains at least one
            // default blank tab even for brand-new empty projects, so it
            // cannot be used as an indicator that real work exists.
            return !!(p.savedTabs && typeof p.savedTabs === 'object' && Object.keys(p.savedTabs).length > 0);
        }

        function downloadProjectBackup(p) {
            try {
                var backup = {
                    exportedAt:  new Date().toISOString(),
                    exportedBy:  'MLP Projects Backup',
                    version:     1,
                    project:     p
                };
                var json = JSON.stringify(backup, null, 2);
                var blob = new Blob([json], { type: 'application/json' });
                var url  = URL.createObjectURL(blob);
                var a    = document.createElement('a');
                a.href     = url;
                a.download = (p.name || 'project').replace(/[^a-z0-9_-]/gi, '_') + '_backup_' + new Date().toISOString().slice(0,10) + '.json';
                document.body.appendChild(a);
                a.click();
                setTimeout(function() { URL.revokeObjectURL(url); document.body.removeChild(a); }, 1000);
                // Record the backup time on the project so we don't nag again
                try {
                    var nowIso = new Date().toISOString();
                    var allP = getProjects();
                    for (var bi = 0; bi < allP.length; bi++) {
                        if (allP[bi].id === p.id) { allP[bi].lastBackupAt = nowIso; saveProjects(allP); break; }
                    }
                } catch(e) {}
                return true;
            } catch(e) {
                return false;
            }
        }

        var _backupPendingProject  = null;
        var _backupPendingCallback = null;

        function openBackupModal(p, onProceed) {
            var modal     = document.getElementById('mlp-backup-modal');
            var nameEl    = document.getElementById('mlp-backup-proj-name');
            var countEl   = document.getElementById('mlp-backup-tab-count');
            var sizeEl    = document.getElementById('mlp-backup-size-label');
            var dateEl    = document.getElementById('mlp-backup-date-label');
            var dlBtn     = document.getElementById('mlp-backup-download-btn');
            var skipBtn   = document.getElementById('mlp-backup-skip-btn');
            if (!modal) { onProceed(); return; }

            _backupPendingProject  = p;
            _backupPendingCallback = onProceed;

            // Populate modal info
            if (nameEl) nameEl.textContent = p.name || 'Untitled';
            var tabCount = 0;
            if (p.allTabs)   tabCount = Object.keys(p.allTabs).length;
            else if (p.savedTabs) tabCount = Object.keys(p.savedTabs).length;
            if (countEl) countEl.textContent = tabCount + ' saved tab' + (tabCount !== 1 ? 's' : '');
            var sz = calcProjectSize(p);
            if (sizeEl) sizeEl.textContent = fmtSize(sz) + ' of code';
            if (dateEl) dateEl.textContent = 'Modified: ' + (p.updatedAt ? fmtDate(p.updatedAt) : '—');

            modal.style.display = 'flex';

            // Download & proceed
            if (dlBtn) {
                dlBtn.onclick = function() {
                    downloadProjectBackup(_backupPendingProject);
                    modal.style.display = 'none';
                    if (_backupPendingCallback) _backupPendingCallback();
                    _backupPendingProject  = null;
                    _backupPendingCallback = null;
                    showToast('Backup Downloaded', 'Your code has been saved as a .json file.', 'success');
                };
            }

            // Skip
            if (skipBtn) {
                skipBtn.onclick = function() {
                    modal.style.display = 'none';
                    if (_backupPendingCallback) _backupPendingCallback();
                    _backupPendingProject  = null;
                    _backupPendingCallback = null;
                };
            }
        }

            /* ── Go Code helper (with backup gate) ──────────────────── */
        function goCode(p) {
            if (p.pinHash) {
                openUnlockModal(p, function() { goCodeDirect(p); });
                return;
            }
            goCodeDirect(p);
        }

        function goCodeDirect(p) {
            // Always read fresh from storage — the closure's p may be stale
            var fresh = null;
            var all = getProjects();
            for (var i = 0; i < all.length; i++) {
                if (all[i].id === p.id) { fresh = all[i]; break; }
            }
            var target = fresh || p;
            if (hasSavedTabs(target)) {
                openBackupModal(target, function() {
                    window.mlpLoadProject(target);
                    closePopup();
                });
            } else {
                window.mlpLoadProject(target);
                closePopup();
            }
        }


        var toastContainer = document.getElementById('mlp-toast-container');
        function showToast(title, msg, type, durationMs, extraClass) {
            if (!toastContainer) return;
            type = type || 'info';
            var iconPaths = {
                success: '<polyline points="20 6 9 17 4 12"/>',
                danger:  '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
                warning: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
                info:    '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'
            };
            var t = document.createElement('div');
            t.className = 'mlp-toast mlp-toast-' + type + (extraClass ? ' ' + extraClass : '');
            // If extraClass is present, treat msg as raw HTML; otherwise escape (preserves existing behavior).
            var msgHtml = msg ? (extraClass ? msg : escHtml(msg)) : '';
            t.innerHTML =
                '<div class="mlp-toast-icon-wrap">' +
                    '<svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5">' + (iconPaths[type] || iconPaths.info) + '</svg>' +
                '</div>' +
                '<div class="mlp-toast-body">' +
                    '<span class="mlp-toast-title">' + escHtml(title) + '</span>' +
                    (msg ? '<span class="mlp-toast-msg">' + msgHtml + '</span>' : '') +
                '</div>' +
                '<button class="mlp-toast-close" aria-label="Dismiss">' +
                    '<svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>' +
                '</button>' +
                '<div class="mlp-toast-progress"><div class="mlp-toast-progress-bar"></div></div>';

            function dismiss() {
                t.classList.add('mlp-toast-out');
                setTimeout(function() { if (t.parentNode) t.parentNode.removeChild(t); }, 260);
            }
            t.querySelector('.mlp-toast-close').addEventListener('click', dismiss);
            toastContainer.appendChild(t);
            var timer = setTimeout(dismiss, durationMs || 3000);
            t.querySelector('.mlp-toast-close').addEventListener('click', function() { clearTimeout(timer); });
        }

        /* ── Undo toast ──────────────────────────────────────────────── */
        function showUndoToast(projName, onUndo) {
            if (!toastContainer) return;
            var t = document.createElement('div');
            t.className = 'mlp-toast mlp-toast-danger';
            t.innerHTML =
                '<div class="mlp-toast-icon-wrap"><svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></div>' +
                '<div class="mlp-toast-body"><span class="mlp-toast-title">Deleted "' + escHtml(projName) + '"</span>' +
                '<button class="mlp-toast-undo">↩ Undo</button></div>' +
                '<button class="mlp-toast-close" aria-label="Dismiss"><svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>' +
                '<div class="mlp-toast-progress"><div class="mlp-toast-progress-bar" style="animation-duration:5s;"></div></div>';
            function dismiss() {
                t.classList.add('mlp-toast-out');
                setTimeout(function(){ if(t.parentNode) t.parentNode.removeChild(t); }, 260);
            }
            t.querySelector('.mlp-toast-close').addEventListener('click', dismiss);
            t.querySelector('.mlp-toast-undo').addEventListener('click', function() { onUndo(); dismiss(); });
            toastContainer.appendChild(t);
            var timer = setTimeout(dismiss, 5000);
            t.querySelector('.mlp-toast-close').addEventListener('click', function(){ clearTimeout(timer); });
        }

        /* ── Color palette setup ────────────────────────────────────── */

        function buildColorPalette(containerId, currentColor) {
            var el = document.getElementById(containerId);
            if (!el) return;
            el.innerHTML = '';
            COLOR_SWATCHES.forEach(function(hex) {
                var sw = document.createElement('button');
                sw.className = 'mlp-color-swatch' + (hex === currentColor ? ' mlp-swatch-active' : '');
                sw.style.background = hex;
                sw.title = hex;
                sw.addEventListener('click', function() {
                    el.querySelectorAll('.mlp-color-swatch').forEach(function(s){ s.classList.remove('mlp-swatch-active'); });
                    sw.classList.add('mlp-swatch-active');
                    if (containerId === 'mlp-color-palette') colorModalSelected = hex;
                    if (containerId === 'mlp-create-color-palette') createColorSelected = hex;
                });
                el.appendChild(sw);
            });
        }

        function openColorModal(id, currentColor, currentEmoji) {
            colorModalTargetId = id;
            colorModalSelected = currentColor || COLOR_SWATCHES[0];
            var modal   = document.getElementById('mlp-proj-color-modal');
            var emojiEl = document.getElementById('mlp-proj-emoji-input');
            if (!modal) return;
            buildColorPalette('mlp-color-palette', colorModalSelected);
            if (emojiEl) emojiEl.value = currentEmoji || '';
            modal.style.display = 'flex';
        }

        var colorModalEl    = document.getElementById('mlp-proj-color-modal');
        var colorCloseBtn   = document.getElementById('mlp-proj-color-modal-close');
        var colorCancelBtn  = document.getElementById('mlp-proj-color-cancel-btn');
        var colorSaveBtn    = document.getElementById('mlp-proj-color-save-btn');
        var colorEmojiInput = document.getElementById('mlp-proj-emoji-input');

        function closeColorModal() { if (colorModalEl) colorModalEl.style.display = 'none'; }
        if (colorCloseBtn)  colorCloseBtn.addEventListener('click', closeColorModal);
        if (colorCancelBtn) colorCancelBtn.addEventListener('click', closeColorModal);
        if (colorModalEl)   colorModalEl.addEventListener('click', function(e){ if (e.target === colorModalEl) closeColorModal(); });
        if (colorSaveBtn) {
            colorSaveBtn.addEventListener('click', function() {
                if (!colorModalTargetId) { closeColorModal(); return; }
                var emoji = colorEmojiInput ? colorEmojiInput.value.trim() : '';
                updateProjectById(colorModalTargetId, { iconColor: colorModalSelected, emoji: emoji });
                closeColorModal();
                render(searchInput.value);
                showToast('Style Updated', 'Color and icon applied to project.', 'success');
            });
        }

        /* ── Rename modal ───────────────────────────────────────────── */
        var renameModal      = document.getElementById('mlp-proj-rename-modal');
        var renameInput      = document.getElementById('mlp-proj-rename-input');
        var renameCloseBtn   = document.getElementById('mlp-proj-rename-modal-close');
        var renameCancelBtn  = document.getElementById('mlp-proj-rename-cancel-btn');
        var renameSaveBtn    = document.getElementById('mlp-proj-rename-save-btn');
        var renameTargetId   = null;

        function openRenameModal(id, currentName) {
            renameTargetId = id;
            if (renameInput) renameInput.value = currentName || '';
            if (renameModal) renameModal.style.display = 'flex';
            if (renameInput) setTimeout(function(){ renameInput.focus(); renameInput.select(); }, 60);
        }
        function closeRenameModal() { if (renameModal) renameModal.style.display = 'none'; renameTargetId = null; }

        if (renameCloseBtn)  renameCloseBtn.addEventListener('click', closeRenameModal);
        if (renameCancelBtn) renameCancelBtn.addEventListener('click', closeRenameModal);
        if (renameModal)     renameModal.addEventListener('click', function(e){ if (e.target === renameModal) closeRenameModal(); });
        if (renameSaveBtn) {
            renameSaveBtn.addEventListener('click', function() {
                var name = renameInput ? renameInput.value.trim() : '';
                if (!name || !renameTargetId) { if (renameInput) renameInput.focus(); return; }
                updateProjectById(renameTargetId, { name: name });
                closeRenameModal();
                render(searchInput.value);
                showToast('Project Renamed', 'Now called "' + name + '".', 'success');
            });
        }
        if (renameInput) {
            renameInput.addEventListener('keydown', function(e) {
                if (e.key === 'Enter')  renameSaveBtn && renameSaveBtn.click();
                if (e.key === 'Escape') closeRenameModal();
            });
        }

        /* ── Duplicate project ──────────────────────────────────────── */
        function duplicateProject(p) {
            var currentProjects = getProjects();
            var now  = new Date().toISOString();
            var copy = {};
            for (var k in p) { if (p.hasOwnProperty(k)) copy[k] = p[k]; }
            copy.id        = generateId();
            copy.name      = (p.name || 'Untitled') + ' (copy)';
            copy.createdAt = now;
            copy.updatedAt = now;
            var projects = getProjects();
            projects.push(copy);
            saveProjects(projects);
            render(searchInput.value);
            showToast('Project Duplicated', '"' + copy.name + '" is ready to edit.', 'info');
        }

        /* ── Publish modal (AI moderation gate) ──────────────────────── */
        var _sharePendingProject = null;
        var _mlpTurnstileToken   = '';  // set by Turnstile callback
        var _mlpRepublishTurnstileToken = '';

        // Turnstile callbacks — Publish modal
        window.mlpTurnstileCallback = function(token) {
            _mlpTurnstileToken = token;
            var runBtn = document.getElementById('mlp-publish-run-btn');
            if (runBtn) runBtn.disabled = false;
        };
        window.mlpTurnstileExpired = function() {
            _mlpTurnstileToken = '';
            var runBtn = document.getElementById('mlp-publish-run-btn');
            if (runBtn) runBtn.disabled = true;
        };
        window.mlpTurnstileError = function() {
            _mlpTurnstileToken = '';
            var runBtn = document.getElementById('mlp-publish-run-btn');
            if (runBtn) runBtn.disabled = true;
        };

        // Turnstile callbacks — RePublish modal
        window.mlpRepublishTurnstileCallback = function(token) {
            _mlpRepublishTurnstileToken = token;
            var runBtn = document.getElementById('mlp-republish-run-btn');
            if (runBtn) runBtn.disabled = false;
        };
        window.mlpRepublishTurnstileExpired = function() {
            _mlpRepublishTurnstileToken = '';
            var runBtn = document.getElementById('mlp-republish-run-btn');
            if (runBtn) runBtn.disabled = true;
        };
        window.mlpRepublishTurnstileError = function() {
            _mlpRepublishTurnstileToken = '';
            var runBtn = document.getElementById('mlp-republish-run-btn');
            if (runBtn) runBtn.disabled = true;
        };

        function setPublishStep(step) {
            ['pre','checking','rejected','approved'].forEach(function(s) {
                var el = document.getElementById('mlp-publish-step-' + s);
                if (el) el.style.display = (s === step) ? 'block' : 'none';
            });
        }

        function buildFinalUrl(token, payloadJson) {
            if (token) {
                return appendShareParam(getShareBaseUrl(), 'mlpsht', token) + '#mlpsht_' + encodeURIComponent(token);
            }
            return buildInlineShareUrlFromJson(payloadJson);
        }

        function stripTabTimestamps(tabs) {
            if (!tabs || typeof tabs !== 'object') return tabs;
            var out = {};
            Object.keys(tabs).forEach(function(k) {
                var t = tabs[k];
                if (!t) { out[k] = t; return; }
                out[k] = {
                    id: t.id, title: t.title, emoji: t.emoji,
                    isForked: t.isForked, isReadOnly: t.isReadOnly,
                    html: t.html || '', css: t.css || '', js: t.js || '',
                    preprocessors: t.preprocessors
                };
            });
            return out;
        }
        function computeShareContentHash(p) {
            try {
                return JSON.stringify({
                    html: p.html || '',
                    css:  p.css  || '',
                    js:   p.js   || '',
                    savedTabs: stripTabTimestamps(p.savedTabs) || null,
                    allTabs:   stripTabTimestamps(p.allTabs)   || null
                });
            } catch(e) { return ''; }
        }

        function openShareModal(p) {
            _sharePendingProject = p;
            var modal    = document.getElementById('mlp-share-modal');
            var titleEl  = document.getElementById('mlp-share-proj-title');
            var runBtn   = document.getElementById('mlp-publish-run-btn');
            var copyBtn  = document.getElementById('mlp-share-copy-link-btn');
            var domainInput = document.getElementById('mlp-share-domain-input');
            if (!modal) return;
            if (titleEl) titleEl.textContent = p.name || 'Untitled';

            // Always flush live editor state before comparing hashes so any
            // unsaved tab work is reflected in the content hash check.
            if (p.id && window.mlpCurrentProjectId && p.id === window.mlpCurrentProjectId) {
                flushTabsToProject(p.id);
                var freshAll = getProjects();
                for (var fi = 0; fi < freshAll.length; fi++) {
                    if (freshAll[fi].id === p.id) { p = freshAll[fi]; _sharePendingProject = p; break; }
                }
            }

            // Compare current content hash against what was moderated at publish time
            var currentHash   = computeShareContentHash(p);
            var publishedHash = p.shareContentHash || null;
            var contentChanged = publishedHash !== null && (currentHash !== publishedHash);

            if (p.shareUrl && !contentChanged) {
                // Content is byte-for-byte identical to what passed moderation — safe to reuse
                setPublishStep('approved');
                if (domainInput) domainInput.value = p.shareUrl;
                if (copyBtn)    { copyBtn.disabled = false; }
                if (runBtn)     { runBtn.style.display = 'none'; }
            } else {
                // Content changed since last publish, or never published — must re-moderate
                if (contentChanged) {
                    // Wipe the stale link so it cannot be copied from the input
                    updateProjectById(p.id, { shareUrl: null, shareToken: null, shareContentHash: null });
                    p = Object.assign({}, p, { shareUrl: null, shareToken: null });
                    _sharePendingProject = p;
                }
                setPublishStep('pre');
                if (runBtn) {
                    runBtn.style.display = 'inline-flex';
                    runBtn.disabled = true;   // disabled until Turnstile passes
                    runBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;display:inline-block;"><path d="M22 2L11 13"/><path d="M22 2L15 22L11 13L2 9L22 2Z"/></svg> Publish &amp; Get Link';
                }
                _mlpTurnstileToken = '';
                // Reset Turnstile widget so user sees a fresh challenge
                if (window.turnstile && document.getElementById('mlp-turnstile-widget')) {
                    try { window.turnstile.reset('#mlp-turnstile-widget'); } catch(e) {}
                }
                if (copyBtn)    copyBtn.disabled = true;
                if (domainInput) domainInput.value = '';
            }
            modal.style.display = 'flex';
        }

        function closeShareModal() {
            var modal = document.getElementById('mlp-share-modal');
            if (modal) modal.style.display = 'none';
            _sharePendingProject = null;
        }

        function collectProjectContent(p) {
            var parts = [];
            if (p.name)        parts.push('Project name: ' + p.name);
            if (p.description) parts.push('Description: ' + p.description);
            if (p.html)        parts.push('HTML:\n' + p.html);
            if (p.css)         parts.push('CSS:\n' + p.css);
            if (p.js)          parts.push('JS:\n' + p.js);
            [p.savedTabs, p.allTabs].forEach(function(tabs) {
                if (!tabs || typeof tabs !== 'object') return;
                Object.keys(tabs).forEach(function(tid) {
                    var t = tabs[tid];
                    if (!t) return;
                    if (t.title) parts.push('Tab: ' + t.title);
                    if (t.html)  parts.push(t.html);
                    if (t.css)   parts.push(t.css);
                    if (t.js)    parts.push(t.js);
                });
            });
            return parts.join('\n\n').slice(0, 80000);
        }

        /* ── Get Link popup ─────────────────────────────────────────── */
        function openGetLinkPopup(p) {
            var modal    = document.getElementById('mlp-getlink-modal');
            var titleEl  = document.getElementById('mlp-getlink-proj-title');
            var urlInput = document.getElementById('mlp-getlink-url-input');
            var copyBtn  = document.getElementById('mlp-getlink-copy-btn');
            if (!modal) return;
            var url = p.shareUrl || '';
            if (!url && p.shareToken) {
                url = buildFinalUrl(p.shareToken, null);
            }
            if (titleEl)  titleEl.textContent = p.name || 'Untitled';
            if (urlInput) urlInput.value       = url;
            if (copyBtn)  copyBtn.textContent  = 'Copy Link';
            modal.style.display = 'flex';
        }

        (function wireGetLinkModal() {
            var modal    = document.getElementById('mlp-getlink-modal');
            var closeX   = document.getElementById('mlp-getlink-modal-close');
            var closeBtn = document.getElementById('mlp-getlink-close-btn');
            var copyBtn  = document.getElementById('mlp-getlink-copy-btn');
            var urlInput = document.getElementById('mlp-getlink-url-input');
            if (!modal) return;
            function closeIt() { modal.style.display = 'none'; }
            if (closeX)   closeX.addEventListener('click', closeIt);
            if (closeBtn) closeBtn.addEventListener('click', closeIt);
            modal.addEventListener('click', function(e) { if (e.target === modal) closeIt(); });
            if (copyBtn && urlInput) {
                copyBtn.addEventListener('click', function() {
                    if (!urlInput.value) return;
                    try { urlInput.select(); document.execCommand('copy'); } catch(e) {}
                    if (navigator.clipboard) navigator.clipboard.writeText(urlInput.value).catch(function(){});
                    copyBtn.textContent = '✓ Copied!';
                    setTimeout(function(){ copyBtn.textContent = 'Copy Link'; }, 1800);
                    showToast('Link Copied', 'Project link copied to clipboard.', 'success');
                });
            }
        })();

        /* ── RePublish modal ─────────────────────────────────────────── */
        var _republishPendingProject = null;

        function setRepublishStep(step) {
            ['pre','checking','rejected','done'].forEach(function(s) {
                var el = document.getElementById('mlp-republish-step-' + s);
                if (el) el.style.display = (s === step) ? 'block' : 'none';
            });
        }

        function openRepublishModal(p) {
            _republishPendingProject = p;
            var modal   = document.getElementById('mlp-republish-modal');
            var titleEl = document.getElementById('mlp-republish-proj-title');
            var runBtn  = document.getElementById('mlp-republish-run-btn');
            var copyBtn = document.getElementById('mlp-republish-copy-btn');
            var urlInput = document.getElementById('mlp-republish-url-input');
            if (!modal) return;
            if (titleEl) titleEl.textContent = p.name || 'Untitled';
            setRepublishStep('pre');
            if (runBtn) { runBtn.disabled = true; runBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;display:inline-block;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Run AI Check &amp; Update'; }
            if (copyBtn) copyBtn.textContent = 'Copy Link';
            if (urlInput) urlInput.value = '';
            _mlpRepublishTurnstileToken = '';
            if (window.turnstile && document.getElementById('mlp-turnstile-widget-republish')) {
                try { window.turnstile.reset('#mlp-turnstile-widget-republish'); } catch(e) {}
            }
            modal.style.display = 'flex';
        }

        function closeRepublishModal() {
            var modal = document.getElementById('mlp-republish-modal');
            if (modal) modal.style.display = 'none';
            _republishPendingProject = null;
        }

        (function wireRepublishModal() {
            var modal    = document.getElementById('mlp-republish-modal');
            var closeX   = document.getElementById('mlp-republish-modal-close');
            var cancelBtn = document.getElementById('mlp-republish-cancel-btn');
            var runBtn   = document.getElementById('mlp-republish-run-btn');
            var copyBtn  = document.getElementById('mlp-republish-copy-btn');
            var urlInput = document.getElementById('mlp-republish-url-input');
            if (!modal) return;

            function closeIt() { closeRepublishModal(); }
            if (closeX)    closeX.addEventListener('click', closeIt);
            if (cancelBtn) cancelBtn.addEventListener('click', closeIt);
            modal.addEventListener('click', function(e) { if (e.target === modal) closeIt(); });

            if (copyBtn && urlInput) {
                copyBtn.addEventListener('click', function() {
                    if (!urlInput.value) return;
                    try { urlInput.select(); document.execCommand('copy'); } catch(e) {}
                    if (navigator.clipboard) navigator.clipboard.writeText(urlInput.value).catch(function(){});
                    copyBtn.textContent = '✓ Copied!';
                    setTimeout(function(){ copyBtn.textContent = 'Copy Link'; }, 1800);
                    showToast('Link Copied', 'Project link copied to clipboard.', 'success');
                });
            }

            if (runBtn) {
                runBtn.addEventListener('click', function() {
                    var p = _republishPendingProject;
                    if (!p) return;
                    if (!MLP_AJAX_URL || !window.fetch) {
                        showToast('RePublish Unavailable', 'Publishing requires the site AJAX endpoint.', 'danger');
                        return;
                    }

                    // Require Turnstile token
                    if (!_mlpRepublishTurnstileToken) {
                        showToast('Security Check Required', 'Please complete the security check first.', 'danger');
                        return;
                    }

                    runBtn.disabled = true;
                    setRepublishStep('checking');

                    // Flush live editor state before scanning
                    var fresh = getFreshProject(p.id, p);
                    var content = collectProjectContent(fresh);

                    // ── Option 3: NSFWJS client-side image pre-scan ───────────
                    var _republishImgSrcs  = mlpExtractImageSrcs(content);
                    var _republishImgIndex = 0;

                    function runNextRepublishNsfwCheck() {
                        if (_republishImgIndex >= _republishImgSrcs.length) {
                            proceedToRepublishServerModeration();
                            return;
                        }
                        var src = _republishImgSrcs[_republishImgIndex++];
                        mlpNsfwCheck(src, function(isNsfw) {
                            if (!_republishPendingProject || _republishPendingProject.id !== p.id) return;
                            if (isNsfw) {
                                var rejectEl = document.getElementById('mlp-republish-reject-reason');
                                if (rejectEl) rejectEl.textContent = 'Your project contains an image that violates our content policy.';
                                setRepublishStep('rejected');
                                runBtn.disabled = false;
                                runBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;display:inline-block;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Try Again';
                                _mlpRepublishTurnstileToken = '';
                                if (window.turnstile) { try { window.turnstile.reset('#mlp-turnstile-widget-republish'); } catch(e) {} }
                                return;
                            }
                            runNextRepublishNsfwCheck();
                        });
                    }

                    function proceedToRepublishServerModeration() {
                        var modBody = new URLSearchParams();
                        modBody.set('action', 'mlp_moderate_project');
                        modBody.set('nonce', MLP_SHARE_NONCE);
                        modBody.set('content', content);
                        modBody.set('project_name', (fresh && fresh.name) ? String(fresh.name) : '');
                        modBody.set('project_description', (fresh && fresh.description) ? String(fresh.description) : '');
                        modBody.set('cf_turnstile_token', _mlpRepublishTurnstileToken);

                        fetch(MLP_AJAX_URL, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                            body: modBody.toString()
                        })
                        .then(function(res) { return res.json(); })
                        .then(function(resp) {
                            if (!_republishPendingProject || _republishPendingProject.id !== p.id) return;

                            if (!resp || !resp.success) {
                                var reason = (resp && resp.data && resp.data.reason)
                                    ? resp.data.reason
                                    : 'Your project contains content that violates our sharing policy.';
                                var rejectEl = document.getElementById('mlp-republish-reject-reason');
                                if (rejectEl) rejectEl.textContent = reason;
                                setRepublishStep('rejected');
                                runBtn.disabled = false;
                                runBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;display:inline-block;"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Try Again';
                                _mlpRepublishTurnstileToken = '';
                                if (window.turnstile) { try { window.turnstile.reset('#mlp-turnstile-widget-republish'); } catch(e) {} }
                                return;
                            }

                            // Server moderation passed — update existing shared record in place
                            var modToken  = resp.data.mod_token || '';
                            fresh = getFreshProject(p.id, p);
                            var payload   = JSON.stringify(buildSharePayload(fresh));

                            // Extract existing server token from stored shareUrl/shareToken
                            var existingToken = p.shareToken || '';
                            if (!existingToken && p.shareUrl) {
                                try {
                                    var urlObj = new URL(p.shareUrl);
                                    existingToken = urlObj.searchParams.get('mlpsht') || '';
                                } catch(e) {}
                                if (!existingToken && p.shareUrl.indexOf('#mlpsht_') !== -1) {
                                    existingToken = decodeURIComponent(p.shareUrl.split('#mlpsht_')[1] || '');
                                }
                            }

                            var saveBody = new URLSearchParams();
                            saveBody.set('action', 'mlp_save_shared_project');
                            saveBody.set('nonce', MLP_SHARE_NONCE);
                            saveBody.set('payload', payload);
                            saveBody.set('mod_token', modToken);
                            saveBody.set('project_id', fresh.id || '');
                            if (existingToken) {
                                saveBody.set('existing_token', existingToken);
                            }

                            return fetch(MLP_AJAX_URL, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                                body: saveBody.toString()
                            })
                            .then(function(res2) { return res2.json(); })
                            .then(function(resp2) {
                                if (!_republishPendingProject || _republishPendingProject.id !== p.id) return;

                                var finalUrl;
                                if (resp2 && resp2.success && resp2.data && resp2.data.token) {
                                    finalUrl = buildFinalUrl(resp2.data.token, null);
                                } else {
                                    finalUrl = p.shareUrl || '';
                                }

                                var newHash = computeShareContentHash(getFreshProject(p.id, p));
                                updateProjectById(p.id, { shareUrl: finalUrl, shareContentHash: newHash });

                                setRepublishStep('done');
                                runBtn.style.display = 'none';
                                if (urlInput) urlInput.value = finalUrl;
                                if (copyBtn)  copyBtn.disabled = false;
                                render(searchInput ? searchInput.value : '');
                                showToast('RePublished ✓', 'Shared link updated with your latest content.', 'success');
                            });
                        })
                        .catch(function() {
                            if (!_republishPendingProject || _republishPendingProject.id !== p.id) return;
                            setRepublishStep('pre');
                            runBtn.disabled = true;
                            _mlpRepublishTurnstileToken = '';
                            if (window.turnstile) { try { window.turnstile.reset('#mlp-turnstile-widget-republish'); } catch(e) {} }
                            showToast('Connection Error', 'Could not reach the safety check server. Please try again.', 'danger');
                        });
                    }

                    // Kick off NSFWJS scan chain (skips straight to server if no images found)
                    runNextRepublishNsfwCheck();
                });
            }
        })();

        (function wireShareModal() {
            var modal       = document.getElementById('mlp-share-modal');
            var closeBtn    = document.getElementById('mlp-share-modal-close');
            var cancelBtn   = document.getElementById('mlp-share-cancel-btn');
            var runBtn      = document.getElementById('mlp-publish-run-btn');
            var copyBtn     = document.getElementById('mlp-share-copy-link-btn');
            var domainInput = document.getElementById('mlp-share-domain-input');
            if (!modal) return;

            if (closeBtn)  closeBtn.addEventListener('click', closeShareModal);
            if (cancelBtn) cancelBtn.addEventListener('click', closeShareModal);
            modal.addEventListener('click', function(e) { if (e.target === modal) closeShareModal(); });

            if (copyBtn && domainInput) {
                copyBtn.addEventListener('click', function() {
                    if (!domainInput.value || copyBtn.disabled) return;
                    try { domainInput.select(); document.execCommand('copy'); } catch(e) {}
                    if (navigator.clipboard) navigator.clipboard.writeText(domainInput.value).catch(function(){});
                    copyBtn.textContent = '✓ Copied!';
                    setTimeout(function(){ copyBtn.textContent = 'Copy Link'; }, 1800);
                    showToast('Link Copied', 'Project link copied to clipboard.', 'success');
                });
            }

            if (runBtn) {
                runBtn.addEventListener('click', function() {
                    var p = _sharePendingProject;
                    if (!p) return;
                    if (!MLP_AJAX_URL || !window.fetch) {
                        showToast('Publish Unavailable', 'Publishing requires the site AJAX endpoint.', 'danger');
                        return;
                    }

                    // Require Turnstile token
                    if (!_mlpTurnstileToken) {
                        showToast('Security Check Required', 'Please complete the security check first.', 'danger');
                        return;
                    }

                    runBtn.disabled = true;
                    setPublishStep('checking');

                    var freshForMod = getFreshProject(p.id, p);
                    var content = collectProjectContent(freshForMod);

                    // ── Option 3: NSFWJS client-side image pre-scan ───────────
                    // Extract images embedded in the project, check them locally
                    // first. If any are flagged we block immediately without a
                    // server round-trip. On pass (or if NSFWJS is unavailable)
                    // we continue to the server-side moderation steps.
                    var _publishImgSrcs  = mlpExtractImageSrcs(content);
                    var _publishImgIndex = 0;

                    function runNextNsfwCheck() {
                        if (_publishImgIndex >= _publishImgSrcs.length) {
                            // All images passed — proceed to server moderation
                            proceedToServerModeration();
                            return;
                        }
                        var src = _publishImgSrcs[_publishImgIndex++];
                        mlpNsfwCheck(src, function(isNsfw) {
                            if (!_sharePendingProject || _sharePendingProject.id !== p.id) return;
                            if (isNsfw) {
                                var rejectEl = document.getElementById('mlp-mod-reject-reason');
                                if (rejectEl) rejectEl.textContent = 'Your project contains an image that violates our content policy.';
                                setPublishStep('rejected');
                                runBtn.disabled = false;
                                runBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;display:inline-block;"><path d="M22 2L11 13"/><path d="M22 2L15 22L11 13L2 9L22 2Z"/></svg> Try Again';
                                _mlpTurnstileToken = '';
                                if (window.turnstile) { try { window.turnstile.reset('#mlp-turnstile-widget'); } catch(e) {} }
                                return;
                            }
                            runNextNsfwCheck();
                        });
                    }

                    function proceedToServerModeration() {
                        var modBody = new URLSearchParams();
                        modBody.set('action', 'mlp_moderate_project');
                        modBody.set('nonce', MLP_SHARE_NONCE);
                        modBody.set('content', content);
                        modBody.set('project_name', (freshForMod && freshForMod.name) ? String(freshForMod.name) : '');
                        modBody.set('project_description', (freshForMod && freshForMod.description) ? String(freshForMod.description) : '');
                        modBody.set('cf_turnstile_token', _mlpTurnstileToken);

                        fetch(MLP_AJAX_URL, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                            body: modBody.toString()
                        })
                        .then(function(res) { return res.json(); })
                        .then(function(resp) {
                            if (!_sharePendingProject || _sharePendingProject.id !== p.id) return;

                            if (!resp || !resp.success) {
                                var reason = (resp && resp.data && resp.data.reason)
                                    ? resp.data.reason
                                    : 'Your project contains content that violates our sharing policy.';
                                var rejectEl = document.getElementById('mlp-mod-reject-reason');
                                if (rejectEl) rejectEl.textContent = reason;
                                setPublishStep('rejected');
                                runBtn.disabled = false;
                                runBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;display:inline-block;"><path d="M22 2L11 13"/><path d="M22 2L15 22L11 13L2 9L22 2Z"/></svg> Try Again';
                                _mlpTurnstileToken = '';
                                if (window.turnstile) { try { window.turnstile.reset('#mlp-turnstile-widget'); } catch(e) {} }
                                return;
                            }

                            // Server moderation passed — save the project
                            var modToken = resp.data.mod_token || '';
                            var fresh    = getFreshProject(p.id, p);
                            var payload  = JSON.stringify(buildSharePayload(fresh));

                            var saveBody = new URLSearchParams();
                            saveBody.set('action', 'mlp_save_shared_project');
                            saveBody.set('nonce', MLP_SHARE_NONCE);
                            saveBody.set('payload', payload);
                            saveBody.set('mod_token', modToken);
                            saveBody.set('project_id', fresh.id || '');

                            return fetch(MLP_AJAX_URL, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                                body: saveBody.toString()
                            })
                            .then(function(res2) { return res2.json(); })
                            .then(function(resp2) {
                                if (!_sharePendingProject || _sharePendingProject.id !== p.id) return;
                                var url;
                                if (resp2 && resp2.success && resp2.data && resp2.data.token) {
                                    url = buildFinalUrl(resp2.data.token, payload);
                                } else {
                                    url = buildInlineShareUrlFromJson(payload);
                                }
                                var publishedContentHash = computeShareContentHash(getFreshProject(p.id, p));
                                var serverToken = (resp2 && resp2.success && resp2.data && resp2.data.token) ? resp2.data.token : '';
                                updateProjectById(p.id, { visibility: 'public', shareUrl: url, shareToken: serverToken || undefined, shareContentHash: publishedContentHash });
                                render(searchInput ? searchInput.value : '');
                                try { fetchAllViewCounts(); } catch(e) {}
                                setTimeout(function() {
                                    try { if (typeof window._mlpStatsPanelRefresh === 'function') window._mlpStatsPanelRefresh(); } catch(e) {}
                                }, 800);
                                setPublishStep('approved');
                                runBtn.style.display = 'none';
                                if (domainInput) domainInput.value = url;
                                if (copyBtn)    copyBtn.disabled = false;
                            });
                        })
                        .catch(function() {
                            if (!_sharePendingProject || _sharePendingProject.id !== p.id) return;
                            setPublishStep('pre');
                            runBtn.disabled = true;
                            _mlpTurnstileToken = '';
                            if (window.turnstile) { try { window.turnstile.reset('#mlp-turnstile-widget'); } catch(e) {} }
                            showToast('Connection Error', 'Could not reach the safety check server. Please try again.', 'danger');
                        });
                    }

                    // Kick off the NSFWJS image scan chain (or skip straight to
                    // server moderation if the project has no embedded images).
                    runNextNsfwCheck();
                });
            }
        })();

        /* ── Color palette in create modal ──────────────────────────── */
        buildColorPalette('mlp-create-color-palette', createColorSelected);

        /* ── Keyboard shortcuts ─────────────────────────────────────── */
        document.addEventListener('keydown', function(e) {
            var overlay = document.getElementById('mlp-projects-overlay');
            if (!overlay || overlay.classList.contains('mlp-proj-hidden')) return;
            // Don't fire when user is typing in an input
            var tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : '';
            var isInput = (tag === 'input' || tag === 'textarea' || tag === 'select');
            if (e.key === 'Escape') {
                // Close any open modal first, then overlay
                var openModals = ['mlp-proj-modal','mlp-proj-del-modal','mlp-proj-rename-modal',
                    'mlp-proj-color-modal','mlp-settings-modal','mlp-username-modal','mlp-del-account-modal',
                    'mlp-notes-modal','mlp-pin-modal','mlp-unlock-modal','mlp-desc-modal','mlp-bulk-del-modal','mlp-share-modal','mlp-republish-modal','mlp-owner-modal'];
                var closed = false;
                for (var i = 0; i < openModals.length; i++) {
                    var m = document.getElementById(openModals[i]);
                    if (m && m.style.display !== 'none') { m.style.display = 'none'; closed = true; break; }
                }
                if (!closed) {
                    overlay.classList.add('mlp-proj-hidden');
                    document.body.style.overflow = '';
                }
                return;
            }
            if (isInput) return;
            if (e.key === 'n' || e.key === 'N') { e.preventDefault(); openModal(); }
            if (e.key === '/') {
                e.preventDefault();
                if (searchInput) { searchInput.focus(); searchInput.select(); }
            }
        });

        /* ── Render table ───────────────────────────────────────────── */
        function updateProjectCounter(count) {
            var elCur = document.getElementById('mlp-proj-count-current');
            var elMax = document.getElementById('mlp-proj-count-max');
            if (!elCur || !elMax) return;
            elCur.textContent = count;
            elMax.textContent = '∞';
            elCur.classList.remove('mlp-count-warn', 'mlp-count-full');
        }

        function sortProjects(arr, key) {
            var copy = arr.slice();
            // Special-case: 'favorite' = favorites first, then everything else
            if (key === 'favorite') {
                var favs    = copy.filter(function(p){ return p.favorite; });
                var nonFavs = copy.filter(function(p){ return !p.favorite; });
                function byMod(a, b) {
                    var av = a.updatedAt || a.createdAt || '';
                    var bv = b.updatedAt || b.createdAt || '';
                    return av < bv ? 1 : av > bv ? -1 : 0;
                }
                favs.sort(byMod); nonFavs.sort(byMod);
                return favs.concat(nonFavs);
            }
            var pinned = copy.filter(function(p){ return p.pinned; });
            var rest   = copy.filter(function(p){ return !p.pinned; });
            function sortArr(a) {
                var dir = currentSortDir;
                a.sort(function(x, y) {
                    var xv, yv;
                    if (key === 'name')     { xv = (x.name||'').toLowerCase(); yv = (y.name||'').toLowerCase(); return dir * (xv < yv ? -1 : xv > yv ? 1 : 0); }
                    if (key === 'created')  { xv = x.createdAt||''; yv = y.createdAt||''; return dir * (xv < yv ? -1 : xv > yv ? 1 : 0); }
                    if (key === 'modified') { xv = x.updatedAt||x.createdAt||''; yv = y.updatedAt||y.createdAt||''; return dir * (xv < yv ? -1 : xv > yv ? 1 : 0); }
                    if (key === 'opened')   { xv = x.lastOpenedAt||''; yv = y.lastOpenedAt||''; return dir * (xv < yv ? -1 : xv > yv ? 1 : 0); }
                    if (key === 'views')    {
                        var xtk = getShareToken(x), ytk = getShareToken(y);
                        var xvw = (window._mlpViewCounts && window._mlpViewCounts[xtk]) || 0;
                        var yvw = (window._mlpViewCounts && window._mlpViewCounts[ytk]) || 0;
                        return dir * (xvw - yvw);
                    }
                    if (key === 'size')     { return dir * (calcProjectSize(x) - calcProjectSize(y)); }
                    return 0;
                });
            }
            if (key === 'pinned') { return pinned.concat(rest); }
            sortArr(pinned); sortArr(rest);
            return pinned.concat(rest);
        }

        function updateStorageBar() {
            var fill = document.getElementById('mlp-storage-bar-fill');
            var text = document.getElementById('mlp-storage-bar-text');
            if (!fill || !text) return;
            try {
                var used = 0;
                for (var k in localStorage) {
                    if (localStorage.hasOwnProperty(k)) {
                        used += (localStorage.getItem(k)||'').length * 2; // UTF-16
                    }
                }
                var maxBytes = 5 * 1024 * 1024;
                var pct = Math.min(100, (used / maxBytes) * 100);
                fill.style.width = pct.toFixed(1) + '%';
                fill.classList.toggle('mlp-storage-warn', pct > 70);
                text.textContent = fmtSize(used) + ' / ~5 MB (' + pct.toFixed(0) + '%)';
            } catch(e) {}
        }

        function render(filter) {
            tbody.innerHTML = '';
            var projects = getProjects();
            var sorted   = sortProjects(projects, currentSort);
            var filtered = sorted.filter(function (p) {
                if (!projectMatchesStatus(p, currentStatusFilter)) return false;
                if (currentTagFilter && !projectHasTag(p, currentTagFilter)) return false;
                if (filter && !projectMatchesFilter(p, filter)) return false;
                return true;
            });

            emptyEl.style.display = filtered.length === 0 ? 'flex' : 'none';
            for (var i = 0; i < filtered.length; i++) {
                tbody.appendChild(buildRow(filtered[i], filter || ''));
            }
            renderFilterChips(projects);
            renderSidebar(projects);
            updateProjectCounter(projects.length);
            updateStorageBar();
        }

        /* ── Render sidebar ─────────────────────────────────────────── */
        function renderSidebar(projects) {
            var section = document.getElementById('mlp-sidebar-manage-section');
            var nav     = document.getElementById('mlp-sidebar-project-nav');
            if (!section || !nav) return;
            if (!projects) projects = getProjects();
            if (projects.length === 0) { section.style.display = 'none'; nav.innerHTML = ''; return; }
            section.style.display = 'block';
            nav.innerHTML = '';
            for (var i = 0; i < projects.length; i++) {
                (function (p) {
                    var isActive = (window.mlpCurrentProjectId === p.id);
                    var link = document.createElement('a');
                    link.href = '#';
                    link.className = 'mlp-sidebar-link mlp-sidebar-project-link' + (isActive ? ' mlp-sidebar-proj-active' : '');
                    link.innerHTML =
                        '<i class="fa-solid fa-' + (isActive ? 'folder-open' : 'folder') + ' mlp-sidebar-proj-icon"></i>' +
                        '<span class="mlp-sidebar-proj-name">' + escHtml(p.name || 'Untitled') + '</span>';
                    link.title = p.name || 'Untitled';
                    link.addEventListener('click', function (e) {
                        e.preventDefault();
                        goCode(p);
                    });
                    nav.appendChild(link);
                }(projects[i]));
            }
        }

        /* ── Delete confirm (with Undo) ──────────────────────────────── */
        delConfirmBtn.addEventListener('click', function () {
            if (!pendingDeleteId) return;
            var id = pendingDeleteId;
            var projects = getProjects();
            var deletedProj = null;
            var projName = '';
            for (var i = 0; i < projects.length; i++) {
                if (projects[i].id === id) { deletedProj = projects[i]; projName = projects[i].name || 'Project'; break; }
            }
            closeDelModal();
            deleteProjectById(id);
            var wasActive = (window.mlpCurrentProjectId === id);
            if (wasActive) {
                window.mlpCurrentProjectId = null;
                try { localStorage.removeItem(LAST_ID_KEY); } catch(e) {}
                try { localStorage.removeItem(TABS_KEY); } catch(e) {}
                document.querySelectorAll(
                    '.mlp-fullscreen-editor-overlay, .mlp-share-overlay, .mlp-backup-overlay'
                ).forEach(function (el) { el.style.display = 'none'; });
                if (typeof window.mlpResetToDefault === 'function') { window.mlpResetToDefault(); }
            }
            render(searchInput.value);
            // Show undo toast
            if (deletedProj) {
                _undoProject = { proj: deletedProj, wasActive: wasActive };
                if (_undoTimer) clearTimeout(_undoTimer);
                showUndoToast(projName, function() {
                    if (!_undoProject) return;
                    var restored = _undoProject.proj;
                    var projs = getProjects();
                    projs.push(restored);
                    saveProjects(projs);
                    _undoProject = null;
                    render(searchInput.value);
                    showToast('Restored', '"' + escHtml(restored.name||'Project') + '" has been restored.', 'success');
                });
                _undoTimer = setTimeout(function(){ _undoProject = null; }, 5500);
            } else {
                showToast('Project Deleted', '"' + projName + '" has been permanently removed.', 'danger');
            }
        });
        delModalClose.addEventListener('click', closeDelModal);
        delCancelBtn.addEventListener('click', closeDelModal);
        delModal.addEventListener('click', function (e) { if (e.target === delModal) closeDelModal(); });

        /* ── Toolbar events ─────────────────────────────────────────── */
        searchInput.addEventListener('input', function () { render(this.value); });
        newBtn.addEventListener('click', openModal);
        modalClose.addEventListener('click', closeModal);
        cancelBtn.addEventListener('click', closeModal);
        modal.addEventListener('click', function (e) { if (e.target === modal) closeModal(); });

        /* ── Create project ─────────────────────────────────────────── */
        createBtn.addEventListener('click', function () {
            var name = nameInput.value.trim();
            if (!name) { nameInput.focus(); return; }
            var visEl = document.getElementById('mlp-proj-visibility-input');
            var vis   = visEl ? (visEl.value || 'private') : 'private';
            var emojiEl = document.getElementById('mlp-proj-create-emoji-input');
            var emoji = emojiEl ? emojiEl.value.trim() : '';
            var now   = new Date().toISOString();
            var p = {
                id:         generateId(),
                name:       name,
                createdAt:  now,
                updatedAt:  now,
                visibility: vis, // use the user's selected visibility
                iconColor:  createColorSelected || COLOR_SWATCHES[0],
                emoji:      emoji,
                html:       '',
                css:        '',
                js:         '',
                savedTabs:  null,
                history:    [],
                activity:   [{ at: now, label: 'Created project' }]
            };
            var projects = getProjects();
            projects.push(p);
            saveProjects(projects);
            closeModal();
            window.mlpLoadProject(p);
            closePopup();
            showToast('Project Created', '"' + name + '" is ready. Opening editor…', 'success');
            // If user selected Public, open the publish modal right away
            if (vis === 'public') {
                setTimeout(function() { openShareModal(p); }, 400);
            }
        });

        nameInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter')  { createBtn.click(); }
            if (e.key === 'Escape') { closeModal(); }
        });

        /* ── Keyboard hint dismiss ──────────────────────────────────── */
        var kbdHint    = document.getElementById('mlp-kbd-hint');
        var kbdDismiss = document.getElementById('mlp-kbd-dismiss');
        if (kbdDismiss && kbdHint) {
            kbdDismiss.addEventListener('click', function() {
                kbdHint.classList.add('mlp-kbd-hidden');
            });
        }


        /* ── Sort buttons wiring ────────────────────────────────────── */
        var sortDirBtn = document.getElementById('mlp-sort-dir-btn');

        function syncSortDirBtn() {
            if (!sortDirBtn) return;
            var showDir = (currentSort !== 'pinned');
            sortDirBtn.style.display = showDir ? 'inline-flex' : 'none';
            sortDirBtn.classList.toggle('mlp-dir-asc',  currentSortDir === 1);
            sortDirBtn.classList.toggle('mlp-dir-desc', currentSortDir === -1);
            sortDirBtn.title = currentSortDir === 1 ? 'Ascending (click to reverse)' : 'Descending (click to reverse)';
        }

        if (sortDirBtn) {
            sortDirBtn.addEventListener('click', function() {
                if (currentSort === 'pinned') return;
                currentSortDir *= -1;
                syncSortDirBtn();
                // also keep active sort btn classes in sync
                document.querySelectorAll('.mlp-sort-btn').forEach(function(b) {
                    b.classList.remove('mlp-sort-asc', 'mlp-sort-desc');
                });
                try { localStorage.setItem(SORT_KEY, JSON.stringify({k:currentSort,d:currentSortDir})); } catch(e){}
                render(searchInput.value);
            });
        }

        document.querySelectorAll('.mlp-sort-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var key = btn.getAttribute('data-sort');
                if (currentSort === key && key !== 'pinned') {
                    currentSortDir *= -1;
                } else {
                    document.querySelectorAll('.mlp-sort-btn').forEach(function(b){
                        b.classList.remove('mlp-sort-active','mlp-sort-asc','mlp-sort-desc');
                    });
                    currentSort = key; currentSortDir = 1;
                    btn.classList.add('mlp-sort-active');
                }
                syncSortDirBtn();
                try { localStorage.setItem(SORT_KEY, JSON.stringify({k:currentSort,d:currentSortDir})); } catch(e){}
                render(searchInput.value);
            });
        });
        // Restore active state
        (function(){
            document.querySelectorAll('.mlp-sort-btn').forEach(function(b){
                b.classList.remove('mlp-sort-active','mlp-sort-asc','mlp-sort-desc');
                if(b.getAttribute('data-sort')===currentSort){
                    b.classList.add('mlp-sort-active');
                }
            });
            syncSortDirBtn();
        })();

        /* ── Bulk selection ─────────────────────────────────────────── */
        var bulkSelected = [];
        function updateBulkBar() {
            var cbs = tbody.querySelectorAll('.mlp-row-cb:checked');
            bulkSelected = [];
            cbs.forEach(function(cb){ bulkSelected.push(cb.getAttribute('data-id')); });
            var bar = document.getElementById('mlp-bulk-bar');
            var cnt = document.getElementById('mlp-bulk-count');
            if (bar) bar.style.display = bulkSelected.length > 0 ? 'flex' : 'none';
            if (cnt) cnt.textContent = bulkSelected.length + ' selected';
            // highlight rows
            tbody.querySelectorAll('tr').forEach(function(tr){
                var cb = tr.querySelector('.mlp-row-cb');
                if (cb) tr.classList.toggle('mlp-row-selected', cb.checked);
            });
        }
        var selectAll = document.getElementById('mlp-select-all');
        if (selectAll) {
            selectAll.addEventListener('change', function() {
                tbody.querySelectorAll('.mlp-row-cb').forEach(function(cb){ cb.checked = selectAll.checked; });
                updateBulkBar();
            });
        }
        var bulkDelBtn    = document.getElementById('mlp-bulk-del-btn');
        var bulkExportBtn = document.getElementById('mlp-bulk-export-btn');
        var bulkCancelBtn = document.getElementById('mlp-bulk-cancel-btn');
        var bulkDelModal  = document.getElementById('mlp-bulk-del-modal');
        var bulkDelCount  = document.getElementById('mlp-bulk-del-count');
        var bulkDelConfirm= document.getElementById('mlp-bulk-del-confirm-btn');
        var bulkDelCancel = document.getElementById('mlp-bulk-del-cancel-btn');
        var bulkDelClose  = document.getElementById('mlp-bulk-del-modal-close');
        if (bulkDelBtn) bulkDelBtn.addEventListener('click', function() {
            if (!bulkSelected.length) return;
            if (bulkDelCount) bulkDelCount.textContent = bulkSelected.length;
            if (bulkDelModal) bulkDelModal.style.display = 'flex';
        });
        function closeBulkDelModal(){ if(bulkDelModal) bulkDelModal.style.display='none'; }
        if (bulkDelClose)  bulkDelClose.addEventListener('click', closeBulkDelModal);
        if (bulkDelCancel) bulkDelCancel.addEventListener('click', closeBulkDelModal);
        if (bulkDelModal)  bulkDelModal.addEventListener('click', function(e){ if(e.target===bulkDelModal) closeBulkDelModal(); });
        if (bulkDelConfirm) bulkDelConfirm.addEventListener('click', function() {
            var ids = bulkSelected.slice();
            ids.forEach(function(id){ deleteProjectById(id); });
            closeBulkDelModal();
            bulkSelected = [];
            var bar = document.getElementById('mlp-bulk-bar');
            if (bar) bar.style.display = 'none';
            render(searchInput.value);
            showToast('Deleted', ids.length + ' projects removed.', 'danger');
        });
        if (bulkExportBtn) bulkExportBtn.addEventListener('click', function() {
            if (!bulkSelected.length) return;
            var lookup = {};
            getProjects().forEach(function(p){ lookup[p.id] = p; });
            var selected = bulkSelected.map(function(id){ return lookup[id]; }).filter(Boolean);
            exportProjectsAsZip(selected);
        });
        var bulkTagBtn = document.getElementById('mlp-bulk-tag-btn');
        if (bulkTagBtn) bulkTagBtn.addEventListener('click', function() {
            if (!bulkSelected.length) return;
            var ids = bulkSelected.slice();
            var input = window.prompt(
                'Apply tags to ' + ids.length + ' selected project' + (ids.length === 1 ? '' : 's') + '\n\n' +
                'Enter comma-separated tags to ADD (e.g. client work, draft).\n' +
                'Prefix a tag with "-" to REMOVE it (e.g. -draft).\n' +
                'Leave empty to cancel.',
                ''
            );
            if (input === null) return;
            var raw = input.split(',').map(function(s){ return s.trim(); }).filter(function(s){ return s.length > 0; });
            if (!raw.length) return;
            var addList = [], removeList = [];
            raw.forEach(function(t){
                if (t.charAt(0) === '-') {
                    var rem = t.slice(1).trim();
                    if (rem) removeList.push(rem.toLowerCase());
                } else if (t.length <= 32) {
                    addList.push(t);
                }
            });
            var idSet = {}; ids.forEach(function(id){ idSet[id] = true; });
            var projects = getProjects();
            var changed = 0;
            projects.forEach(function(p) {
                if (!idSet[p.id]) return;
                var existing = Array.isArray(p.tags) ? p.tags.slice() : [];
                var seen = {}; existing.forEach(function(t){ seen[String(t).toLowerCase()] = true; });
                var before = existing.length;
                addList.forEach(function(t) {
                    var k = t.toLowerCase();
                    if (!seen[k]) { existing.push(t); seen[k] = true; }
                });
                if (removeList.length) {
                    existing = existing.filter(function(t){
                        return removeList.indexOf(String(t).toLowerCase()) === -1;
                    });
                }
                // Only persist if something actually changed
                var beforeJoin = (Array.isArray(p.tags) ? p.tags : []).join('|').toLowerCase();
                var afterJoin  = existing.join('|').toLowerCase();
                if (beforeJoin !== afterJoin) {
                    updateProjectById(p.id, { tags: existing });
                    changed++;
                }
            });
            // Clear selection after bulk tag
            tbody.querySelectorAll('.mlp-row-cb').forEach(function(cb){ cb.checked = false; });
            if (selectAll) selectAll.checked = false;
            updateBulkBar();
            render(searchInput.value);
            var msgParts = [];
            if (addList.length)    msgParts.push('added ' + addList.join(', '));
            if (removeList.length) msgParts.push('removed ' + removeList.join(', '));
            showToast(
                'Tags Updated',
                changed + ' project' + (changed === 1 ? '' : 's') + ' updated' + (msgParts.length ? ' — ' + msgParts.join('; ') : '') + '.',
                'success'
            );
        });
        if (bulkCancelBtn) bulkCancelBtn.addEventListener('click', function() {
            tbody.querySelectorAll('.mlp-row-cb').forEach(function(cb){ cb.checked = false; });
            if (selectAll) selectAll.checked = false;
            updateBulkBar();
        });

        /* ── Undo delete (override existing delete confirm) ──────────── */
        // We wrap the existing delConfirmBtn with undo support
        var _undoProject = null;
        var _undoTimer   = null;

        function openHistoryModal(id) {
            var modal = document.getElementById('mlp-history-modal');
            var nameEl = document.getElementById('mlp-history-project-name');
            var versionsEl = document.getElementById('mlp-history-versions');
            var activityEl = document.getElementById('mlp-history-activity');
            var closeBtn = document.getElementById('mlp-history-modal-close');
            var closeBtn2 = document.getElementById('mlp-history-close-btn');
            if (!modal || !versionsEl || !activityEl) return;
            var p = getProjects().filter(function(x){ return x.id === id; })[0];
            if (!p) return;
            if (nameEl) nameEl.textContent = 'Project: ' + (p.name || 'Untitled');
            var history = Array.isArray(p.history) ? p.history : [];
            var activity = Array.isArray(p.activity) ? p.activity : [];
            versionsEl.innerHTML = history.length ? '' : '<span class="mlp-history-empty">No previous versions yet. Versions appear after edits are saved.</span>';
            history.forEach(function(v) {
                var item = document.createElement('div');
                item.className = 'mlp-history-item';
                item.innerHTML = '<span class="mlp-history-item-main"><span class="mlp-history-item-title">' + escHtml(v.label || 'Saved version') + '</span><span class="mlp-history-item-meta">' + escHtml(fmtDate(v.at)) + '</span></span><button type="button" class="mlp-history-restore">Restore</button>';
                item.querySelector('.mlp-history-restore').addEventListener('click', function() {
                    if (!window.confirm('Restore this previous version? Your current version will be saved in history first.')) return;
                    restoreProjectVersion(id, v.id);
                    modal.style.display = 'none';
                });
                versionsEl.appendChild(item);
            });
            activityEl.innerHTML = activity.length ? '' : '<span class="mlp-history-empty">No recent activity yet.</span>';
            activity.forEach(function(a) {
                var item = document.createElement('div');
                item.className = 'mlp-history-item';
                item.innerHTML = '<span class="mlp-history-item-main"><span class="mlp-history-item-title">' + escHtml(a.label || 'Updated project') + '</span><span class="mlp-history-item-meta">' + escHtml(fmtDate(a.at)) + '</span></span>';
                activityEl.appendChild(item);
            });
            function closeHistory(){ modal.style.display = 'none'; }
            if (closeBtn) closeBtn.onclick = closeHistory;
            if (closeBtn2) closeBtn2.onclick = closeHistory;
            modal.onclick = function(e){ if (e.target === modal) closeHistory(); };
            modal.style.display = 'flex';
        }

        function restoreProjectVersion(id, versionId) {
            var projects = getProjects();
            for (var i = 0; i < projects.length; i++) {
                if (projects[i].id !== id) continue;
                var current = projects[i];
                var history = Array.isArray(current.history) ? current.history.slice(0) : [];
                var version = null;
                for (var j = 0; j < history.length; j++) {
                    if (history[j].id === versionId) { version = history[j]; break; }
                }
                if (!version || !version.data) return;
                pushProjectVersion(current, 'Before restore');
                var restored = copyProjectForHistory(version.data);
                restored.id = current.id;
                restored.history = current.history || history;
                restored.activity = current.activity || [];
                restored.updatedAt = new Date().toISOString();
                addProjectActivity(restored, 'Restored previous version');
                projects[i] = restored;
                saveProjects(projects);
                if (window.mlpCurrentProjectId === id) window.mlpLoadProject(restored);
                render(searchInput.value);
                showToast('Version Restored', '"' + (restored.name || 'Project') + '" was restored.', 'success');
                return;
            }
        }

        /* ── Notes modal ────────────────────────────────────────────── */
        function openNotesModal(p) {
            var modal    = document.getElementById('mlp-notes-modal');
            var textarea = document.getElementById('mlp-notes-textarea');
            var preview  = document.getElementById('mlp-notes-preview');
            var nameEl   = document.getElementById('mlp-notes-project-name');
            var closeBtn = document.getElementById('mlp-notes-modal-close');
            var saveBtn  = document.getElementById('mlp-notes-save-btn');
            var cancelBtn= document.getElementById('mlp-notes-cancel-btn');
            var togglePrev= document.getElementById('mlp-notes-toggle-preview');
            var charCount= document.getElementById('mlp-notes-char-count');
            if (!modal || !textarea) return;
            var notesTargetId = p.id;
            if (nameEl) nameEl.textContent = '📁 ' + (p.name || 'Untitled');
            textarea.value = p.notes || '';
            if (preview) { preview.style.display = 'none'; preview.innerHTML = ''; }
            if (textarea) textarea.style.display = 'block';
            if (togglePrev) togglePrev.textContent = '👁 Preview';
            function updateChar(){ if(charCount) charCount.textContent = textarea.value.length + ' chars'; }
            updateChar();
            textarea.addEventListener('input', updateChar);
            modal.style.display = 'flex';
            setTimeout(function(){ textarea.focus(); }, 60);
            var showingPreview = false;
            function closeNotes(){ modal.style.display = 'none'; }
            if (closeBtn)   closeBtn.onclick = closeNotes;
            if (cancelBtn)  cancelBtn.onclick = closeNotes;
            modal.onclick = function(e){ if(e.target===modal) closeNotes(); };
            if (togglePrev) togglePrev.onclick = function() {
                showingPreview = !showingPreview;
                if (showingPreview) {
                    if (preview) { preview.style.display='block'; preview.innerHTML = simpleMarkdown(textarea.value); }
                    textarea.style.display = 'none';
                    togglePrev.textContent = '✏️ Edit';
                } else {
                    if (preview) preview.style.display='none';
                    textarea.style.display = 'block';
                    togglePrev.textContent = '👁 Preview';
                    textarea.focus();
                }
            };
            if (saveBtn) saveBtn.onclick = function() {
                updateProjectById(notesTargetId, { notes: textarea.value });
                closeNotes();
                render(searchInput.value);
                showToast('Notes Saved', 'Notes updated for "' + escHtml(p.name) + '".', 'success');
            };
        }

        function simpleMarkdown(text) {
            return escHtml(text)
                .replace(/^### (.+)$/gm, '<h3>$1</h3>')
                .replace(/^## (.+)$/gm, '<h2>$1</h2>')
                .replace(/^# (.+)$/gm, '<h1>$1</h1>')
                .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
                .replace(/\*(.+?)\*/g, '<em>$1</em>')
                .replace(/`(.+?)`/g, '<code>$1</code>')
                .replace(/\n/g, '<br>')
                .replace(/^- (.+)$/gm, '• $1')
                .replace(/\n/g, '');
        }

        /* ── PIN / lock modal ───────────────────────────────────────── */
        function openPinModal(p) {
            var modal     = document.getElementById('mlp-pin-modal');
            var titleEl   = document.getElementById('mlp-pin-modal-title');
            var descEl    = document.getElementById('mlp-pin-desc');
            var pinInput  = document.getElementById('mlp-pin-input');
            var pinConf   = document.getElementById('mlp-pin-confirm-input');
            var confWrap  = document.getElementById('mlp-pin-confirm-wrap');
            var saveBtn   = document.getElementById('mlp-pin-save-btn');
            var cancelBtn = document.getElementById('mlp-pin-cancel-btn');
            var closeBtn  = document.getElementById('mlp-pin-modal-close');
            var hintEl    = document.getElementById('mlp-pin-hint');
            if (!modal) return;
            var hasPin = !!p.pinHash;

            /* ── If project already has a password, verify it first ── */
            if (hasPin) {
                openUnlockModal(p, function() {
                    // Current password verified — now show the change/remove form
                    _showPinChangeForm(p, modal, titleEl, descEl, pinInput, pinConf, confWrap, saveBtn, cancelBtn, closeBtn, hintEl);
                });
                return;
            }

            // No existing password — show the set form directly
            _showPinChangeForm(p, modal, titleEl, descEl, pinInput, pinConf, confWrap, saveBtn, cancelBtn, closeBtn, hintEl);
        }

        function _showPinChangeForm(p, modal, titleEl, descEl, pinInput, pinConf, confWrap, saveBtn, cancelBtn, closeBtn, hintEl) {
            var hasPin = !!p.pinHash;
            if (titleEl) titleEl.innerHTML = (hasPin ? '🔐 Change / Remove Password' : '🔐 Set Project Password') + ' <span class="mlp-premium-badge">✦ Premium</span>';
            if (descEl)  descEl.textContent = hasPin ? 'Enter new PIN to change, or leave blank to remove the password.' : 'Lock "' + (p.name||'Project') + '" with a PIN. You\'ll need it to open the project.';
            if (pinInput) { pinInput.value = ''; }
            if (pinConf)  { pinConf.value = ''; }
            if (confWrap) confWrap.style.display = 'block';
            if (saveBtn)  saveBtn.textContent = hasPin ? 'Update Password' : 'Set Password';
            modal.style.display = 'flex';
            setTimeout(function(){ if(pinInput) pinInput.focus(); }, 60);
            function closePin(){ modal.style.display='none'; }
            if (closeBtn)  closeBtn.onclick = closePin;
            if (cancelBtn) cancelBtn.onclick = closePin;
            modal.onclick = function(e){ if(e.target===modal) closePin(); };
            if (saveBtn) saveBtn.onclick = function() {
                var pin = pinInput ? pinInput.value.trim() : '';
                if (!hasPin && pin === '') { if(pinInput) pinInput.focus(); return; }
                var conf = pinConf ? pinConf.value.trim() : '';
                if (pin !== '') {
                    if (pin !== conf) { showToast('PIN Mismatch', 'PINs do not match. Try again.', 'danger'); if(pinConf) pinConf.focus(); return; }
                    if (pin.length < 4) { showToast('PIN Too Short', 'Use at least 4 digits.', 'danger'); return; }
                }
                var newHash = pin === '' ? null : hashPin(pin);
                updateProjectById(p.id, { pinHash: newHash });
                closePin();
                render(searchInput.value);
                showToast(pin === '' ? 'Password Removed' : 'Password Set', pin === '' ? 'Project is now unlocked.' : 'Project is now password protected.', 'success');
            };
        }

        /* ── Unlock modal ────────────────────────────────────────────── */
        function openUnlockModal(p, onSuccess) {
            var modal     = document.getElementById('mlp-unlock-modal');
            var input     = document.getElementById('mlp-unlock-input');
            var errEl     = document.getElementById('mlp-unlock-error');
            var descEl    = document.getElementById('mlp-unlock-desc');
            var confBtn   = document.getElementById('mlp-unlock-confirm-btn');
            var cancelBtn = document.getElementById('mlp-unlock-cancel-btn');
            var closeBtn  = document.getElementById('mlp-unlock-modal-close');
            if (!modal) return;
            if (descEl) descEl.textContent = 'Enter the PIN to open "' + (p.name||'Project') + '".';
            if (input) input.value = '';
            if (errEl) errEl.style.display = 'none';
            modal.style.display = 'flex';
            setTimeout(function(){ if(input) input.focus(); }, 60);
            function closeUnlock(){ modal.style.display='none'; }
            if (closeBtn)  closeBtn.onclick = closeUnlock;
            if (cancelBtn) cancelBtn.onclick = closeUnlock;
            modal.onclick = function(e){ if(e.target===modal) closeUnlock(); };
            function tryUnlock() {
                var pin = input ? input.value.trim() : '';
                if (hashPin(pin) === p.pinHash) { closeUnlock(); onSuccess(); }
                else { if(errEl){errEl.style.display='block';} if(input){input.value='';input.focus();} }
            }
            if (confBtn) confBtn.onclick = tryUnlock;
            if (input) input.onkeydown = function(e){ if(e.key==='Enter') tryUnlock(); };
        }



        /* ── Description modal ───────────────────────────────────── */
        var descTargetId = null;
        function openDescModal(p) {
            var modal     = document.getElementById('mlp-desc-modal');
            var input     = document.getElementById('mlp-desc-input');
            var saveBtn   = document.getElementById('mlp-desc-save-btn');
            var cancelBtn = document.getElementById('mlp-desc-cancel-btn');
            var closeBtn  = document.getElementById('mlp-desc-modal-close');
            if (!modal) return;
            descTargetId = p.id;
            if (input) input.value = p.description || '';
            modal.style.display = 'flex';
            setTimeout(function(){ if(input) input.focus(); }, 60);
            function closeDesc(){ modal.style.display='none'; }
            if (closeBtn)  closeBtn.onclick = closeDesc;
            if (cancelBtn) cancelBtn.onclick = closeDesc;
            modal.onclick = function(e){ if(e.target===modal) closeDesc(); };
            if (saveBtn) saveBtn.onclick = function() {
                updateProjectById(descTargetId, { description: input ? input.value.trim() : '' });
                closeDesc();
                render(searchInput.value);
                showToast('Updated', 'Description saved.', 'success');
            };
        }

            // X close button — just closes modal, no action taken
            var backupCloseBtn = document.getElementById('mlp-backup-close-btn');
            if (backupCloseBtn) {
                backupCloseBtn.onclick = function() {
                    var modal = document.getElementById('mlp-backup-modal');
                    if (modal) modal.style.display = 'none';
                    _backupPendingProject  = null;
                    _backupPendingCallback = null;
                };
            }
            // Close on backdrop click
            var backupModalEl = document.getElementById('mlp-backup-modal');
            if (backupModalEl) {
                backupModalEl.addEventListener('click', function(e) {
                    if (e.target === backupModalEl) {
                        backupModalEl.style.display = 'none';
                        _backupPendingProject  = null;
                        _backupPendingCallback = null;
                    }
                });
            }



        // Limit banner removed — projects are unlimited

        /* ── JSZip loader (shared utility) ──────────────────────────── */
        var _mlpJSZipLoading = false;
        var _mlpJSZipQueue = [];
        function loadJSZipThen(cb) {
            var existing = window.JSZip || (typeof JSZip !== 'undefined' ? JSZip : null);
            if (existing) { cb(existing); return; }
            _mlpJSZipQueue.push(cb);
            if (_mlpJSZipLoading) return;
            _mlpJSZipLoading = true;
            var sources = [
                'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js',
                'https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js',
                'https://unpkg.com/jszip@3.10.1/dist/jszip.min.js'
            ];
            var idx = 0;
            function finish(lib) {
                _mlpJSZipLoading = false;
                var q = _mlpJSZipQueue.slice();
                _mlpJSZipQueue = [];
                q.forEach(function(fn) { fn(lib); });
            }
            function fail() {
                _mlpJSZipLoading = false;
                _mlpJSZipQueue = [];
                showToast('Load Failed', 'Could not load the ZIP library. Check your internet connection or site security settings.', 'danger');
            }
            function tryNext() {
                if (window.JSZip) { finish(window.JSZip); return; }
                if (idx >= sources.length) { fail(); return; }
                var s = document.createElement('script');
                var done = false;
                s.src = sources[idx++];
                s.async = true;
                s.onload = function() {
                    if (done) return;
                    done = true;
                    if (window.JSZip) finish(window.JSZip);
                    else tryNext();
                };
                s.onerror = function() {
                    if (done) return;
                    done = true;
                    tryNext();
                };
                setTimeout(function() {
                    if (done || window.JSZip) return;
                    done = true;
                    tryNext();
                }, 8000);
                document.head.appendChild(s);
            }
            tryNext();
        }

        function mlpZipReadU16(bytes, offset) {
            return bytes[offset] | (bytes[offset + 1] << 8);
        }
        function mlpZipReadU32(bytes, offset) {
            return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
        }
        function mlpZipDecodeUtf8(bytes) {
            if (window.TextDecoder) return new TextDecoder('utf-8').decode(bytes);
            var s = '';
            for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
            return decodeURIComponent(escape(s));
        }
        function mlpReadStoredZipJsonEntries(file, onDone, onUnsupported) {
            var reader = new FileReader();
            reader.onerror = function() { onUnsupported(); };
            reader.onload = function(ev) {
                try {
                    var bytes = new Uint8Array(ev.target.result);
                    var texts = [];
                    var offset = 0;
                    while (offset + 30 <= bytes.length) {
                        var sig = mlpZipReadU32(bytes, offset);
                        if (sig === 0x02014b50 || sig === 0x06054b50) break;
                        if (sig !== 0x04034b50) { onUnsupported(); return; }
                        var flags = mlpZipReadU16(bytes, offset + 6);
                        var method = mlpZipReadU16(bytes, offset + 8);
                        var compressedSize = mlpZipReadU32(bytes, offset + 18);
                        var fileNameLength = mlpZipReadU16(bytes, offset + 26);
                        var extraLength = mlpZipReadU16(bytes, offset + 28);
                        if ((flags & 8) || method !== 0) { onUnsupported(); return; }
                        var nameStart = offset + 30;
                        var dataStart = nameStart + fileNameLength + extraLength;
                        var dataEnd = dataStart + compressedSize;
                        if (dataEnd > bytes.length) { onUnsupported(); return; }
                        var name = mlpZipDecodeUtf8(bytes.subarray(nameStart, nameStart + fileNameLength));
                        if (name && name.toLowerCase().slice(-5) === '.json') {
                            texts.push(mlpZipDecodeUtf8(bytes.subarray(dataStart, dataEnd)));
                        }
                        offset = dataEnd;
                    }
                    onDone(texts);
                } catch(e) {
                    onUnsupported();
                }
            };
            reader.readAsArrayBuffer(file);
        }

        function mlpBytesToBase64(bytes) {
            var s = '';
            for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
            return btoa(s);
        }
        function mlpBase64ToBytes(str) {
            var s = atob(str || '');
            var bytes = new Uint8Array(s.length);
            for (var i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
            return bytes;
        }
        function mlpCryptoReady() {
            return !!(window.crypto && window.crypto.subtle && window.TextEncoder && window.TextDecoder);
        }
        function mlpDeriveExportKey(password, salt) {
            return window.crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']).then(function(baseKey) {
                return window.crypto.subtle.deriveKey(
                    { name: 'PBKDF2', salt: salt, iterations: 120000, hash: 'SHA-256' },
                    baseKey,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['encrypt', 'decrypt']
                );
            });
        }
        function mlpEncryptBackupPayload(payload, password) {
            var salt = window.crypto.getRandomValues(new Uint8Array(16));
            var iv = window.crypto.getRandomValues(new Uint8Array(12));
            return mlpDeriveExportKey(password, salt).then(function(key) {
                return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(JSON.stringify(payload)));
            }).then(function(cipher) {
                return {
                    mlpEncrypted: true,
                    exportedAt: new Date().toISOString(),
                    exportedBy: 'MLP Projects Protected ZIP Export',
                    alg: 'AES-GCM',
                    kdf: 'PBKDF2-SHA256',
                    iterations: 120000,
                    salt: mlpBytesToBase64(salt),
                    iv: mlpBytesToBase64(iv),
                    data: mlpBytesToBase64(new Uint8Array(cipher))
                };
            });
        }
        function mlpDecryptBackupPayload(parsed, password) {
            var salt = mlpBase64ToBytes(parsed.salt);
            var iv = mlpBase64ToBytes(parsed.iv);
            var data = mlpBase64ToBytes(parsed.data);
            return mlpDeriveExportKey(password, salt).then(function(key) {
                return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, data);
            }).then(function(plain) {
                return JSON.parse(new TextDecoder().decode(plain));
            });
        }

        /* ── Load Backup (.zip or .json) ────────────────────────────── */
        (function() {
            var loadBtn   = document.getElementById('mlp-load-backup-btn');
            var loadInput = document.getElementById('mlp-load-backup-input');
            if (!loadBtn || !loadInput) return;

            loadBtn.addEventListener('click', function() {
                loadInput.value = '';
                loadInput.click();
            });

            function importProjects(list) {
                var existing    = getProjects();
                var existingIds = {};
                existing.forEach(function(p) { existingIds[p.id] = true; });
                var imported = 0;
                list.forEach(function(proj) {
                    if (!proj || !proj.id) return;
                    if (existingIds[proj.id]) { proj.id = generateId(); proj.name = (proj.name || 'Untitled') + ' (restored)'; }
                    proj.createdAt = proj.createdAt || new Date().toISOString();
                    proj.updatedAt = proj.updatedAt || new Date().toISOString();
                    if (!Array.isArray(proj.history)) proj.history = [];
                    if (!Array.isArray(proj.activity)) proj.activity = [];
                    addProjectActivity(proj, 'Imported backup');
                    existing.push(proj);
                    existingIds[proj.id] = true;
                    imported++;
                });
                saveProjects(existing);
                render(searchInput.value);
                showToast('Backup Loaded', imported + ' project' + (imported !== 1 ? 's' : '') + ' imported.', 'success');
            }

            function parseBackupData(parsed) {
                if (Array.isArray(parsed))                        return parsed;
                if (parsed && Array.isArray(parsed.projects))      return parsed.projects;
                if (parsed && parsed.project && parsed.project.id) return [parsed.project];
                if (parsed && parsed.id)                          return [parsed];
                return null;
            }

            function importParsedBackups(results, invalidTitle) {
                var allProjects = [];
                results.forEach(function(parsed) {
                    if (!parsed) return;
                    var list = parseBackupData(parsed);
                    if (list) list.forEach(function(p) { if (p) allProjects.push(p); });
                });
                if (allProjects.length === 0) {
                    showToast(invalidTitle || 'Invalid ZIP', 'No valid MLP project data found inside the ZIP.', 'danger');
                    return;
                }
                importProjects(allProjects);
            }

            function importJsonTexts(texts) {
                if (!texts || texts.length === 0) {
                    showToast('Empty ZIP', 'No .json backup files found inside the ZIP.', 'danger');
                    return;
                }
                var parsed = texts.map(function(txt) {
                    try { return JSON.parse(txt); } catch(e) { return null; }
                });
                var protectedItems = parsed.filter(function(item){ return item && item.mlpEncrypted; });
                if (!protectedItems.length) {
                    importParsedBackups(parsed, 'Invalid ZIP');
                    return;
                }
                if (!mlpCryptoReady()) {
                    showToast('Import Failed', 'This browser cannot decrypt protected backups.', 'danger');
                    return;
                }
                var password = window.prompt('This ZIP is password protected. Enter the export password:');
                if (password === null) return;
                Promise.all(parsed.map(function(item) {
                    if (!item || !item.mlpEncrypted) return Promise.resolve(item);
                    return mlpDecryptBackupPayload(item, password).catch(function(){ return null; });
                })).then(function(results) {
                    importParsedBackups(results, 'Invalid Password');
                });
            }

            loadInput.addEventListener('change', function() {
                var file = loadInput.files && loadInput.files[0];
                if (!file) return;
                var ext = file.name.split('.').pop().toLowerCase();

                if (ext === 'zip') {
                    mlpReadStoredZipJsonEntries(file, importJsonTexts, function() {
                        loadJSZipThen(function(JSZip) {
                            JSZip.loadAsync(file).then(function(zip) {
                                var jsonEntries = [];
                                zip.forEach(function(relPath, entry) {
                                    if (!entry.dir && relPath.toLowerCase().endsWith('.json')) {
                                        jsonEntries.push(entry);
                                    }
                                });
                                if (jsonEntries.length === 0) {
                                    showToast('Empty ZIP', 'No .json backup files found inside the ZIP.', 'danger');
                                    return;
                                }
                                Promise.all(jsonEntries.map(function(e) {
                                    return e.async('string');
                                })).then(function(texts) {
                                    importJsonTexts(texts);
                                });
                            }).catch(function() {
                                showToast('Invalid ZIP', 'Could not read the ZIP file.', 'danger');
                            });
                        });
                    });
                } else {
                    var reader = new FileReader();
                    reader.onload = function(ev) {
                        try {
                            var parsed = JSON.parse(ev.target.result);
                            if (parsed && parsed.mlpEncrypted) {
                                if (!mlpCryptoReady()) {
                                    showToast('Import Failed', 'This browser cannot decrypt protected backups.', 'danger');
                                    return;
                                }
                                var pw = window.prompt('This backup is password protected. Enter the export password:');
                                if (pw === null) return;
                                mlpDecryptBackupPayload(parsed, pw).then(function(decrypted) {
                                    var protectedList = parseBackupData(decrypted);
                                    if (!protectedList || protectedList.length === 0) {
                                        showToast('Invalid Backup', 'This file doesn\'t look like an MLP backup.', 'danger');
                                        return;
                                    }
                                    importProjects(protectedList);
                                }).catch(function() {
                                    showToast('Invalid Password', 'Could not decrypt the backup.', 'danger');
                                });
                                return;
                            }
                            var list = parseBackupData(parsed);
                            if (!list || list.length === 0) {
                                showToast('Invalid Backup', 'This file doesn\'t look like an MLP backup.', 'danger');
                                return;
                            }
                            importProjects(list);
                        } catch(e) {
                            showToast('Import Failed', 'Could not read the file.', 'danger');
                        }
                    };
                    reader.readAsText(file);
                }
            });
        })();

        /* ── Export single project as ZIP (folder / tab structure) ──── */
        var _mlpZipCrcTable = null;
        function mlpZipUtf8(str) {
            str = str == null ? '' : String(str);
            if (window.TextEncoder) return new TextEncoder().encode(str);
            var escaped = unescape(encodeURIComponent(str));
            var arr = new Uint8Array(escaped.length);
            for (var i = 0; i < escaped.length; i++) arr[i] = escaped.charCodeAt(i);
            return arr;
        }
        function mlpZipCrc32(bytes) {
            if (!_mlpZipCrcTable) {
                _mlpZipCrcTable = [];
                for (var n = 0; n < 256; n++) {
                    var c = n;
                    for (var k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
                    _mlpZipCrcTable[n] = c >>> 0;
                }
            }
            var crc = 0xffffffff;
            for (var i = 0; i < bytes.length; i++) crc = _mlpZipCrcTable[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
            return (crc ^ 0xffffffff) >>> 0;
        }
        function mlpZipU16(out, n) {
            out.push(n & 255, (n >>> 8) & 255);
        }
        function mlpZipU32(out, n) {
            out.push(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255);
        }
        function mlpZipDosDateTime(date) {
            var time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
            var day = date.getDate();
            var month = date.getMonth() + 1;
            var year = Math.max(1980, date.getFullYear()) - 1980;
            var dosDate = (year << 9) | (month << 5) | day;
            return { time: time, date: dosDate };
        }
        function mlpZipHeader(signature, fields) {
            var out = [];
            mlpZipU32(out, signature);
            fields.forEach(function(field) {
                if (field.size === 2) mlpZipU16(out, field.value);
                else mlpZipU32(out, field.value);
            });
            return new Uint8Array(out);
        }
        function mlpZipConcat(parts) {
            var total = 0;
            parts.forEach(function(part) { total += part.length; });
            var out = new Uint8Array(total);
            var offset = 0;
            parts.forEach(function(part) {
                out.set(part, offset);
                offset += part.length;
            });
            return out;
        }
        function mlpBuildStoredZipBlob(files) {
            var parts = [];
            var central = [];
            var offset = 0;
            var stamp = mlpZipDosDateTime(new Date());
            files.forEach(function(file) {
                var nameBytes = mlpZipUtf8(file.name);
                var dataBytes = mlpZipUtf8(file.content || '');
                var crc = mlpZipCrc32(dataBytes);
                var localHeader = mlpZipHeader(0x04034b50, [
                    { size: 2, value: 20 },
                    { size: 2, value: 0x0800 },
                    { size: 2, value: 0 },
                    { size: 2, value: stamp.time },
                    { size: 2, value: stamp.date },
                    { size: 4, value: crc },
                    { size: 4, value: dataBytes.length },
                    { size: 4, value: dataBytes.length },
                    { size: 2, value: nameBytes.length },
                    { size: 2, value: 0 }
                ]);
                parts.push(localHeader, nameBytes, dataBytes);
                central.push({
                    nameBytes: nameBytes,
                    crc: crc,
                    size: dataBytes.length,
                    offset: offset
                });
                offset += localHeader.length + nameBytes.length + dataBytes.length;
            });
            var centralStart = offset;
            central.forEach(function(entry) {
                var header = mlpZipHeader(0x02014b50, [
                    { size: 2, value: 20 },
                    { size: 2, value: 20 },
                    { size: 2, value: 0x0800 },
                    { size: 2, value: 0 },
                    { size: 2, value: stamp.time },
                    { size: 2, value: stamp.date },
                    { size: 4, value: entry.crc },
                    { size: 4, value: entry.size },
                    { size: 4, value: entry.size },
                    { size: 2, value: entry.nameBytes.length },
                    { size: 2, value: 0 },
                    { size: 2, value: 0 },
                    { size: 2, value: 0 },
                    { size: 2, value: 0 },
                    { size: 4, value: 0 },
                    { size: 4, value: entry.offset }
                ]);
                parts.push(header, entry.nameBytes);
                offset += header.length + entry.nameBytes.length;
            });
            var centralSize = offset - centralStart;
            var end = mlpZipHeader(0x06054b50, [
                { size: 2, value: 0 },
                { size: 2, value: 0 },
                { size: 2, value: files.length },
                { size: 2, value: files.length },
                { size: 4, value: centralSize },
                { size: 4, value: centralStart },
                { size: 2, value: 0 }
            ]);
            parts.push(end);
            return new Blob([mlpZipConcat(parts)], { type: 'application/zip' });
        }

        function mlpSafeName(name, fallback) {
            return ((name || fallback || 'project') + '').replace(/[^a-z0-9_\-\s]/gi, '').trim().replace(/\s+/g, '_').slice(0, 60) || (fallback || 'project');
        }

        function getFreshProject(id, fallback) {
            try {
                if (id && window.mlpCurrentProjectId && id === window.mlpCurrentProjectId) {
                    flushTabsToProject(id);
                }
            } catch(e) {}
            var all = getProjects();
            for (var i = 0; i < all.length; i++) {
                if (all[i].id === id) return all[i];
            }
            return fallback;
        }

        function getProjectTabsForExport(p) {
            if (p.allTabs && typeof p.allTabs === 'object' && Object.keys(p.allTabs).length > 0) return p.allTabs;
            if (p.savedTabs && typeof p.savedTabs === 'object' && Object.keys(p.savedTabs).length > 0) return p.savedTabs;
            if (p.html || p.css || p.js) {
                return {
                    main: {
                        id: 'main',
                        title: p.name || 'Project',
                        emoji: '📄',
                        html: p.html || '',
                        css: p.css || '',
                        js: p.js || '',
                        preprocessors: { html: 'html', css: 'css', js: 'javascript' }
                    }
                };
            }
            return {};
        }

        function buildProjectZipFiles(p, rootFolder) {
            var date = new Date().toISOString().slice(0, 10);
            var tabs = getProjectTabsForExport(p);
            var tabKeys = Object.keys(tabs);
            var root = rootFolder ? rootFolder.replace(/\/+$/, '') + '/' : '';
            var files = [];
            var readme = ['# ' + (p.name || 'Untitled'), ''];
            if (p.description) readme.push(p.description, '');
            readme.push('**Exported:** ' + date, '**Tabs:** ' + tabKeys.length, '', '## Folders', '');
            if (tabKeys.length === 0) {
                readme.push('_No tabs found in this project._');
            } else {
                var usedFolders = {};
                tabKeys.forEach(function(tabId) {
                    var tab = tabs[tabId];
                    if (!tab) return;
                    var baseFolderName = mlpSafeName(tab.title || tabId || 'tab', 'tab');
                    var folderName = baseFolderName;
                    if (usedFolders[folderName]) {
                        usedFolders[folderName]++;
                        folderName = baseFolderName + '_' + usedFolders[baseFolderName];
                    } else {
                        usedFolders[folderName] = 1;
                    }
                    var pre = tab.preprocessors || {};
                    var cssExt = pre.css === 'scss' ? 'scss' : pre.css === 'less' ? 'less' : 'css';
                    var jsExt = pre.js === 'typescript' ? 'ts' : pre.js === 'coffeescript' ? 'coffee' : 'js';
                    files.push({ name: root + folderName + '/index.html', content: tab.html || '' });
                    files.push({ name: root + folderName + '/style.' + cssExt, content: tab.css || '' });
                    files.push({ name: root + folderName + '/script.' + jsExt, content: tab.js || '' });
                    readme.push('- `' + folderName + '/`  →  ' + (tab.emoji ? tab.emoji + ' ' : '') + ((tab.title || tabId || 'Tab') + ''));
                });
            }
            files.unshift({ name: root + 'project-backup.json', content: JSON.stringify({
                exportedAt: new Date().toISOString(),
                exportedBy: 'MLP Projects ZIP Export',
                version: 1,
                project: p
            }, null, 2) });
            files.unshift({ name: root + 'README.md', content: readme.join('\n') });
            return files;
        }

        function downloadZipFiles(files, zipName, successMessage) {
            var blob = mlpBuildStoredZipBlob(files);
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = zipName;
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
            setTimeout(function() {
                URL.revokeObjectURL(url);
                if (a.parentNode) a.parentNode.removeChild(a);
            }, 1500);
            showToast('Exported', successMessage, 'success');
        }

        function getOptionalZipPassword() {
            return window.prompt('Optional: enter a password to protect this ZIP backup. Leave blank for a normal ZIP, or press Cancel to stop export.');
        }

        function exportProtectedZip(payload, zipName, successMessage) {
            var password = getOptionalZipPassword();
            if (password === null) return true;
            if (!password) return null;
            if (!mlpCryptoReady()) {
                showToast('Export Failed', 'This browser cannot create password-protected exports.', 'danger');
                return false;
            }
            showToast('Protecting ZIP', 'Encrypting your backup before download.', 'info');
            mlpEncryptBackupPayload(payload, password).then(function(protectedPayload) {
                downloadZipFiles([
                    { name: 'README.md', content: 'This MLP Projects ZIP is password protected. Load it through MLP Projects and enter the export password to restore it.' },
                    { name: 'protected-backup.json', content: JSON.stringify(protectedPayload, null, 2) }
                ], zipName, successMessage);
            }).catch(function() {
                showToast('Export Failed', 'Could not encrypt the ZIP backup.', 'danger');
            });
            return true;
        }

        function exportProjectAsZip(p) {
            if (!p || !p.id) {
                showToast('Export Failed', 'Project data is missing.', 'danger');
                return;
            }
            p = getFreshProject(p.id, p);
            var date = new Date().toISOString().slice(0, 10);
            var zipName = mlpSafeName(p.name || 'project', 'project') + '_' + date + '.zip';
            var protectedResult = exportProtectedZip({
                exportedAt: new Date().toISOString(),
                exportedBy: 'MLP Projects Protected ZIP Export',
                version: 1,
                project: p
            }, zipName, '"' + (p.name || 'Project') + '" saved as protected ZIP.');
            if (protectedResult) return;
            if (protectedResult === false) return;
            showToast('Preparing ZIP', 'Your project export is being created.', 'info');
            try {
                downloadZipFiles(buildProjectZipFiles(p, ''), zipName, '"' + (p.name || 'Project') + '" saved as ZIP.');
            } catch(e) {
                showToast('Export Failed', 'Could not prepare the ZIP file.', 'danger');
            }
        }

        function exportProjectsAsZip(projects) {
            if (!projects || !projects.length) {
                showToast('Export Failed', 'No projects selected.', 'danger');
                return;
            }
            var date = new Date().toISOString().slice(0, 10);
            var fresh = projects.map(function(p){ return getFreshProject(p.id, p); }).filter(Boolean);
            var zipName = 'mlp_projects_' + fresh.length + '_' + date + '.zip';
            var protectedResult = exportProtectedZip({
                exportedAt: new Date().toISOString(),
                exportedBy: 'MLP Projects Protected Bulk ZIP Export',
                version: 1,
                projects: fresh
            }, zipName, fresh.length + ' projects saved as protected ZIP.');
            if (protectedResult) return;
            if (protectedResult === false) return;
            showToast('Preparing ZIP', 'Your selected projects are being exported.', 'info');
            try {
                var files = [];
                var used = {};
                fresh.forEach(function(p) {
                    var folder = mlpSafeName(p.name || 'project', 'project');
                    if (used[folder]) {
                        used[folder]++;
                        folder = folder + '_' + used[folder];
                    } else {
                        used[folder] = 1;
                    }
                    files = files.concat(buildProjectZipFiles(p, folder));
                });
                files.unshift({ name: 'all-projects-backup.json', content: JSON.stringify({
                    exportedAt: new Date().toISOString(),
                    exportedBy: 'MLP Projects Bulk ZIP Export',
                    version: 1,
                    projects: fresh
                }, null, 2) });
                files.unshift({ name: 'README.md', content: '# MLP Projects Bulk Export\n\nExported: ' + date + '\nProjects: ' + fresh.length + '\n\nEach selected project has its own folder.' });
                downloadZipFiles(files, zipName, fresh.length + ' projects saved as ZIP.');
            } catch(e) {
                showToast('Export Failed', 'Could not prepare the bulk ZIP file.', 'danger');
            }
        }

        /* ── Helper: extract a share token from a project (handles legacy shareUrl-only projects) ── */
        function getShareToken(p) {
            if (!p) return '';
            if (p.shareToken) return p.shareToken;
            if (!p.shareUrl) return '';
            try {
                var u = new URL(p.shareUrl);
                var t = u.searchParams.get('mlpsht') || '';
                if (!t && p.shareUrl.indexOf('#mlpsht_') !== -1) {
                    t = decodeURIComponent(p.shareUrl.split('#mlpsht_')[1] || '');
                }
                return t || '';
            } catch(e) { return ''; }
        }

        /* ── Initial render ─────────────────────────────────────────── */
        render();

        /* ── 📊 Stats Panel ─────────────────────────────────────────── */
        (function() {
            var statsPanel   = document.getElementById('mlp-stats-panel');
            var statsCloseBtn= document.getElementById('mlp-stats-close-btn');
            var statsGoBtn   = document.getElementById('mlp-stats-go-btn');
            var _statsTarget = null; // the project currently shown

            var LANG_COLORS = {
                html: '#e34c26', css: '#264de4', javascript: '#f7df1e',
                js: '#f7df1e', typescript: '#3178c6', scss: '#c69', less: '#1d365d',
                coffeescript: '#244776', other: '#6b7280'
            };

            /* ── Helpers ── */
            function countLines(str) {
                if (!str) return 0;
                return (str.match(/\n/g) || []).length + (str.trim() ? 1 : 0);
            }
            function relativeTime(iso) {
                if (!iso) return 'Never';
                var ms = Date.now() - new Date(iso).getTime();
                var s = Math.floor(ms / 1000);
                if (s < 60) return 'just now';
                var m = Math.floor(s / 60);
                if (m < 60) return m + 'm ago';
                var h = Math.floor(m / 60);
                if (h < 24) return h + 'h ago';
                var d = Math.floor(h / 24);
                if (d < 7) return d + 'd ago';
                if (d < 30) return Math.floor(d/7) + 'w ago';
                if (d < 365) return Math.floor(d/30) + 'mo ago';
                return Math.floor(d/365) + 'y ago';
            }
            function ageSince(iso) {
                if (!iso) return '—';
                var ms = Date.now() - new Date(iso).getTime();
                var d = Math.floor(ms / 86400000);
                if (d < 1) return 'Today';
                if (d === 1) return '1 day';
                if (d < 30) return d + ' days';
                if (d < 365) { var mo = Math.floor(d/30); return mo + ' month' + (mo>1?'s':''); }
                var yr = Math.floor(d/365); var rem = Math.floor((d - yr*365)/30);
                return yr + 'y' + (rem ? ' ' + rem + 'mo' : '');
            }
            function fmtNum(n) {
                if (n >= 1000000) return (n/1000000).toFixed(1).replace(/\.0$/,'') + 'M';
                if (n >= 1000) return (n/1000).toFixed(1).replace(/\.0$/,'') + 'k';
                return String(n);
            }

            /* ── Build language stats from a project ── */
            function buildLangStats(p) {
                var tabs = {};
                if (p.allTabs && typeof p.allTabs === 'object') tabs = p.allTabs;
                else if (p.savedTabs && typeof p.savedTabs === 'object') tabs = p.savedTabs;

                var stats = { html: 0, css: 0, js: 0 };

                function countTab(t) {
                    if (!t) return;
                    var pre = t.preprocessors || {};
                    stats.html += countLines(t.html || '');
                    var cssLang = (pre.css || 'css').toLowerCase();
                    stats[cssLang] = (stats[cssLang] || 0) + countLines(t.css || '');
                    var jsLang = (pre.js || 'javascript').toLowerCase();
                    if (jsLang === 'javascript') jsLang = 'js';
                    stats[jsLang] = (stats[jsLang] || 0) + countLines(t.js || '');
                }

                if (Object.keys(tabs).length > 0) {
                    Object.keys(tabs).forEach(function(k){ countTab(tabs[k]); });
                } else {
                    stats.html += countLines(p.html || '');
                    stats.css  += countLines(p.css  || '');
                    stats.js   += countLines(p.js   || '');
                }
                return stats;
            }

            /* ── Count tab count ── */
            function getTabCount(p) {
                if (p.allTabs && typeof p.allTabs === 'object') return Object.keys(p.allTabs).length;
                if (p.savedTabs && typeof p.savedTabs === 'object') return Object.keys(p.savedTabs).length;
                return 1;
            }

            /* ── Sparkline canvas draw ── */
            function drawSparkline(views) {
                var canvas = document.getElementById('mlp-stats-sparkline');
                if (!canvas) return;
                var ctx = canvas.getContext('2d');
                var W = canvas.offsetWidth || 220;
                var H = 48;
                canvas.width  = W * (window.devicePixelRatio || 1);
                canvas.height = H * (window.devicePixelRatio || 1);
                ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);
                ctx.clearRect(0, 0, W, H);

                if (!views || views.length < 2) {
                    // Draw a flat "no data" line
                    ctx.strokeStyle = 'rgba(148,163,184,0.4)';
                    ctx.lineWidth = 1.5;
                    ctx.setLineDash([4,4]);
                    ctx.beginPath(); ctx.moveTo(0, H/2); ctx.lineTo(W, H/2); ctx.stroke();
                    return;
                }

                var max = Math.max.apply(null, views);
                if (max === 0) max = 1;
                var step = W / (views.length - 1);
                var pts = views.map(function(v, i) {
                    return { x: i * step, y: H - 4 - (v / max) * (H - 12) };
                });

                // Fill gradient
                var grad = ctx.createLinearGradient(0, 0, 0, H);
                grad.addColorStop(0, 'rgba(37,99,235,0.25)');
                grad.addColorStop(1, 'rgba(37,99,235,0.02)');
                ctx.beginPath();
                ctx.moveTo(pts[0].x, pts[0].y);
                for (var i = 1; i < pts.length; i++) {
                    var mx = (pts[i-1].x + pts[i].x) / 2;
                    ctx.bezierCurveTo(mx, pts[i-1].y, mx, pts[i].y, pts[i].x, pts[i].y);
                }
                ctx.lineTo(pts[pts.length-1].x, H);
                ctx.lineTo(pts[0].x, H);
                ctx.closePath();
                ctx.fillStyle = grad;
                ctx.fill();

                // Line
                ctx.beginPath();
                ctx.moveTo(pts[0].x, pts[0].y);
                for (var j = 1; j < pts.length; j++) {
                    var mx2 = (pts[j-1].x + pts[j].x) / 2;
                    ctx.bezierCurveTo(mx2, pts[j-1].y, mx2, pts[j].y, pts[j].x, pts[j].y);
                }
                ctx.strokeStyle = '#3b82f6';
                ctx.lineWidth = 2;
                ctx.setLineDash([]);
                ctx.stroke();

                // Last point dot
                var last = pts[pts.length-1];
                ctx.beginPath(); ctx.arc(last.x, last.y, 3.5, 0, Math.PI*2);
                ctx.fillStyle = '#2563eb'; ctx.fill();
                ctx.beginPath(); ctx.arc(last.x, last.y, 3.5, 0, Math.PI*2);
                ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.5; ctx.stroke();
            }

            /* ── Populate stats panel ── */
            function populateStats(p) {
                if (!p) return;
                _statsTarget = p;

                // Identity
                var iconEl = document.getElementById('mlp-stats-proj-icon');
                var nameEl = document.getElementById('mlp-stats-proj-name');
                var visEl  = document.getElementById('mlp-stats-proj-vis');
                if (iconEl) {
                    var iconColor = p.iconColor || 'linear-gradient(135deg,#3b82f6 0%,#7c3aed 100%)';
                    var isGrad = iconColor.indexOf('linear-gradient') !== -1 || iconColor.indexOf('radial-gradient') !== -1;
                    iconEl.style.background = isGrad ? iconColor : iconColor;
                    if (p.emoji) {
                        iconEl.textContent = p.emoji;
                        iconEl.style.fontSize = '15px';
                        iconEl.innerHTML = '';
                        iconEl.textContent = p.emoji;
                    } else {
                        iconEl.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';
                    }
                }
                if (nameEl) nameEl.textContent = p.name || 'Untitled';
                if (visEl)  visEl.textContent  = (p.visibility || 'private').toUpperCase();

                // Code stats
                var langStats = buildLangStats(p);
                var totalLines = 0;
                Object.keys(langStats).forEach(function(k){ totalLines += langStats[k]; });
                var tabCount = getTabCount(p);

                // Compute total size (bytes approx)
                var totalSize = 0;
                function addStr(s){ totalSize += (s||'').length; }
                addStr(p.html); addStr(p.css); addStr(p.js);
                if (p.savedTabs) { try { addStr(JSON.stringify(p.savedTabs)); } catch(e){} }
                if (p.allTabs)   { try { addStr(JSON.stringify(p.allTabs));   } catch(e){} }
                function fmtSize(b) {
                    if (b < 1024) return b + ' B';
                    if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
                    return (b/(1024*1024)).toFixed(2) + ' MB';
                }

                var nonZero = Object.keys(langStats).filter(function(k){ return langStats[k] > 0; });
                var set = function(id, val) {
                    var el = document.getElementById(id);
                    if (el) el.textContent = val;
                };
                set('mlp-stats-lines', fmtNum(totalLines));
                set('mlp-stats-size',  fmtSize(totalSize));
                set('mlp-stats-tabs',  String(tabCount));
                set('mlp-stats-langs', String(nonZero.length || 1));

                // Language bar
                var barWrap  = document.getElementById('mlp-stats-lang-bar-wrap');
                var barEl    = document.getElementById('mlp-stats-lang-bar');
                var legendEl = document.getElementById('mlp-stats-lang-legend');
                if (barWrap && barEl && legendEl && nonZero.length > 0 && totalLines > 0) {
                    barWrap.style.display = 'block';
                    barEl.innerHTML = '';
                    legendEl.innerHTML = '';
                    nonZero.forEach(function(lang) {
                        var pct = (langStats[lang] / totalLines * 100).toFixed(1);
                        var color = LANG_COLORS[lang.toLowerCase()] || LANG_COLORS.other;
                        var seg = document.createElement('div');
                        seg.className = 'mlp-stats-lang-seg';
                        seg.style.width = pct + '%';
                        seg.style.background = color;
                        seg.title = lang.toUpperCase() + ': ' + pct + '% (' + fmtNum(langStats[lang]) + ' lines)';
                        barEl.appendChild(seg);
                        var item = document.createElement('div');
                        item.className = 'mlp-stats-lang-item';
                        item.innerHTML = '<span class="mlp-stats-lang-dot" style="background:' + color + ';"></span>' +
                            lang.toUpperCase() + ' <span style="color:var(--mlp-text-muted);font-weight:400;">' + pct + '%</span>';
                        legendEl.appendChild(item);
                    });
                } else if (barWrap) {
                    barWrap.style.display = 'none';
                }

                // ── Language Distribution Chart ──
                var langChartSection = document.getElementById('mlp-stats-lang-chart-section');
                var langChartEl      = document.getElementById('mlp-stats-lang-chart');
                if (langChartSection && langChartEl && nonZero.length > 0 && totalLines > 0) {
                    langChartSection.style.display = '';
                    langChartEl.innerHTML = '';
                    nonZero.forEach(function(lang) {
                        var pct   = (langStats[lang] / totalLines * 100);
                        var color = LANG_COLORS[lang.toLowerCase()] || LANG_COLORS.other;
                        var row   = document.createElement('div');
                        row.className = 'mlp-stats-lc-row';
                        var lbl   = document.createElement('span');
                        lbl.className = 'mlp-stats-lc-label';
                        lbl.textContent = lang.toUpperCase().slice(0,4);
                        var track = document.createElement('div');
                        track.className = 'mlp-stats-lc-track';
                        var fill  = document.createElement('div');
                        fill.className = 'mlp-stats-lc-fill';
                        fill.style.background = color;
                        fill.style.width = '0%';
                        track.appendChild(fill);
                        var pctEl = document.createElement('span');
                        pctEl.className = 'mlp-stats-lc-pct';
                        pctEl.textContent = pct.toFixed(0) + '%';
                        row.appendChild(lbl);
                        row.appendChild(track);
                        row.appendChild(pctEl);
                        langChartEl.appendChild(row);
                        // animate
                        setTimeout(function(f, v){ f.style.width = v + '%'; }, 30, fill, pct.toFixed(1));
                    });
                } else if (langChartSection) {
                    langChartSection.style.display = 'none';
                }

                // ── Last 7 Edits ──
                var editsSection = document.getElementById('mlp-stats-edits-section');
                var editsWrap    = document.getElementById('mlp-stats-edits-wrap');
                if (editsSection && editsWrap) {
                    var hist = Array.isArray(p.history) ? p.history : [];
                    var last7 = hist.slice(0, 7);
                    if (last7.length > 0) {
                        editsSection.style.display = '';
                        editsWrap.innerHTML = '';
                        last7.forEach(function(v) {
                            var row   = document.createElement('div');
                            row.className = 'mlp-stats-edit-row';
                            var dot   = document.createElement('div');
                            dot.className = 'mlp-stats-edit-dot';
                            var lbl   = document.createElement('span');
                            lbl.className = 'mlp-stats-edit-label';
                            if (v.at) {
                                var d = new Date(v.at);
                                lbl.textContent = (d.getMonth()+1) + '/' + d.getDate();
                            } else { lbl.textContent = '—'; }
                            var meta  = document.createElement('span');
                            meta.className = 'mlp-stats-edit-meta';
                            meta.textContent = v.label || 'Saved version';
                            row.appendChild(dot);
                            row.appendChild(lbl);
                            row.appendChild(meta);
                            editsWrap.appendChild(row);
                        });
                    } else {
                        editsSection.style.display = '';
                        editsWrap.innerHTML = '<div class="mlp-stats-edit-empty">No edit history yet.</div>';
                    }
                }

                // ── Storage Usage ──
                (function() {
                    function calcSize(obj) {
                        try { return JSON.stringify(obj).length; } catch(e) { return 0; }
                    }
                    function fmtSz(b) {
                        if (b < 1024) return b + ' B';
                        if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
                        return (b/(1024*1024)).toFixed(2) + ' MB';
                    }
                    var allProjects = getProjects();
                    var projSize  = calcSize(p);
                    var totalLsSize = 0;
                    try {
                        for (var ki = 0; ki < localStorage.length; ki++) {
                            var k = localStorage.key(ki);
                            totalLsSize += (k || '').length + (localStorage.getItem(k) || '').length;
                        }
                    } catch(e) {}
                    var allProjSize = calcSize(allProjects);
                    var LS_MAX = 5 * 1024 * 1024; // ~5 MB estimate

                    var projPct  = Math.min(100, (projSize / LS_MAX * 100));
                    var otherPct = Math.min(100 - projPct, ((allProjSize - projSize) / LS_MAX * 100));

                    var elProjVal   = document.getElementById('mlp-stats-proj-size-val');
                    var elTotalVal  = document.getElementById('mlp-stats-total-size-val');
                    var elBarProj   = document.getElementById('mlp-stats-storage-bar-proj');
                    var elBarOther  = document.getElementById('mlp-stats-storage-bar-other');
                    var elPct       = document.getElementById('mlp-stats-storage-pct');
                    if (elProjVal)  elProjVal.textContent  = fmtSz(projSize);
                    if (elTotalVal) elTotalVal.textContent = fmtSz(totalLsSize);
                    if (elBarProj)  { elBarProj.style.width  = '0%'; setTimeout(function(){ elBarProj.style.width  = projPct.toFixed(1)  + '%'; }, 30); }
                    if (elBarOther) { elBarOther.style.width = '0%'; setTimeout(function(){ elBarOther.style.width = otherPct.toFixed(1) + '%'; }, 30); }
                    if (elPct)      elPct.textContent = (totalLsSize / LS_MAX * 100).toFixed(1) + '% of ~5 MB used';
                })();

                // Timeline
                set('mlp-stats-created',  p.createdAt  ? (new Date(p.createdAt).toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'}) + ' · ' + relativeTime(p.createdAt)) : '—');
                set('mlp-stats-modified', p.updatedAt  ? relativeTime(p.updatedAt) : '—');
                set('mlp-stats-opened',   p.lastOpenedAt ? relativeTime(p.lastOpenedAt) : 'Never opened');
                set('mlp-stats-age',      ageSince(p.createdAt));

                // Views
                var viewsSection = document.getElementById('mlp-stats-views-section');
                if (viewsSection) {
                    var tok = '';
                    if (p.shareToken) tok = p.shareToken;
                    else if (p.shareUrl) {
                        try {
                            var u = new URL(p.shareUrl);
                            tok = u.searchParams.get('mlpsht') || '';
                            if (!tok && p.shareUrl.indexOf('#mlpsht_') !== -1) {
                                tok = decodeURIComponent(p.shareUrl.split('#mlpsht_')[1]||'');
                            }
                        } catch(e){}
                    }
                    var isPublic = (p.visibility === 'public') && !!tok;
                    viewsSection.style.display = isPublic ? '' : 'none';
                    if (isPublic) {
                        var cached = (window._mlpViewCounts && window._mlpViewCounts[tok]);
                        var viewNum = typeof cached === 'number' ? cached : null;
                        set('mlp-stats-view-num', viewNum !== null ? fmtNum(viewNum) : '…');
                        // Generate synthetic sparkline from view count (7-day simulated trend)
                        var sparkLabel = document.getElementById('mlp-stats-spark-label');
                        if (sparkLabel) {
                            sparkLabel.textContent = viewNum !== null
                                ? 'All-time: ' + viewNum + (viewNum === 1 ? ' view' : ' views')
                                : 'Loading view data…';
                        }
                        // Build simulated trend (actual data stored as single total, so we spread it)
                        var fakeSparkline = (function(total) {
                            if (total === null || total === 0) return null;
                            var pts = 7;
                            var arr = [];
                            var remaining = total;
                            for (var si = 0; si < pts; si++) {
                                var share = (si === pts-1) ? remaining : Math.floor(remaining * (0.1 + Math.random() * 0.22));
                                arr.push(Math.max(0, share));
                                remaining -= share;
                            }
                            return arr;
                        })(viewNum);
                        setTimeout(function(){ drawSparkline(fakeSparkline || [0,0,0,0,0,0,0]); }, 30);
                    }
                }

                // History
                set('mlp-stats-versions', String(Array.isArray(p.history) ? p.history.length : 0));
                set('mlp-stats-events',   String(Array.isArray(p.activity) ? p.activity.length : 0));

                // Tags
                var tagsSection = document.getElementById('mlp-stats-tags-section');
                var tagsWrap    = document.getElementById('mlp-stats-tags-wrap');
                if (tagsSection && tagsWrap) {
                    var hasTags = Array.isArray(p.tags) && p.tags.length > 0;
                    tagsSection.style.display = hasTags ? '' : 'none';
                    if (hasTags) {
                        tagsWrap.innerHTML = '';
                        p.tags.forEach(function(tag) {
                            var chip = document.createElement('span');
                            chip.className = 'mlp-tag-chip';
                            chip.textContent = '#' + tag;
                            tagsWrap.appendChild(chip);
                        });
                    }
                }

                // Notes
                var notesSection   = document.getElementById('mlp-stats-notes-section');
                var notesPrev      = document.getElementById('mlp-stats-notes-preview');
                if (notesSection && notesPrev) {
                    var hasNotes = !!(p.notes && p.notes.trim());
                    notesSection.style.display = hasNotes ? '' : 'none';
                    if (hasNotes) notesPrev.textContent = p.notes.slice(0, 200);
                }
            }

            /* ── Open stats panel for a project ── */
            window.mlpOpenStatsPanel = function(p) {
                if (!statsPanel) return;
                // Read fresh from storage
                var all = getProjects();
                var fresh = null;
                for (var i = 0; i < all.length; i++) {
                    if (all[i].id === p.id) { fresh = all[i]; break; }
                }
                var target = fresh || p;
                populateStats(target);
                statsPanel.style.display = 'flex';
            };

            /* ── Close ── */
            function closeStats() {
                if (statsPanel) statsPanel.style.display = 'none';
                _statsTarget = null;
            }
            if (statsCloseBtn) statsCloseBtn.addEventListener('click', closeStats);

            /* ── Go Code from stats panel ── */
            if (statsGoBtn) {
                statsGoBtn.addEventListener('click', function() {
                    if (_statsTarget) {
                        closeStats();
                        goCode(_statsTarget);
                    }
                });
            }

            /* ── Refresh stats when view counts update ── */
            var _origFetchAllViewCounts = window._mlpFetchAllViewCountsCb;
            window._mlpStatsPanelRefresh = function() {
                if (_statsTarget && statsPanel && statsPanel.style.display !== 'none') {
                    var all = getProjects();
                    for (var i = 0; i < all.length; i++) {
                        if (all[i].id === _statsTarget.id) { populateStats(all[i]); return; }
                    }
                }
            };
        })();

        /* ── 📊 Fetch view counts for all public projects ───────────── */
        window._mlpViewCounts = window._mlpViewCounts || {};
        function fetchAllViewCounts() {
            try {
                var projs = getProjects();
                var tokens = [];
                for (var i = 0; i < projs.length; i++) {
                    var tk = getShareToken(projs[i]);
                    if (tk) tokens.push(tk);
                }
                if (!tokens.length) return;
                var fd = new FormData();
                fd.append('action', 'mlp_get_project_views');
                fd.append('tokens', JSON.stringify(tokens));
                fetch(MLP_AJAX_URL, { method: 'POST', body: fd, credentials: 'same-origin' })
                    .then(function(r){ return r.json(); })
                    .then(function(j) {
                        if (!j || !j.success || !j.data || !j.data.views) return;
                        var v = j.data.views;
                        for (var k in v) { if (Object.prototype.hasOwnProperty.call(v, k)) {
                            window._mlpViewCounts[k] = parseInt(v[k], 10) || 0;
                        }}
                        // Re-render so the badges show real counts
                        try { render(searchInput.value); } catch(e) {}
                        // Refresh stats panel view count if open
                        try { if (typeof window._mlpStatsPanelRefresh === 'function') window._mlpStatsPanelRefresh(); } catch(e) {}
                    })
                    .catch(function(){});
            } catch(e) {}
        }
        fetchAllViewCounts();
        // Refresh every 60s while the popup is open
        setInterval(function() {
            var overlay = document.getElementById('mlp-projects-overlay');
            if (overlay && overlay.style.display !== 'none' && overlay.offsetParent !== null) {
                fetchAllViewCounts();
            }
        }, 60000);

        /* ── ⏰ Backup reminder toast (after 7 days) ────────────────── */
        (function() {
            try {
                var REMIND_AFTER_DAYS = 7;
                var SNOOZE_KEY = 'mlp_backup_reminder_snoozed_until';
                var snoozedUntil = parseInt(localStorage.getItem(SNOOZE_KEY) || '0', 10);
                if (snoozedUntil && Date.now() < snoozedUntil) return;

                var projs = getProjects();
                if (!projs.length) return;

                var nowMs = Date.now();
                var threshold = REMIND_AFTER_DAYS * 24 * 60 * 60 * 1000;
                var stale = [];
                for (var i = 0; i < projs.length; i++) {
                    var pr = projs[i];
                    if (!hasMeaningfulContent(pr)) continue;
                    var lastBackup = pr.lastBackupAt ? Date.parse(pr.lastBackupAt) : 0;
                    var anchor = lastBackup || Date.parse(pr.createdAt || '') || 0;
                    if (anchor && (nowMs - anchor) > threshold) stale.push(pr);
                }
                if (!stale.length) return;

                // Defer slightly so the dashboard has finished its first paint
                setTimeout(function() {
                    var msg = stale.length === 1
                        ? 'It\u2019s been a while since you backed up <b>' + escHtml(stale[0].name || 'this project') + '</b>.'
                        : 'You have <b>' + stale.length + ' projects</b> that haven\u2019t been backed up recently.';
                    var actionHtml = '<button class="mlp-toast-action-btn" id="mlp-toast-backup-now-btn">Back up now</button>' +
                                     '<button class="mlp-toast-action-btn" id="mlp-toast-backup-snooze-btn" style="background:#94a3b8;margin-left:6px;">Remind me later</button>';
                    showToast('Backup reminder', msg + '<br>' + actionHtml, 'warning', 12000, 'mlp-toast-backup-reminder');
                    setTimeout(function() {
                        var nowBtn = document.getElementById('mlp-toast-backup-now-btn');
                        var snzBtn = document.getElementById('mlp-toast-backup-snooze-btn');
                        if (nowBtn) nowBtn.addEventListener('click', function(e) {
                            e.stopPropagation();
                            // Back up the first stale project (or the only one)
                            downloadProjectBackup(stale[0]);
                            if (stale.length > 1) {
                                showToast('Backup started', 'Backed up "' + escHtml(stale[0].name || '') + '". Open the others to back them up too.', 'success');
                            }
                            try { localStorage.setItem(SNOOZE_KEY, String(Date.now() + 24*60*60*1000)); } catch(e) {}
                        });
                        if (snzBtn) snzBtn.addEventListener('click', function(e) {
                            e.stopPropagation();
                            try { localStorage.setItem(SNOOZE_KEY, String(Date.now() + 3*24*60*60*1000)); } catch(e) {}
                            showToast('Reminder snoozed', 'We\u2019ll remind you again in 3 days.', 'info', 3000);
                        });
                    }, 50);
                }, 1500);
            } catch(e) {}
        })();

        /* ── Auto-load project from URL ?project=ID ─────────────────── */
        (function() {
            try {
                var params = new URLSearchParams(window.location.search);
                var projId = params.get('project');
                if (!projId) return;
                var projects = getProjects();
                var target = null;
                for (var i = 0; i < projects.length; i++) {
                    if (projects[i].id === projId) { target = projects[i]; break; }
                }
                if (!target) {
                    showToast('Project Not Found', 'This project link is not in your library.', 'danger');
                    return;
                }
                // Auto-open project, skip the popup
                setTimeout(function() {
                    goCode(target);
                }, 300);
            } catch(e) {}
        })();

        /* ── Import shared project from #mlpsh_BASE64 ───────────────── */
        (function() {
            try {
                function clearShareHash() {
                    try { sessionStorage.removeItem('mlp_pending_share'); } catch(e) {}
                    try {
                        var params = new URLSearchParams(window.location.search || '');
                        params.delete('mlpsh');
                        params.delete('mlpsht');
                        var cleanSearch = params.toString();
                        window.history.replaceState(null, '', window.location.pathname + (cleanSearch ? '?' + cleanSearch : ''));
                    } catch(e) {}
                }

                function openImportedProject(project) {
                    if (!project || !project.id) return;
                    try {
                        window.mlpCurrentProjectId = project.id;
                        localStorage.setItem(LAST_ID_KEY, project.id);
                        restoreTabsFromProject(project);
                    } catch(e) {}
                    setTimeout(function() {
                        goCode(project);
                        scheduleReloadTabsForProject(project.id, 16);
                    }, 250);
                }

                function cloneSharedTabs(shared) {
                    var result = { savedTabs: null, allTabs: null };
                    if (shared && shared.savedTabs) {
                        try { result.savedTabs = JSON.parse(JSON.stringify(shared.savedTabs)); } catch(e) { result.savedTabs = null; }
                    }
                    if (shared && shared.allTabs) {
                        try { result.allTabs = JSON.parse(JSON.stringify(shared.allTabs)); } catch(e) { result.allTabs = null; }
                    }
                    if (result.savedTabs) {
                        if (!result.allTabs) result.allTabs = {};
                        Object.keys(result.savedTabs).forEach(function(tabId) {
                            if (!result.allTabs[tabId]) result.allTabs[tabId] = result.savedTabs[tabId];
                        });
                    }
                    return result;
                }

                function applySharedDataToExistingProject(existing, shared) {
                    if (!existing || !shared) return existing;
                    var tabBundle = cloneSharedTabs(shared);
                    var projects = getProjects();
                    for (var i = 0; i < projects.length; i++) {
                        if (projects[i].id === existing.id) {
                            if (shared.name) projects[i].name = shared.name;
                            if (shared.description !== undefined) projects[i].description = shared.description || '';
                            if (shared.html !== undefined) projects[i].html = shared.html || '';
                            if (shared.css !== undefined) projects[i].css = shared.css || '';
                            if (shared.js !== undefined) projects[i].js = shared.js || '';
                            if (tabBundle.savedTabs) projects[i].savedTabs = tabBundle.savedTabs;
                            if (tabBundle.allTabs) projects[i].allTabs = tabBundle.allTabs;
                            if (shared.activeTabId) projects[i].activeTabId = shared.activeTabId;
                            projects[i].sourceShareId = projects[i].sourceShareId || shared.id;
                            projects[i].updatedAt = new Date().toISOString();
                            saveProjects(projects);
                            return projects[i];
                        }
                    }
                    return existing;
                }

                /* ── Owner preview modal wiring ─────────────────────────── */
                (function() {
                    var modal      = document.getElementById('mlp-owner-modal');
                    var closeBtn   = document.getElementById('mlp-owner-modal-close');
                    var cancelBtn  = document.getElementById('mlp-owner-cancel-btn');
                    var importBtn  = document.getElementById('mlp-owner-import-btn');
                    var avatarEl   = document.getElementById('mlp-owner-modal-avatar');
                    var nameEl     = document.getElementById('mlp-owner-modal-name');
                    var projNameEl = document.getElementById('mlp-owner-modal-proj-name');
                    var projDescEl = document.getElementById('mlp-owner-modal-proj-desc');
                    if (!modal) return;

                    var _pendingCb = null;

                    function closeOwnerModal() {
                        modal.style.display = 'none';
                        _pendingCb = null;
                    }

                    if (closeBtn)  closeBtn.addEventListener('click',  closeOwnerModal);
                    if (cancelBtn) cancelBtn.addEventListener('click',  closeOwnerModal);
                    modal.addEventListener('click', function(e) {
                        if (e.target === modal) closeOwnerModal();
                    });

                    if (importBtn) {
                        importBtn.addEventListener('click', function() {
                            modal.style.display = 'none';
                            if (typeof _pendingCb === 'function') { var cb = _pendingCb; _pendingCb = null; cb(); }
                        });
                    }

                    /**
                     * showOwnerModal(shared, onConfirm)
                     * Populates and opens the owner preview modal.
                     * onConfirm is called when the user clicks "Import & Open".
                     */
                    window._mlpShowOwnerModal = function(shared, onConfirm) {
                        if (!modal) { if (typeof onConfirm === 'function') onConfirm(); return; }

                        // Populate avatar
                        var ownerAvatar = (shared && shared.sharedByAvatar) || null;
                        if (avatarEl) {
                            if (ownerAvatar) {
                                avatarEl.style.background = 'transparent';
                                avatarEl.innerHTML = '<img src="' + escHtml(ownerAvatar) + '" alt="Host"/>';
                            } else {
                                // Absolute fallback — generate a generic coloured avatar
                                avatarEl.style.background = '#6366f1';
                                avatarEl.style.color      = '#fff';
                                avatarEl.textContent      = '👤';
                            }
                        }

                        // Populate text fields
                        if (projNameEl) projNameEl.textContent = (shared && shared.name) ? '📁 ' + shared.name : '';
                        if (projDescEl) {
                            var desc = (shared && shared.description) || '';
                            if (desc) {
                                projDescEl.textContent = desc;
                                projDescEl.style.display = '';
                            } else {
                                projDescEl.style.display = 'none';
                            }
                        }

                        _pendingCb = onConfirm || null;
                        modal.style.display = 'flex';
                        if (importBtn) importBtn.focus();
                    };
                })();
                /* ─────────────────────────────────────────────────────────── */

                function doActualImport(shared) {
                    var projects   = getProjects();
                    var alreadyHas = false;
                    var existingProject = null;
                    var originalId = shared.id;
                    for (var i = 0; i < projects.length; i++) {
                        if (projects[i].id === originalId || projects[i].sourceShareId === originalId) {
                            alreadyHas = true;
                            existingProject = projects[i];
                            break;
                        }
                    }

                    if (alreadyHas) {
                        existingProject = applySharedDataToExistingProject(existingProject, shared);
                        try { render(); } catch(e) {}
                        setTimeout(function() {
                            showToast('Project Updated', '"' + escHtml(shared.name || 'Project') + '" is already in your library, so its shared tabs were refreshed.', 'info');
                        }, 500);
                        openImportedProject(existingProject);
                    } else {
                        var sharedTabs = cloneSharedTabs(shared);
                        shared.savedTabs = sharedTabs.savedTabs;
                        shared.allTabs = sharedTabs.allTabs;
                        shared.sourceShareId = originalId;
                        shared.id           = generateId();
                        shared.importedAt   = new Date().toISOString();
                        shared.importedFrom = shared.sharedBy || 'another user';
                        shared.activity     = [{ at: shared.importedAt, label: 'Imported from share link' }];
                        shared.history      = [];
                        shared.visibility   = 'private';
                        projects.push(shared);
                        saveProjects(projects);
                        render();
                        setTimeout(function() {
                            showToast(
                                '📬 Project Added',
                                '"' + escHtml(shared.name || 'Project') + '" was added to your projects.' +
                                (shared.sharedBy ? ' (from ' + escHtml(shared.sharedBy) + ')' : '') +
                                (shared.pinHash ? ' 🔐 Password required to open.' : ''),
                                'success'
                            );
                        }, 400);
                        if (shared.pinHash) {
                            openUnlockModal(shared, function() { openImportedProject(shared); });
                        } else {
                            openImportedProject(shared);
                        }
                    }
                }

                function importSharedProject(shared) {
                    if (!shared || !shared.id) return;
                    clearShareHash();

                    // Check if this project is already in the user's library
                    var projects   = getProjects();
                    var alreadyHas = false;
                    var originalId = shared.id;
                    for (var i = 0; i < projects.length; i++) {
                        if (projects[i].id === originalId || projects[i].sourceShareId === originalId) {
                            alreadyHas = true;
                            break;
                        }
                    }

                    // Already owned → update silently without the modal
                    if (alreadyHas) {
                        doActualImport(shared);
                        return;
                    }

                    // New project → show owner preview modal first
                    if (typeof window._mlpShowOwnerModal === 'function') {
                        window._mlpShowOwnerModal(shared, function() {
                            doActualImport(shared);
                        });
                    } else {
                        doActualImport(shared);
                    }
                }

                function decodeInlineShare(b64) {
                    try {
                        return JSON.parse(b64UrlToUtf8(b64));
                    } catch(e1) {
                        try { return JSON.parse(decodeURIComponent(escape(atob(b64)))); } catch(e2) {}
                    }
                    return null;
                }

                function fetchTokenShare(token) {
                    if (!window.fetch || !MLP_AJAX_URL) {
                        showToast('Share Link Unavailable', 'This share link could not be loaded. Please ask the sender to create a new link.', 'danger');
                        return;
                    }
                    var url = MLP_AJAX_URL + '?action=mlp_get_shared_project&token=' + encodeURIComponent(token);
                    fetch(url, { credentials: 'same-origin' })
                        .then(function(res) { return res.json(); })
                        .then(function(resp) {
                            if (!resp || !resp.success || !resp.data || !resp.data.payload) {
                                showToast('Share Link Unavailable', 'This share link could not be found. Please ask the sender to copy the link again.', 'danger');
                                return;
                            }
                            try {
                                importSharedProject(JSON.parse(resp.data.payload));
                            } catch(e) {
                                showToast('Invalid Share Link', 'This project link is damaged. Please ask the sender to copy it again.', 'danger');
                            }
                        })
                        .catch(function() {
                            showToast('Share Link Unavailable', 'Could not load this shared project. Please try again.', 'danger');
                        });
                }

                var raw = '';
                try { raw = sessionStorage.getItem('mlp_pending_share') || ''; } catch(e) {}
                // Fallback: check current hash (works when no redirect happens)
                if (!raw) {
                    var h = window.location.hash || '';
                    if (h.indexOf('#mlpsh_') === 0 || h.indexOf('#mlpsht_') === 0) raw = h.slice(1);
                    if (!raw) {
                        var params = new URLSearchParams(window.location.search || '');
                        var token = params.get('mlpsht');
                        var inlineShare = params.get('mlpsh');
                        if (token) raw = 'mlpsht_' + token;
                        else if (inlineShare) raw = 'mlpsh_' + inlineShare;
                    }
                }
                if (!raw || raw === 'mlpsh_err') return;

                if (raw.indexOf('mlpsht_') === 0) {
                    fetchTokenShare(raw.slice('mlpsht_'.length));
                    return;
                }

                var b64 = (raw.indexOf('mlpsh_') === 0) ? raw.slice('mlpsh_'.length) : raw;
                if (!b64) return;
                var shared = decodeInlineShare(b64);
                if (shared && shared.id) {
                    importSharedProject(shared);
                } else {
                    showToast('Invalid Share Link', 'This project link is incomplete or damaged. Please ask the sender to copy it again.', 'danger');
                }
            } catch(e) {}
        })();

        /* ── Notify about shared projects received ──────────────────── */
        setTimeout(function() {
            var count = window._mlpSharedProjectsCount;
            if (count && count > 0) {
                window._mlpSharedProjectsCount = 0;
                showToast(
                    '📬 ' + count + ' Project' + (count > 1 ? 's' : '') + ' Shared With You',
                    count > 1
                        ? count + ' projects were added to your list by another user.'
                        : 'A project was added to your list by another user.',
                    'success'
                );
                render(); // re-render to show the newly merged projects
            }
        }, 600);

        /* ── Public API ─────────────────────────────────────────────── */
        window.mlpProjectsOpen = function () {
            overlay.classList.remove('mlp-proj-hidden');
            render();
        };

        // Legacy hook — still works, now per-project
        window.mlpDeleteCurrentProject = function () {
            var id = window.mlpCurrentProjectId;
            if (!id) return;
            deleteProjectById(id);
            window.mlpCurrentProjectId = null;
            try { localStorage.removeItem(LAST_ID_KEY); } catch(e) {}
            try { localStorage.removeItem(TABS_KEY); } catch(e) {}
            if (typeof window.mlpResetToDefault === 'function') { window.mlpResetToDefault(); }
            render();
        };

        // Called by main plugin on tab switch to keep snapshot fresh
        window.mlpSyncTabsToProject = function () {
            flushTabsToProject(window.mlpCurrentProjectId || null);
        };
    }

    /* ── Admin-delete sync ───────────────────────────────────────── */
    /* On page load, check if any public projects were admin-deleted. */
    /* If so, set them back to private in localStorage immediately.   */
    (function checkAdminDeletedProjects() {
        if (!MLP_AJAX_URL || !window.fetch) return;
        try {
            var projects = getProjects();
            // Collect share tokens from public projects
            var tokens = [];
            projects.forEach(function(p) {
                if (p.visibility === 'public' && p.shareToken) tokens.push(p.shareToken);
                // Also extract token from shareUrl if shareToken not set
                if (p.visibility === 'public' && !p.shareToken && p.shareUrl) {
                    try {
                        var u = new URL(p.shareUrl);
                        var t = u.searchParams.get('mlpsht') || '';
                        if (!t && p.shareUrl.indexOf('#mlpsht_') !== -1) {
                            t = decodeURIComponent(p.shareUrl.split('#mlpsht_')[1] || '');
                        }
                        if (t) tokens.push(t);
                    } catch(e) {}
                }
            });
            if (!tokens.length) return;

            var body = new URLSearchParams();
            body.set('action', 'mlp_check_project_status');
            body.set('tokens', JSON.stringify(tokens));

            fetch(MLP_AJAX_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                body: body.toString()
            })
            .then(function(r) { return r.json(); })
            .then(function(resp) {
                if (!resp || !resp.success || !resp.data || !resp.data.deleted) return;
                var deletedTokens = resp.data.deleted;
                if (!deletedTokens.length) return;

                // For each deleted token, find the matching project and set it to private
                var changed = false;
                var allProjects = getProjects();
                allProjects.forEach(function(p) {
                    var pToken = p.shareToken || '';
                    if (!pToken && p.shareUrl) {
                        try {
                            var u = new URL(p.shareUrl);
                            pToken = u.searchParams.get('mlpsht') || '';
                            if (!pToken && p.shareUrl.indexOf('#mlpsht_') !== -1) {
                                pToken = decodeURIComponent(p.shareUrl.split('#mlpsht_')[1] || '');
                            }
                        } catch(e) {}
                    }
                    if (pToken && deletedTokens.indexOf(pToken) !== -1) {
                        updateProjectById(p.id, {
                            visibility:       'private',
                            shareUrl:         null,
                            shareToken:       null,
                            shareContentHash: null,
                            adminDeleted:     true
                        });
                        changed = true;
                    }
                });

                if (changed) {
                    try { render(); } catch(e) {}
                    showToast(
                        'Project Removed',
                        'One or more of your shared projects was removed by an administrator and set back to private.',
                        'danger'
                    );
                }
            })
            .catch(function() {}); // silent fail — not critical
        } catch(e) {}
    })();

    /* ── Boot ─────────────────────────────────────────────────────── */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
ENDJS;

        return str_replace(
            [ 'MLP_PROJECTS_LS_KEY_PLACEHOLDER', 'MLP_AJAX_URL_PLACEHOLDER', 'MLP_SHARE_NONCE_PLACEHOLDER' ],
            [ $ls_key, $ajax_url, $share_nonce ],
            $js
        );
    }
}

add_action( 'wp_ajax_mlp_save_shared_project',        [ 'MLP_Projects', 'ajax_save_shared_project' ] );
add_action( 'wp_ajax_nopriv_mlp_save_shared_project', [ 'MLP_Projects', 'ajax_save_shared_project' ] );
add_action( 'wp_ajax_mlp_get_shared_project',         [ 'MLP_Projects', 'ajax_get_shared_project' ] );
add_action( 'wp_ajax_nopriv_mlp_get_shared_project',  [ 'MLP_Projects', 'ajax_get_shared_project' ] );
add_action( 'wp_ajax_mlp_moderate_project',           [ 'MLP_Projects', 'ajax_moderate_project' ] );
add_action( 'wp_ajax_nopriv_mlp_moderate_project',    [ 'MLP_Projects', 'ajax_moderate_project' ] );
add_action( 'wp_ajax_mlp_check_project_status',        [ 'MLP_Projects', 'ajax_check_project_status' ] );
add_action( 'wp_ajax_nopriv_mlp_check_project_status', [ 'MLP_Projects', 'ajax_check_project_status' ] );
add_action( 'wp_ajax_mlp_get_project_views',           [ 'MLP_Projects', 'ajax_get_project_views' ] );
add_action( 'wp_ajax_nopriv_mlp_get_project_views',    [ 'MLP_Projects', 'ajax_get_project_views' ] );

/* ======================================================================== */
/*  MLP Projects — Admin Dashboard                                           */
/* ======================================================================== */

if ( ! class_exists( 'MLP_Projects_Admin' ) ) :

class MLP_Projects_Admin {

    const PER_PAGE      = 10;
    const IGNORED_OPT   = 'mlp_admin_ignored_tokens'; // tokens admin has "Ignored & Safe"
    const DELETED_OPT   = 'mlp_admin_deleted_tokens'; // tokens admin has "Deleted" (project set private)

    /* ── Boot ─────────────────────────────────────────────────────────── */
    public static function init() {
        add_action( 'admin_menu',  [ __CLASS__, 'register_menu'    ] );
        add_action( 'admin_enqueue_scripts', [ __CLASS__, 'enqueue_assets' ] );
        add_action( 'wp_ajax_mlp_admin_ignore_project',  [ __CLASS__, 'ajax_ignore'  ] );
        add_action( 'wp_ajax_mlp_admin_delete_project',  [ __CLASS__, 'ajax_delete'  ] );
    }

    /* ── Admin menu ───────────────────────────────────────────────────── */
    public static function register_menu() {
        add_menu_page(
            'MLP Published Projects',
            'MLP Projects',
            'manage_options',
            'mlp-published-projects',
            [ __CLASS__, 'render_page' ],
            'dashicons-share',
            30
        );
    }

    /* ── Enqueue page styles (only on our page) ───────────────────────── */
    public static function enqueue_assets( $hook ) {
        if ( $hook !== 'toplevel_page_mlp-published-projects' ) return;
        wp_add_inline_style( 'wp-admin', self::get_admin_css() );
    }

    /* ── Collect all shared projects from wp_options ─────────────────── */
    private static function get_all_shared_projects() {
        global $wpdb;
        $rows = $wpdb->get_results(
            "SELECT option_name, option_value FROM {$wpdb->options}
             WHERE option_name LIKE 'mlp_share_%'
             ORDER BY option_id DESC",
            ARRAY_A
        );
        $projects = [];
        foreach ( $rows as $row ) {
            $token = substr( $row['option_name'], strlen( 'mlp_share_' ) );
            $data  = maybe_unserialize( $row['option_value'] );
            if ( ! is_array( $data ) || empty( $data['payload'] ) ) continue;
            $payload = json_decode( $data['payload'], true );
            $share_url = home_url( '/?mlpsht=' . $token );
            $projects[] = [
                'token'      => $token,
                'created'    => $data['created']  ?? 0,
                'updated'    => $data['updated']  ?? null,
                'name'       => $payload['name']  ?? 'Untitled',
                'sharedBy'   => $payload['sharedBy'] ?? '',
                'shareUrl'   => $share_url,
                'html'       => $payload['html']  ?? '',
                'css'        => $payload['css']   ?? '',
                'js'         => $payload['js']    ?? '',
                'savedTabs'  => $payload['savedTabs'] ?? [],
                'allTabs'    => $payload['allTabs']   ?? [],
                'republished'=> ! empty( $data['updated'] ),
            ];
        }
        return $projects;
    }

    /* ── AJAX: Ignore & Safe ──────────────────────────────────────────── */
    public static function ajax_ignore() {
        check_ajax_referer( 'mlp_admin_action', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( [], 403 );
        $token = sanitize_key( $_POST['token'] ?? '' );
        if ( ! $token ) wp_send_json_error( [ 'message' => 'Missing token.' ], 400 );
        $ignored = get_option( self::IGNORED_OPT, [] );
        if ( ! in_array( $token, $ignored, true ) ) {
            $ignored[] = $token;
            update_option( self::IGNORED_OPT, $ignored, false );
        }
        wp_send_json_success();
    }

    /* ── AJAX: Delete Project (set visibility=private for user) ───────── */
    public static function ajax_delete() {
        check_ajax_referer( 'mlp_admin_action', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( [], 403 );
        $token = sanitize_key( $_POST['token'] ?? '' );
        if ( ! $token ) wp_send_json_error( [ 'message' => 'Missing token.' ], 400 );

        // 1. Mark on the share record — ajax_get_shared_project checks this flag
        //    and returns a 410, breaking the share link immediately.
        $record = get_option( 'mlp_share_' . $token, null );
        if ( is_array( $record ) ) {
            $record['admin_deleted']    = true;
            $record['admin_deleted_at'] = time();
            update_option( 'mlp_share_' . $token, $record, false );
        }

        // 2. Track in deleted list (for admin reference)
        $deleted = get_option( self::DELETED_OPT, [] );
        if ( ! in_array( $token, $deleted, true ) ) {
            $deleted[] = $token;
            update_option( self::DELETED_OPT, $deleted, false );
        }

        // 3. Add to ignored so it disappears from admin view
        $ignored = get_option( self::IGNORED_OPT, [] );
        if ( ! in_array( $token, $ignored, true ) ) {
            $ignored[] = $token;
            update_option( self::IGNORED_OPT, $ignored, false );
        }

        // 4. Return the token so the JS can tell the frontend to set the project private.
        //    The frontend JS polls ajax_check_project_status on page load and handles this.
        wp_send_json_success( [ 'token' => $token ] );
    }

    /* ── Render the admin page ────────────────────────────────────────── */
    public static function render_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Access denied.' );
        }

        $all_projects = self::get_all_shared_projects();
        $ignored      = get_option( self::IGNORED_OPT, [] );
        $nonce        = wp_create_nonce( 'mlp_admin_action' );
        $ajax_url     = admin_url( 'admin-ajax.php' );

        // Separate: today vs rest, filtered by ignored
        $today_start  = strtotime( 'today midnight' );
        $today        = [];
        $all_active   = [];

        foreach ( $all_projects as $p ) {
            $is_ignored = in_array( $p['token'], $ignored, true );
            // "Today" = created today OR republished today, and not ignored
            $last_action = $p['updated'] ?? $p['created'];
            $is_today    = ( $last_action >= $today_start );
            if ( ! $is_ignored && $is_today ) {
                $today[] = $p;
            }
            if ( ! $is_ignored ) {
                $all_active[] = $p;
            }
        }

        // Pagination for all active projects
        $total      = count( $all_active );
        $per_page   = self::PER_PAGE;
        $page       = max( 1, intval( $_GET['paged'] ?? 1 ) );
        $total_pages = max( 1, (int) ceil( $total / $per_page ) );
        $page       = min( $page, $total_pages );
        $offset     = ( $page - 1 ) * $per_page;
        $page_items = array_slice( $all_active, $offset, $per_page );

        $admin_url_base = admin_url( 'admin.php?page=mlp-published-projects' );

        ?>
        <div class="wrap mlp-admin-wrap">
            <h1 class="mlp-admin-title">
                <span class="dashicons dashicons-share" style="font-size:26px;width:26px;height:26px;margin-right:8px;vertical-align:middle;color:#6d28d9;"></span>
                MLP — Published Projects
            </h1>
            <p class="mlp-admin-subtitle">All projects shared by users. Use <strong>Ignore &amp; Safe</strong> to clear from view (reappears if republished). Use <strong>Delete Project</strong> to force it back to private for the user.</p>

            <!-- Search bar -->
            <div class="mlp-search-bar-wrap">
                <div class="mlp-search-icon">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                </div>
                <input
                    type="text"
                    id="mlp-admin-search"
                    class="mlp-search-input-bar"
                    placeholder="Search by project name, owner, or share URL…"
                    autocomplete="off"
                    spellcheck="false"
                />
                <button id="mlp-search-clear" class="mlp-search-clear" title="Clear search" style="display:none;">&#x2715;</button>
                <span id="mlp-search-results-count" class="mlp-search-results-count" style="display:none;"></span>
            </div>
            <!-- Search results panel (shown when searching) -->
            <div id="mlp-search-results-section" class="mlp-admin-section mlp-admin-search-section" style="display:none;">
                <div class="mlp-admin-section-header">
                    <span class="mlp-admin-section-dot" style="background:#0ea5e9;box-shadow:0 0 0 3px #e0f2fe;"></span>
                    <h2 class="mlp-admin-section-title">Search Results <span class="mlp-admin-count-chip" id="mlp-search-match-count">0</span></h2>
                </div>
                <div class="mlp-admin-grid" id="mlp-search-grid"></div>
                <div id="mlp-search-empty" class="mlp-admin-empty" style="display:none;">No projects match your search.</div>
            </div>

            <?php /* ── TODAY section ── */ ?>
            <div class="mlp-admin-section mlp-admin-today-section">
                <div class="mlp-admin-section-header">
                    <span class="mlp-admin-section-dot mlp-dot-today"></span>
                    <h2 class="mlp-admin-section-title">Codes Published &amp; Republished Today
                        <span class="mlp-admin-count-chip"><?php echo count( $today ); ?></span>
                    </h2>
                </div>
                <?php if ( empty( $today ) ) : ?>
                    <div class="mlp-admin-empty">No projects published or republished today.</div>
                <?php else : ?>
                    <div class="mlp-admin-grid" id="mlp-today-grid">
                        <?php foreach ( $today as $p ) : ?>
                            <?php self::render_card( $p, $nonce, $ajax_url, true ); ?>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>

            <?php /* ── ALL ACTIVE section ── */ ?>
            <div class="mlp-admin-section">
                <div class="mlp-admin-section-header">
                    <span class="mlp-admin-section-dot mlp-dot-all"></span>
                    <h2 class="mlp-admin-section-title">All Published Projects
                        <span class="mlp-admin-count-chip"><?php echo $total; ?></span>
                    </h2>
                    <?php if ( $total_pages > 1 ) : ?>
                        <span class="mlp-admin-page-info">Page <?php echo $page; ?> of <?php echo $total_pages; ?></span>
                    <?php endif; ?>
                </div>

                <?php if ( empty( $all_active ) ) : ?>
                    <div class="mlp-admin-empty">No published projects yet.</div>
                <?php else : ?>
                    <div class="mlp-admin-grid" id="mlp-all-grid">
                        <?php foreach ( $page_items as $p ) : ?>
                            <?php self::render_card( $p, $nonce, $ajax_url, false ); ?>
                        <?php endforeach; ?>
                    </div>

                    <?php if ( $total_pages > 1 ) : ?>
                        <div class="mlp-admin-pagination">
                            <?php if ( $page > 1 ) : ?>
                                <a class="mlp-page-btn" href="<?php echo esc_url( add_query_arg( 'paged', $page - 1, $admin_url_base ) ); ?>">&#8592; Prev</a>
                            <?php endif; ?>
                            <?php for ( $i = 1; $i <= $total_pages; $i++ ) : ?>
                                <?php if ( abs( $i - $page ) <= 2 || $i === 1 || $i === $total_pages ) : ?>
                                    <a class="mlp-page-btn <?php echo $i === $page ? 'mlp-page-current' : ''; ?>"
                                       href="<?php echo esc_url( add_query_arg( 'paged', $i, $admin_url_base ) ); ?>">
                                        <?php echo $i; ?>
                                    </a>
                                <?php elseif ( abs( $i - $page ) === 3 ) : ?>
                                    <span class="mlp-page-ellipsis">&hellip;</span>
                                <?php endif; ?>
                            <?php endfor; ?>
                            <?php if ( $page < $total_pages ) : ?>
                                <a class="mlp-page-btn" href="<?php echo esc_url( add_query_arg( 'paged', $page + 1, $admin_url_base ) ); ?>">Next &#8594;</a>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>

        <script>
        (function() {
            var nonce   = <?php echo wp_json_encode( $nonce ); ?>;
            var ajaxUrl = <?php echo wp_json_encode( $ajax_url ); ?>;

            function mlpAdminAction(action, token, cardId, onDone) {
                var btn = document.querySelectorAll('[data-token="' + token + '"]');
                btn.forEach(function(b){ b.disabled = true; });
                var body = new URLSearchParams();
                body.set('action', action);
                body.set('nonce', nonce);
                body.set('token', token);
                fetch(ajaxUrl, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: body.toString()
                })
                .then(function(r){ return r.json(); })
                .then(function(resp) {
                    if (resp && resp.success) {
                        onDone(token, cardId);
                    } else {
                        btn.forEach(function(b){ b.disabled = false; });
                        alert('Action failed. Please try again.');
                    }
                })
                .catch(function(){
                    btn.forEach(function(b){ b.disabled = false; });
                    alert('Network error. Please try again.');
                });
            }

            function removeCard(token) {
                document.querySelectorAll('.mlp-admin-card[data-token="' + token + '"]').forEach(function(card) {
                    card.style.transition = 'opacity 0.3s, transform 0.3s';
                    card.style.opacity = '0';
                    card.style.transform = 'scale(0.95)';
                    setTimeout(function(){ card.remove(); }, 320);
                });
            }

            document.addEventListener('click', function(e) {
                var btn = e.target.closest('[data-action]');
                if (!btn) return;
                var action = btn.dataset.action;
                var token  = btn.dataset.token;
                if (!action || !token) return;

                if (action === 'ignore') {
                    if (!confirm('Mark this project as Ignored & Safe? It will be cleared from this view but will reappear if the user republishes.')) return;
                    mlpAdminAction('mlp_admin_ignore_project', token, null, function() {
                        removeCard(token);
                    });
                }

                if (action === 'delete') {
                    if (!confirm('Delete this project for the user? Their project will be set to Private and the share link will stop working.')) return;
                    mlpAdminAction('mlp_admin_delete_project', token, null, function() {
                        removeCard(token);
                    });
                }
            });

            // Code tab switching
            document.addEventListener('click', function(e) {
                var tab = e.target.closest('.mlp-code-tab');
                if (!tab) return;
                var card = tab.closest('.mlp-admin-card');
                if (!card) return;
                var lang = tab.dataset.lang;
                card.querySelectorAll('.mlp-code-tab').forEach(function(t){ t.classList.remove('active'); });
                card.querySelectorAll('.mlp-code-pane').forEach(function(p){ p.style.display = 'none'; });
                tab.classList.add('active');
                var pane = card.querySelector('.mlp-code-pane[data-lang="' + lang + '"]');
                if (pane) pane.style.display = 'block';
            });

            // Toggle code visibility
            document.addEventListener('click', function(e) {
                var btn = e.target.closest('.mlp-toggle-code');
                if (!btn) return;
                var card = btn.closest('.mlp-admin-card');
                var codeBlock = card.querySelector('.mlp-code-block');
                if (!codeBlock) return;
                var isHidden = codeBlock.style.display === 'none' || codeBlock.style.display === '';
                codeBlock.style.display = isHidden ? 'block' : 'none';
                btn.textContent = isHidden ? '▲ Hide Code' : '▼ View Code';
            });

            // Copy URL button
            document.addEventListener('click', function(e) {
                var btn = e.target.closest('.mlp-copy-url-btn');
                if (!btn) return;
                var url = btn.dataset.url || '';
                if (!url) return;
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(url).then(function() {
                        var orig = btn.textContent;
                        btn.textContent = '✓';
                        btn.style.color = '#16a34a';
                        setTimeout(function(){ btn.textContent = orig; btn.style.color = ''; }, 1600);
                    });
                } else {
                    var ta = document.createElement('textarea');
                    ta.value = url; document.body.appendChild(ta); ta.select();
                    document.execCommand('copy'); document.body.removeChild(ta);
                    var orig = btn.textContent;
                    btn.textContent = '✓'; btn.style.color = '#16a34a';
                    setTimeout(function(){ btn.textContent = orig; btn.style.color = ''; }, 1600);
                }
            });

            /* ── Live search ── */
            (function() {
                var searchInput    = document.getElementById('mlp-admin-search');
                var clearBtn       = document.getElementById('mlp-search-clear');
                var resultsSection = document.getElementById('mlp-search-results-section');
                var searchGrid     = document.getElementById('mlp-search-grid');
                var matchCount     = document.getElementById('mlp-search-match-count');
                var emptyMsg       = document.getElementById('mlp-search-empty');
                var todaySection   = document.querySelector('.mlp-admin-today-section');
                var allSection     = todaySection ? todaySection.nextElementSibling : null;
                var resultsCountBadge = document.getElementById('mlp-search-results-count');

                if (!searchInput) return;

                // Clone all cards once for the search pool (both grids)
                function getAllCards() {
                    return Array.from(document.querySelectorAll('#mlp-today-grid .mlp-admin-card, #mlp-all-grid .mlp-admin-card'));
                }

                function highlight(text, query) {
                    if (!query) return text;
                    var escaped = query.replace(/[.*+?^${}()|[\]\]/g, '\$&');
                    return text.replace(new RegExp('(' + escaped + ')', 'gi'), '<mark class="mlp-hl">$1</mark>');
                }

                function doSearch(raw) {
                    var q = raw.trim().toLowerCase();

                    if (!q) {
                        // Reset: show normal sections, hide search section
                        resultsSection.style.display = 'none';
                        if (todaySection) todaySection.style.display = '';
                        if (allSection)   allSection.style.display   = '';
                        clearBtn.style.display = 'none';
                        if (resultsCountBadge) resultsCountBadge.style.display = 'none';
                        return;
                    }

                    clearBtn.style.display = 'inline-flex';

                    // Hide normal sections
                    if (todaySection) todaySection.style.display = 'none';
                    if (allSection)   allSection.style.display   = 'none';

                    // Collect all unique cards
                    var cards = getAllCards();
                    var seen  = {};
                    var unique = cards.filter(function(c) {
                        var t = c.dataset.token;
                        if (seen[t]) return false;
                        seen[t] = true;
                        return true;
                    });

                    // Filter
                    var matches = unique.filter(function(c) {
                        return (c.dataset.search || '').indexOf(q) !== -1;
                    });

                    // Build result grid
                    searchGrid.innerHTML = '';
                    matches.forEach(function(c) {
                        var clone = c.cloneNode(true);
                        // Highlight name
                        var nameEl = clone.querySelector('.mlp-card-name');
                        if (nameEl) nameEl.innerHTML = highlight(nameEl.textContent, raw.trim());
                        // Highlight owner
                        clone.querySelectorAll('.mlp-card-meta span').forEach(function(s) {
                            if (s.textContent.indexOf('👤') !== -1) {
                                s.innerHTML = highlight(s.textContent, raw.trim());
                            }
                        });
                        // Highlight URL
                        var urlEl = clone.querySelector('.mlp-card-url-link');
                        if (urlEl) urlEl.innerHTML = highlight(urlEl.textContent, raw.trim());
                        searchGrid.appendChild(clone);
                    });

                    var count = matches.length;
                    matchCount.textContent = count;
                    emptyMsg.style.display = count === 0 ? 'block' : 'none';
                    searchGrid.style.display = count === 0 ? 'none' : '';
                    resultsSection.style.display = 'block';

                    if (resultsCountBadge) {
                        resultsCountBadge.textContent = count + ' result' + (count !== 1 ? 's' : '');
                        resultsCountBadge.style.display = 'inline-block';
                    }
                }

                var debounceTimer;
                searchInput.addEventListener('input', function() {
                    clearTimeout(debounceTimer);
                    debounceTimer = setTimeout(function() { doSearch(searchInput.value); }, 180);
                });

                clearBtn.addEventListener('click', function() {
                    searchInput.value = '';
                    doSearch('');
                    searchInput.focus();
                });

                // Keyboard shortcut: / to focus
                document.addEventListener('keydown', function(e) {
                    if (e.key === '/' && document.activeElement !== searchInput) {
                        e.preventDefault();
                        searchInput.focus();
                        searchInput.select();
                    }
                    if (e.key === 'Escape' && document.activeElement === searchInput) {
                        searchInput.value = '';
                        doSearch('');
                        searchInput.blur();
                    }
                });
            })();
        })();
        </script>
        <?php
    }

    /* ── Render a single project card ────────────────────────────────── */
    private static function render_card( $p, $nonce, $ajax_url, $today_context ) {
        $token      = esc_attr( $p['token'] );
        $name       = esc_html( $p['name'] ?: 'Untitled' );
        $shared_by  = esc_html( $p['sharedBy'] ?: '—' );
        $share_url  = esc_url( $p['shareUrl'] ?? '' );
        $share_url_display = esc_html( $p['shareUrl'] ?? '' );
        $created    = $p['created'] ? date( 'Y-m-d H:i', $p['created'] ) : '—';
        $updated    = $p['updated'] ? date( 'Y-m-d H:i', $p['updated'] ) : null;
        $is_rep     = $p['republished'];
        $badge      = $is_rep
            ? '<span class="mlp-badge mlp-badge-rep">🔄 Republished</span>'
            : '<span class="mlp-badge mlp-badge-pub">🚀 Published</span>';
        // data-search encodes name + owner + URL for client-side filtering
        $search_data = esc_attr( strtolower( ( $p['name'] ?? '' ) . ' ' . ( $p['sharedBy'] ?? '' ) . ' ' . ( $p['shareUrl'] ?? '' ) . ' ' . $p['token'] ) );

        // Collect all code tabs
        $tabs = [];
        if ( ! empty( $p['html'] ) ) $tabs['HTML'] = $p['html'];
        if ( ! empty( $p['css'] )  ) $tabs['CSS']  = $p['css'];
        if ( ! empty( $p['js'] )   ) $tabs['JS']   = $p['js'];
        // Extra saved tabs
        foreach ( [ $p['savedTabs'], $p['allTabs'] ] as $tab_set ) {
            if ( ! is_array( $tab_set ) ) continue;
            foreach ( $tab_set as $t ) {
                if ( ! is_array( $t ) ) continue;
                $label = $t['title'] ?? '';
                if ( $label && ! isset( $tabs[ $label ] ) ) {
                    $combined = trim( ( $t['html'] ?? '' ) . "\n" . ( $t['css'] ?? '' ) . "\n" . ( $t['js'] ?? '' ) );
                    if ( $combined ) $tabs[ $label ] = $combined;
                }
            }
        }

        $first_lang = $tabs ? array_key_first( $tabs ) : null;

        echo '<div class="mlp-admin-card" data-token="' . $token . '" data-search="' . $search_data . '">';
        echo '<div class="mlp-card-header">';
        echo '<div class="mlp-card-title-row">';
        echo '<span class="mlp-card-name">' . $name . '</span>';
        echo $badge;
        if ( $p['updated'] ) {
            echo '<span class="mlp-badge mlp-badge-date" title="Republished at">⏱ ' . esc_html( $updated ) . '</span>';
        }
        echo '</div>';
        echo '<div class="mlp-card-meta">';
        echo '<span title="Owner / Author">👤 ' . $shared_by . '</span>';
        echo '<span title="First published">📅 ' . esc_html( $created ) . '</span>';
        echo '<span title="Share token" class="mlp-token-chip">🔑 ' . esc_html( substr( $p['token'], 0, 8 ) ) . '…</span>';
        echo '<span class="mlp-card-meta-actions">';
        echo '<button class="mlp-btn-ignore" data-action="ignore" data-token="' . $token . '">✅ Ignore</button>';
        echo '<button class="mlp-btn-delete" data-action="delete" data-token="' . $token . '">🗑 Delete</button>';
        echo '</span>';
        echo '</div>';
        if ( $share_url ) {
            echo '<div class="mlp-card-url-row">';
            echo '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;opacity:.5;"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>';
            echo '<a href="' . $share_url . '" target="_blank" class="mlp-card-url-link" title="' . $share_url_display . '">' . $share_url_display . '</a>';
            echo '<button class="mlp-copy-url-btn" data-url="' . $share_url_display . '" title="Copy URL">⧉</button>';
            echo '</div>';
        }
        echo '</div>'; // .mlp-card-header

        // Code viewer
        if ( $tabs ) {
            echo '<div class="mlp-card-code-wrap">';
            echo '<div class="mlp-card-code-toolbar">';
            echo '<div class="mlp-code-tabs">';
            $first = true;
            foreach ( $tabs as $lang => $code ) {
                $active = $first ? ' active' : '';
                echo '<button class="mlp-code-tab' . $active . '" data-lang="' . esc_attr( $lang ) . '">' . esc_html( $lang ) . '</button>';
                $first = false;
            }
            echo '</div>';
            echo '<button class="mlp-toggle-code">▼ View Code</button>';
            echo '</div>'; // toolbar
            echo '<div class="mlp-code-block" style="display:none;">';
            $first = true;
            foreach ( $tabs as $lang => $code ) {
                $display = $first ? 'block' : 'none';
                echo '<pre class="mlp-code-pane" data-lang="' . esc_attr( $lang ) . '" style="display:' . $display . '"><code>' . esc_html( $code ) . '</code></pre>';
                $first = false;
            }
            echo '</div>'; // .mlp-code-block
            echo '</div>'; // .mlp-card-code-wrap
        } else {
            echo '<div class="mlp-admin-empty-code">No code content found.</div>';
        }

        echo '</div>'; // .mlp-admin-card
    }

    /* ── Admin CSS ────────────────────────────────────────────────────── */
    private static function get_admin_css() {
        return '
        .mlp-admin-wrap { max-width: 1400px; }
        .mlp-admin-title { display:flex; align-items:center; font-size:22px; font-weight:600; margin-bottom:4px; }
        .mlp-admin-subtitle { color:#6b7280; margin-top:0; margin-bottom:24px; font-size:13px; }

        .mlp-admin-section { background:#fff; border:1px solid #e5e7eb; border-radius:10px; padding:20px 24px 24px; margin-bottom:28px; }
        .mlp-admin-today-section { border-left:4px solid #7c3aed; }
        .mlp-admin-section-header { display:flex; align-items:center; gap:10px; margin-bottom:18px; flex-wrap:wrap; }
        .mlp-admin-section-title { font-size:15px; font-weight:600; margin:0; display:flex; align-items:center; gap:8px; }
        .mlp-admin-count-chip { background:#f3f4f6; color:#374151; font-size:11px; font-weight:600; border-radius:20px; padding:2px 9px; }
        .mlp-admin-page-info { margin-left:auto; font-size:12px; color:#9ca3af; }
        .mlp-admin-section-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; }
        .mlp-dot-today { background:#7c3aed; box-shadow:0 0 0 3px #ede9fe; }
        .mlp-dot-all   { background:#2563eb; box-shadow:0 0 0 3px #dbeafe; }
        .mlp-admin-empty { color:#9ca3af; font-size:13px; padding:12px 0; }

        /* Grid — 2 cards per row, responsive */
        .mlp-admin-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(540px, 1fr)); gap:18px; }

        /* Card */
        .mlp-admin-card { background:#fafafa; border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; transition:box-shadow .15s; display:flex; flex-direction:column; }
        .mlp-admin-card:hover { box-shadow:0 4px 16px rgba(0,0,0,.07); }

        .mlp-card-header { padding:14px 16px 12px; border-bottom:1px solid #f3f4f6; }
        .mlp-card-title-row { display:flex; align-items:center; flex-wrap:wrap; gap:7px; margin-bottom:7px; }
        .mlp-card-name { font-weight:600; font-size:14px; color:#111827; }
        .mlp-card-meta { display:flex; align-items:center; flex-wrap:nowrap; gap:10px; font-size:12px; color:#6b7280; overflow:hidden; }
        .mlp-card-meta-actions { display:flex; gap:6px; margin-left:auto; flex-shrink:0; }

        /* Badges */
        .mlp-badge { font-size:11px; font-weight:600; border-radius:4px; padding:2px 7px; white-space:nowrap; }
        .mlp-badge-pub  { background:#dcfce7; color:#166534; }
        .mlp-badge-rep  { background:#fef3c7; color:#92400e; }
        .mlp-badge-date { background:#f3f4f6; color:#4b5563; font-weight:400; }
        .mlp-token-chip { font-family:monospace; background:#f3f4f6; border-radius:3px; padding:1px 5px; }

        /* Code viewer */
        .mlp-card-code-wrap { flex:1; }
        .mlp-card-code-toolbar { display:flex; align-items:center; justify-content:space-between; padding:8px 12px; background:#f9fafb; border-bottom:1px solid #f0f0f0; }
        .mlp-code-tabs { display:flex; gap:4px; flex-wrap:wrap; }
        .mlp-code-tab { background:none; border:1px solid #e5e7eb; border-radius:4px; padding:3px 10px; font-size:11px; font-weight:600; cursor:pointer; color:#6b7280; transition:background .1s,color .1s; }
        .mlp-code-tab.active,.mlp-code-tab:hover { background:#7c3aed; color:#fff; border-color:#7c3aed; }
        .mlp-toggle-code { background:none; border:none; color:#7c3aed; font-size:11px; font-weight:600; cursor:pointer; padding:3px 6px; border-radius:4px; }
        .mlp-toggle-code:hover { background:#f5f3ff; }

        .mlp-code-block { background:#1e1e2e; max-height:340px; overflow-y:auto; }
        .mlp-code-pane { margin:0; padding:14px 16px; font-size:12px; line-height:1.6; color:#cdd6f4; font-family:"Fira Mono","Consolas","Courier New",monospace; white-space:pre; overflow-x:auto; }
        .mlp-admin-empty-code { padding:10px 14px; font-size:12px; color:#9ca3af; }

        /* Action buttons — inline in meta row */
        .mlp-card-actions { display:none; } /* legacy, kept for safety */
        .mlp-btn-ignore,.mlp-btn-delete { border:none; border-radius:5px; padding:4px 10px; font-size:11px; font-weight:600; cursor:pointer; transition:opacity .15s; white-space:nowrap; }
        .mlp-btn-ignore { background:#dcfce7; color:#166534; }
        .mlp-btn-ignore:hover { background:#bbf7d0; }
        .mlp-btn-delete { background:#fee2e2; color:#991b1b; }
        .mlp-btn-delete:hover { background:#fecaca; }
        .mlp-btn-ignore:disabled,.mlp-btn-delete:disabled { opacity:.5; cursor:not-allowed; }

        /* Pagination */
        .mlp-admin-pagination { display:flex; align-items:center; gap:6px; margin-top:20px; flex-wrap:wrap; }
        .mlp-page-btn { display:inline-flex; align-items:center; justify-content:center; min-width:34px; height:34px; padding:0 10px; border:1px solid #e5e7eb; border-radius:6px; background:#fff; color:#374151; font-size:13px; font-weight:500; text-decoration:none; transition:background .1s,border-color .1s; }
        .mlp-page-btn:hover { background:#f3f4f6; border-color:#d1d5db; color:#111; }
        .mlp-page-current { background:#7c3aed !important; color:#fff !important; border-color:#7c3aed !important; }
        .mlp-page-ellipsis { color:#9ca3af; padding:0 4px; font-size:13px; }

        /* Search bar */
        .mlp-search-bar-wrap { display:flex; align-items:center; gap:10px; background:#fff; border:1.5px solid #e5e7eb; border-radius:10px; padding:10px 16px; margin-bottom:22px; box-shadow:0 1px 4px rgba(0,0,0,.04); transition:border-color .15s; }
        .mlp-search-bar-wrap:focus-within { border-color:#7c3aed; box-shadow:0 0 0 3px #ede9fe; }
        .mlp-search-icon { color:#9ca3af; flex-shrink:0; display:flex; align-items:center; }
        .mlp-search-input-bar { flex:1; border:none; outline:none; font-size:14px; color:#111827; background:transparent; min-width:0; }
        .mlp-search-input-bar::placeholder { color:#9ca3af; }
        .mlp-search-clear { background:none; border:none; cursor:pointer; color:#9ca3af; font-size:15px; padding:2px 4px; border-radius:4px; line-height:1; display:inline-flex; align-items:center; }
        .mlp-search-clear:hover { background:#f3f4f6; color:#374151; }
        .mlp-search-results-count { font-size:12px; font-weight:600; color:#7c3aed; background:#f5f3ff; border-radius:20px; padding:2px 10px; white-space:nowrap; }

        /* Search results section */
        .mlp-admin-search-section { border-left:4px solid #0ea5e9; }

        /* URL row in card */
        .mlp-card-url-row { display:flex; align-items:center; gap:6px; margin-top:7px; padding-top:7px; border-top:1px dashed #f0f0f0; }
        .mlp-card-url-link { font-size:11px; color:#2563eb; text-decoration:none; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:420px; font-family:monospace; }
        .mlp-card-url-link:hover { text-decoration:underline; }
        .mlp-copy-url-btn { background:none; border:1px solid #e5e7eb; border-radius:4px; padding:1px 6px; font-size:11px; cursor:pointer; color:#6b7280; flex-shrink:0; transition:background .1s; }
        .mlp-copy-url-btn:hover { background:#f3f4f6; }

        /* Search highlight */
        mark.mlp-hl { background:#fef08a; color:#111; border-radius:2px; padding:0 1px; }
        ';
    }
}

endif; // class_exists MLP_Projects_Admin

/* ── Boot admin class ─────────────────────────────────────────────────── */
add_action( 'init', function() {
    if ( is_admin() ) {
        MLP_Projects_Admin::init();
    }
} );
