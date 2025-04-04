<?php
/**
 * Plugin Name:       Spudcryption
 * Plugin URI:        https://example.com/spudcryption (Replace with actual URI)
 * Description:       Envelope Encryption
 * Version:           1.0.0
 * Author:            Mr. Potato
 * Author URI:        https://example.com/mr-potato (Replace with actual URI)
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       spudcryption
 * Domain Path:       /languages
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

define( 'SPUDCRYPTION_VERSION', '1.0.0' );
define( 'SPUDCRYPTION_PATH', plugin_dir_path( __FILE__ ) );
define( 'SPUDCRYPTION_URL', plugin_dir_url( __FILE__ ) );
define( 'SPUDCRYPTION_KEK_CONSTANT', 'SPUDCRYPTION_KEK' ); // The constant name in wp-config.php
define( 'SPUDCRYPTION_OPTIONS_PREFIX', 'spudcryption_' );
define( 'SPUDCRYPTION_LOG_OPTION', SPUDCRYPTION_OPTIONS_PREFIX . 'log' );
define( 'SPUDCRYPTION_DEK_OPTION', SPUDCRYPTION_OPTIONS_PREFIX . 'deks' );
define( 'SPUDCRYPTION_SETTINGS_OPTION', SPUDCRYPTION_OPTIONS_PREFIX . 'settings' );
define( 'SPUDCRYPTION_CRON_HOOK', 'spudcryption_rotate_dek_hook' );

// Check for OpenSSL
if ( ! extension_loaded('openssl') ) {
    add_action( 'admin_notices', function() {
        echo '<div class="notice notice-error"><p>';
        esc_html_e( 'Spudcryption Error: The OpenSSL PHP extension is required but not enabled. Please enable it.', 'spudcryption' );
        echo '</p></div>';
    });
    // Optionally deactivate the plugin or prevent further loading
    // return;
}

// Check if KEK is defined
if ( ! defined( SPUDCRYPTION_KEK_CONSTANT ) ) {
     add_action( 'admin_notices', function() {
        echo '<div class="notice notice-error"><p>';
        printf(
            /* translators: %s: Constant name */
            esc_html__( 'Spudcryption Error: The Key Encryption Key constant "%s" is not defined in your wp-config.php file. Spudcryption cannot function without it.', 'spudcryption' ),
            esc_html( SPUDCRYPTION_KEK_CONSTANT )
        );
         echo '</p><p>';
         esc_html_e( 'Please define it with a strong, random key (e.g., 64 hex characters). Example:', 'spudcryption');
         echo ' <code>define( \'' . esc_html( SPUDCRYPTION_KEK_CONSTANT ) . '\', \'YOUR_STRONG_RANDOM_HEX_KEY_HERE\' );</code>';
         echo '</p></div>';
    });
    // Optionally deactivate or prevent loading
    // return;
} elseif ( defined( SPUDCRYPTION_KEK_CONSTANT ) && strlen( constant( SPUDCRYPTION_KEK_CONSTANT ) ) < 32 ) { // Basic length check (32 bytes = 256 bits)
     add_action( 'admin_notices', function() {
        echo '<div class="notice notice-warning"><p>';
        printf(
            /* translators: %s: Constant name */
            esc_html__( 'Spudcryption Warning: The Key Encryption Key defined in "%s" seems short. Please ensure it is a cryptographically strong key (recommend 64+ hex characters / 32+ bytes).', 'spudcryption' ),
            esc_html( SPUDCRYPTION_KEK_CONSTANT )
        );
        echo '</p></div>';
    });
}


// Include core files
require_once SPUDCRYPTION_PATH . 'includes/class-spudcryption-logger.php';
require_once SPUDCRYPTION_PATH . 'includes/class-spudcryption-crypto.php';
require_once SPUDCRYPTION_PATH . 'includes/class-spudcryption-dek-manager.php';
require_once SPUDCRYPTION_PATH . 'includes/class-spudcryption-core.php';

// Include admin files if in admin area
if ( is_admin() ) {
    require_once SPUDCRYPTION_PATH . 'admin/class-spudcryption-admin.php';
}

/**
 * The main function to retrieve the Spudcryption Core instance.
 * Ensures only one instance is loaded.
 *
 * @return Spudcryption_Core
 */
function spudcryption() {
    static $instance = null;
    if ( null === $instance ) {
        $instance = new Spudcryption_Core();
    }
    return $instance;
}

// Initialize the plugin (can be called early)
spudcryption();

// Initialize Admin
if ( is_admin() ) {
    new Spudcryption_Admin();
}


// --- Public API Functions ---

/**
 * Encrypts a string using the current active DEK.
 *
 * @param string $plaintext     The string to encrypt.
 * @param string $source_plugin A slug or identifier for the calling plugin (for logging).
 * @return string|false The encrypted string (base64 encoded "dek_id:iv:ciphertext:tag") or false on failure.
 */
function spudcryption_encrypt_string( $plaintext, $source_plugin = 'unknown' ) {
    return spudcryption()->encrypt_string( $plaintext, $source_plugin );
}

/**
 * Decrypts a string previously encrypted by Spudcryption.
 * Automatically detects the DEK used based on the encrypted string format.
 *
 * @param string $ciphertext    The encrypted string (base64 encoded "dek_id:iv:ciphertext:tag").
 * @param string $source_plugin A slug or identifier for the calling plugin (for logging).
 * @return string|false The original plaintext string, or false on failure (e.g., invalid format, decryption failed).
 */
function spudcryption_decrypt_string( $ciphertext, $source_plugin = 'unknown' ) {
    // Basic check: If it doesn't look like our format, return original (or false?)
    // This helps prevent errors if trying to decrypt unencrypted data.
    // A more robust check would involve trying to parse the base64 and ':' structure.
    if ( ! is_string($ciphertext) || strpos( base64_decode($ciphertext, true), ':' ) === false ) {
         Spudcryption_Logger::log( 'decrypt_attempt_skipped', $source_plugin, 'invalid_format', ['ciphertext_preview' => substr($ciphertext, 0, 50)] );
        return $ciphertext; // Return original if it doesn't look encrypted
        // return false; // Alternative: return false if not decryptable
    }
    return spudcryption()->decrypt_string( $ciphertext, $source_plugin );
}

/**
 * Encrypts a file using the current active DEK.
 * Creates the encrypted file and a metadata file (.meta).
 *
 * @param string $source_path   Path to the original file.
 * @param string $dest_path     Path where the encrypted file should be saved (e.g., file.enc).
 * @param string $source_plugin A slug or identifier for the calling plugin (for logging).
 * @return bool True on success, false on failure.
 */
function spudcryption_encrypt_file( $source_path, $dest_path, $source_plugin = 'unknown' ) {
    return spudcryption()->encrypt_file( $source_path, $dest_path, $source_plugin );
}

/**
 * Decrypts a file previously encrypted by Spudcryption.
 * Reads the associated metadata file (.meta).
 *
 * @param string $source_path   Path to the encrypted file (e.g., file.enc).
 * @param string $dest_path     Path where the decrypted file should be saved.
 * @param string $source_plugin A slug or identifier for the calling plugin (for logging).
 * @return bool True on success, false on failure.
 */
function spudcryption_decrypt_file( $source_path, $dest_path, $source_plugin = 'unknown' ) {
    return spudcryption()->decrypt_file( $source_path, $dest_path, $source_plugin );
}


// --- Activation / Deactivation / Cron ---

register_activation_hook( __FILE__, 'spudcryption_activate' );
register_deactivation_hook( __FILE__, 'spudcryption_deactivate' );

/**
 * Activation hook. Schedule the initial cron job.
 */
function spudcryption_activate() {
    // Ensure DEK manager is loaded to get defaults
    require_once SPUDCRYPTION_PATH . 'includes/class-spudcryption-dek-manager.php';
    $settings = get_option( SPUDCRYPTION_SETTINGS_OPTION, [] );
    $rotation_interval = isset( $settings['rotation_interval'] ) ? $settings['rotation_interval'] : 'daily'; // Default

    if ( ! wp_next_scheduled( SPUDCRYPTION_CRON_HOOK ) ) {
        wp_schedule_event( time(), $rotation_interval, SPUDCRYPTION_CRON_HOOK );
    }

    // Generate initial DEK if none exists
    spudcryption()->get_dek_manager()->get_active_dek();
}

/**
 * Deactivation hook. Clear the cron job.
 */
function spudcryption_deactivate() {
    wp_clear_scheduled_hook( SPUDCRYPTION_CRON_HOOK );
}

/**
 * Cron job callback function to rotate the DEK.
 */
function spudcryption_rotate_dek() {
    require_once SPUDCRYPTION_PATH . 'includes/class-spudcryption-logger.php';
    require_once SPUDCRYPTION_PATH . 'includes/class-spudcryption-crypto.php';
    require_once SPUDCRYPTION_PATH . 'includes/class-spudcryption-dek-manager.php';

    Spudcryption_Logger::log('cron_rotate_start', 'spudcryption_cron', 'system');
    $dek_manager = new Spudcryption_DEK_Manager(); // Needs KEK
    $rotated = $dek_manager->rotate_dek();
    if ($rotated) {
         Spudcryption_Logger::log('cron_rotate_success', 'spudcryption_cron', 'system', ['new_dek_id' => $dek_manager->get_active_dek_id()]);
    } else {
         Spudcryption_Logger::log('cron_rotate_failed', 'spudcryption_cron', 'system');
    }
}
add_action( SPUDCRYPTION_CRON_HOOK, 'spudcryption_rotate_dek' );