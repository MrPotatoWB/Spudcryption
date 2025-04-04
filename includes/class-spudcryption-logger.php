<?php
// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

/**
 * Spudcryption_Logger Class
 *
 * Simple logger storing entries in a WordPress option.
 * NOTE: For high-volume logging, a custom table is recommended.
 */
class Spudcryption_Logger {

    private static $max_log_entries = 200; // Limit number of entries stored in options

    /**
     * Log an event.
     *
     * @param string $action        A code for the action (e.g., 'encrypt_success', 'dek_rotate').
     * @param string $source        Identifier for the source (e.g., plugin slug, 'cron', 'admin').
     * @param string $target        Identifier for the target (e.g., option name, file path, 'system').
     * @param array  $details       Optional additional details (avoid logging sensitive data).
     */
    public static function log( $action, $source = 'unknown', $target = 'unknown', $details = [] ) {
        $log_entries = get_option( SPUDCRYPTION_LOG_OPTION, [] );

        // Ensure it's an array
        if (!is_array($log_entries)) {
            $log_entries = [];
        }

        $entry = [
            'timestamp' => current_time( 'mysql', true ), // GMT timestamp
            'action'    => sanitize_key( $action ),
            'source'    => sanitize_text_field( $source ),
            'target'    => sanitize_text_field( $target ),
            'details'   => array_map( 'sanitize_text_field', $details ) // Basic sanitization
        ];

        // Add new entry to the beginning
        array_unshift( $log_entries, $entry );

        // Trim log to max size
        if ( count( $log_entries ) > self::$max_log_entries ) {
            $log_entries = array_slice( $log_entries, 0, self::$max_log_entries );
        }

        update_option( SPUDCRYPTION_LOG_OPTION, $log_entries, 'no' ); // 'no' for autoload
    }

    /**
     * Retrieve log entries.
     *
     * @param int $limit Number of entries to retrieve.
     * @return array Array of log entries (newest first).
     */
    public static function get_logs( $limit = 50 ) {
        $log_entries = get_option( SPUDCRYPTION_LOG_OPTION, [] );
         if (!is_array($log_entries)) {
            $log_entries = [];
        }
        return array_slice( $log_entries, 0, $limit );
    }

    /**
     * Clear all log entries.
     */
    public static function clear_logs() {
        delete_option( SPUDCRYPTION_LOG_OPTION );
        self::log('logs_cleared', 'spudcryption_admin', 'system');
    }
}