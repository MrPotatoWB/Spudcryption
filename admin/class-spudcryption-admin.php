<?php
// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

/**
 * Spudcryption_Admin Class
 *
 * Handles the admin settings page.
 */
class Spudcryption_Admin {

    public function __construct() {
        add_action( 'admin_menu', [ $this, 'add_admin_menu' ] );
        add_action( 'admin_init', [ $this, 'handle_form_actions' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] ); // Use Settings API
    }

    /**
     * Add the options page to the settings menu.
     */
    public function add_admin_menu() {
        add_options_page(
            __( 'Spudcryption Settings', 'spudcryption' ),
            __( 'Spudcryption', 'spudcryption' ),
            'manage_options', // Capability required
            'spudcryption-settings',
            [ $this, 'render_settings_page' ]
        );
    }

    /**
     * Register settings using the Settings API for better security and structure.
     */
     public function register_settings() {
        register_setting(
            'spudcryption_settings_group', // Option group
            SPUDCRYPTION_SETTINGS_OPTION, // Option name
            [ $this, 'sanitize_settings' ] // Sanitize callback
        );

        add_settings_section(
            'spudcryption_rotation_section', // ID
            __( 'DEK Rotation Settings', 'spudcryption' ), // Title
            null, // Callback
            'spudcryption-settings' // Page slug
        );

        add_settings_field(
            'rotation_interval', // ID
            __( 'Rotation Frequency', 'spudcryption' ), // Title
            [ $this, 'render_rotation_interval_field' ], // Callback
            'spudcryption-settings', // Page slug
            'spudcryption_rotation_section' // Section ID
        );
     }

     /**
      * Sanitize settings before saving.
      *
      * @param array $input Raw input from the form.
      * @return array Sanitized input.
      */
     public function sanitize_settings( $input ) {
        $sanitized_input = [];
        $valid_intervals = wp_get_schedules(); // Get valid WP Cron schedules

        if ( isset( $input['rotation_interval'] ) && array_key_exists( $input['rotation_interval'], $valid_intervals ) ) {
            $sanitized_input['rotation_interval'] = $input['rotation_interval'];

            // Reschedule cron job if interval changed
            $current_settings = get_option( SPUDCRYPTION_SETTINGS_OPTION, [] );
            $old_interval = isset( $current_settings['rotation_interval'] ) ? $current_settings['rotation_interval'] : 'daily'; // Default if not set

            if ( $old_interval !== $sanitized_input['rotation_interval'] ) {
                wp_clear_scheduled_hook( SPUDCRYPTION_CRON_HOOK );
                wp_schedule_event( time(), $sanitized_input['rotation_interval'], SPUDCRYPTION_CRON_HOOK );
                Spudcryption_Logger::log('cron_rescheduled', 'spudcryption_admin', 'system', ['new_interval' => $sanitized_input['rotation_interval']]);
                 add_settings_error(
                    'spudcryption_settings',
                    'cron_rescheduled',
                    sprintf( __( 'DEK rotation schedule updated to: %s. The next rotation will occur accordingly.', 'spudcryption' ), $valid_intervals[$sanitized_input['rotation_interval']]['display'] ),
                    'updated' // 'updated' or 'success' CSS class
                );
            }

        } else {
             // Add an error if the interval is invalid
             add_settings_error(
                'spudcryption_settings',
                'invalid_interval',
                __( 'Invalid rotation interval selected.', 'spudcryption' ),
                'error'
            );
            // Keep the old setting if the new one is invalid
            $current_settings = get_option( SPUDCRYPTION_SETTINGS_OPTION, [] );
            $sanitized_input['rotation_interval'] = isset( $current_settings['rotation_interval'] ) ? $current_settings['rotation_interval'] : 'daily';
        }


        return $sanitized_input;
     }

     /**
      * Render the dropdown for rotation interval.
      */
     public function render_rotation_interval_field() {
        $settings = get_option( SPUDCRYPTION_SETTINGS_OPTION, [] );
        $current_interval = isset( $settings['rotation_interval'] ) ? $settings['rotation_interval'] : 'daily'; // Default
        $schedules = wp_get_schedules();
        ?>
        <select name="<?php echo esc_attr( SPUDCRYPTION_SETTINGS_OPTION ); ?>[rotation_interval]" id="rotation_interval">
            <?php foreach ( $schedules as $name => $details ) : ?>
                <option value="<?php echo esc_attr( $name ); ?>" <?php selected( $current_interval, $name ); ?>>
                    <?php echo esc_html( $details['display'] ); ?> (<?php echo esc_html($name); ?>)
                </option>
            <?php endforeach; ?>
        </select>
        <p class="description">
            <?php esc_html_e( 'How often a new Data Encryption Key (DEK) should be generated and become active. Existing data encrypted with older keys can still be decrypted.', 'spudcryption' ); ?>
             <br>
             <?php
                $next_run = wp_next_scheduled( SPUDCRYPTION_CRON_HOOK );
                if ($next_run) {
                    printf(
                        esc_html__( 'Next scheduled rotation check: %s (%s from now)', 'spudcryption' ),
                        esc_html( get_date_from_gmt( date( 'Y-m-d H:i:s', $next_run ), 'Y-m-d H:i:s' ) ),
                        esc_html( human_time_diff( $next_run, time() ) )
                    );
                } else {
                    esc_html_e( 'Rotation schedule is not currently active. Saving settings should activate it.', 'spudcryption' );
                }
             ?>
        </p>
        <?php
     }


    /**
     * Handle manual actions like clearing logs or rotating DEK now.
     */
    public function handle_form_actions() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        // Check if our specific actions are being triggered
        if ( isset( $_POST['spudcryption_action'] ) && isset( $_POST['_wpnonce'] ) ) {
            // Verify nonce
            if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'spudcryption_admin_actions' ) ) {
                wp_die( __( 'Nonce verification failed!', 'spudcryption' ) );
            }

            $action = sanitize_key( $_POST['spudcryption_action'] );

            if ( $action === 'clear_logs' ) {
                Spudcryption_Logger::clear_logs();
                add_settings_error(
                    'spudcryption_settings', // Setting group slug
                    'logs_cleared',          // Error code
                    __( 'Spudcryption logs cleared.', 'spudcryption' ), // Message
                    'updated'                // Type ('error', 'updated', 'warning')
                );
            } elseif ( $action === 'rotate_now' ) {
                 $rotated = spudcryption()->get_dek_manager()->rotate_dek();
                 if ($rotated) {
                     add_settings_error(
                        'spudcryption_settings',
                        'dek_rotated',
                        __( 'New DEK generated and activated successfully.', 'spudcryption' ),
                        'updated'
                    );
                 } else {
                     add_settings_error(
                        'spudcryption_settings',
                        'dek_rotate_failed',
                        __( 'Failed to rotate DEK. Check Spudcryption logs for details.', 'spudcryption' ),
                        'error'
                    );
                 }
            }

            // Redirect back to the settings page to prevent form resubmission on refresh
            // Add the 'settings-updated=true' query arg manually if using add_settings_error
            $redirect_url = add_query_arg(
                [ 'page' => 'spudcryption-settings', 'settings-updated' => 'true' ],
                admin_url( 'options-general.php' )
            );
             wp_safe_redirect( $redirect_url );
             exit;
        }
    }

    /**
     * Render the HTML for the settings page.
     */
    public function render_settings_page() {
        // Check user capabilities
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( __( 'You do not have sufficient permissions to access this page.', 'spudcryption' ) );
        }

        // Include the view file
        require_once SPUDCRYPTION_PATH . 'admin/views/admin-page.php';
    }
}