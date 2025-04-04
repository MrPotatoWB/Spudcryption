<?php
// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

// Ensure we are in admin context and have the necessary functions.
if ( ! current_user_can( 'manage_options' ) ) {
    return;
}

?>
<div class="wrap spudcryption-wrap">
    <h1><?php esc_html_e( 'Spudcryption Settings', 'spudcryption' ); ?></h1>
    <p><?php esc_html_e( 'Configure DEK rotation and view activity logs. Made by Mr. Potato!', 'spudcryption' ); ?></p>

    <?php
    // Display settings errors/update messages
    settings_errors('spudcryption_settings');
    ?>

    <h2 class="nav-tab-wrapper">
        <a href="#settings" class="nav-tab nav-tab-active"><?php esc_html_e( 'Settings', 'spudcryption' ); ?></a>
        <a href="#logs" class="nav-tab"><?php esc_html_e( 'Logs', 'spudcryption' ); ?></a>
    </h2>

    <div id="settings" class="tab-content active">
        <form method="post" action="options.php">
            <?php
            settings_fields( 'spudcryption_settings_group' ); // Output nonce, action, and option_page fields for Settings API group
            do_settings_sections( 'spudcryption-settings' ); // Output the fields for the page slug
            submit_button( __( 'Save Rotation Settings', 'spudcryption' ) );
            ?>
        </form>

        <hr>
        <h3><?php esc_html_e( 'Manual Actions', 'spudcryption' ); ?></h3>
         <form method="post" action="<?php echo esc_url( admin_url( 'options-general.php?page=spudcryption-settings' ) ); ?>" style="display: inline-block; margin-right: 10px;">
            <?php wp_nonce_field( 'spudcryption_admin_actions' ); ?>
            <input type="hidden" name="spudcryption_action" value="rotate_now">
            <?php submit_button( __( 'Rotate DEK Now', 'spudcryption' ), 'secondary', 'submit_rotate', false ); ?>
             <p class="description"><?php esc_html_e( 'Manually generate and activate a new DEK immediately.', 'spudcryption' ); ?></p>
        </form>

    </div>

    <div id="logs" class="tab-content" style="display: none;">
        <h2><?php esc_html_e( 'Activity Log', 'spudcryption' ); ?></h2>
        <p><?php esc_html_e( 'Recent encryption/decryption activities and system events.', 'spudcryption' ); ?></p>

        <form method="post" action="<?php echo esc_url( admin_url( 'options-general.php?page=spudcryption-settings' ) ); ?>" style="margin-bottom: 15px;">
            <?php wp_nonce_field( 'spudcryption_admin_actions' ); ?>
            <input type="hidden" name="spudcryption_action" value="clear_logs">
            <?php submit_button( __( 'Clear Logs', 'spudcryption' ), 'delete', 'submit_clear_logs', false, ['onclick' => 'return confirm("' . esc_js( __( 'Are you sure you want to clear all Spudcryption logs?', 'spudcryption' ) ) . '");'] ); ?>
        </form>

        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th scope="col" style="width: 180px;"><?php esc_html_e( 'Timestamp (GMT)', 'spudcryption' ); ?></th>
                    <th scope="col" style="width: 150px;"><?php esc_html_e( 'Action', 'spudcryption' ); ?></th>
                    <th scope="col" style="width: 150px;"><?php esc_html_e( 'Source', 'spudcryption' ); ?></th>
                    <th scope="col"><?php esc_html_e( 'Target / Details', 'spudcryption' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php
                $logs = Spudcryption_Logger::get_logs( 100 ); // Get recent 100 entries
                if ( empty( $logs ) ) : ?>
                    <tr>
                        <td colspan="4"><?php esc_html_e( 'No log entries found.', 'spudcryption' ); ?></td>
                    </tr>
                <?php else :
                    foreach ( $logs as $entry ) : ?>
                        <tr>
                            <td><?php echo esc_html( $entry['timestamp'] ); ?></td>
                            <td><code><?php echo esc_html( $entry['action'] ); ?></code></td>
                            <td><?php echo esc_html( $entry['source'] ); ?></td>
                            <td>
                                <strong><?php echo esc_html( $entry['target'] ); ?></strong>
                                <?php if ( ! empty( $entry['details'] ) ) : ?>
                                    <small>(<?php
                                        $details_str = [];
                                        foreach ($entry['details'] as $key => $value) {
                                            $details_str[] = esc_html($key) . ': ' . esc_html($value);
                                        }
                                        echo implode(', ', $details_str);
                                     ?>)</small>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach;
                endif; ?>
            </tbody>
        </table>
    </div>

</div>

<style>
    .spudcryption-wrap .nav-tab { cursor: pointer; }
    .spudcryption-wrap .tab-content { padding: 15px; border: 1px solid #ccc; border-top: none; background: #fff; margin-bottom: 20px; }
</style>

<script type="text/javascript">
    jQuery(document).ready(function($) {
        $('.spudcryption-wrap .nav-tab').on('click', function(e) {
            e.preventDefault();
            var $tab = $(this);
            var target = $tab.attr('href');

            // Toggle active tab class
            $('.spudcryption-wrap .nav-tab').removeClass('nav-tab-active');
            $tab.addClass('nav-tab-active');

            // Hide all content, show target content
            $('.spudcryption-wrap .tab-content').hide();
            $(target).show();
        });

        // Ensure the initially active tab's content is shown
        var initialTarget = $('.spudcryption-wrap .nav-tab-active').attr('href');
        if (initialTarget) {
             $('.spudcryption-wrap .tab-content').hide();
             $(initialTarget).show();
        } else {
            // Fallback if somehow no tab is active initially
             $('.spudcryption-wrap .tab-content').first().show();
             $('.spudcryption-wrap .nav-tab').first().addClass('nav-tab-active');
        }
    });
</script>