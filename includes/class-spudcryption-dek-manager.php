<?php
// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

/**
 * Spudcryption_DEK_Manager Class
 *
 * Handles generation, storage, retrieval, and rotation of Data Encryption Keys (DEKs).
 * DEKs are stored encrypted with the KEK.
 */
class Spudcryption_DEK_Manager {

    private $kek;
    private $deks = []; // Array format: [dek_id => ['encrypted_dek_b64' => base64(encrypted_dek), 'iv_b64' => base64(iv), 'tag_b64' => base64(tag), 'created_at' => timestamp]]
    private $active_dek_id = null;
    private $kek_loaded = false;

    public function __construct() {
        $this->load_kek();
        $this->load_deks();
    }

    /**
     * Load the KEK from wp-config.php.
     * Converts hex KEK to binary if needed.
     */
    private function load_kek() {
        if ( ! defined( SPUDCRYPTION_KEK_CONSTANT ) ) {
            Spudcryption_Logger::log('dek_error', 'spudcryption_dek_manager', 'load_kek', ['error' => 'KEK constant not defined']);
            $this->kek_loaded = false;
            return;
        }

        $kek_value = constant( SPUDCRYPTION_KEK_CONSTANT );

        // Assume KEK might be hex encoded, convert to binary
        if ( ctype_xdigit( $kek_value ) && strlen( $kek_value ) % 2 === 0 ) {
            $this->kek = hex2bin( $kek_value );
        } else {
            // Assume it's already binary or some other format (use as is)
            // WARNING: Ensure the KEK format is consistent and strong!
            $this->kek = $kek_value;
             Spudcryption_Logger::log('dek_warning', 'spudcryption_dek_manager', 'load_kek', ['warning' => 'KEK is not hex or has odd length, using value directly. Ensure it is binary.']);
        }

        // Basic length check for binary key
        if (strlen($this->kek) < 32) { // Recommend 256-bit (32 bytes) KEK
             Spudcryption_Logger::log('dek_warning', 'spudcryption_dek_manager', 'load_kek', ['warning' => 'KEK is less than 32 bytes long.']);
        }

        $this->kek_loaded = true;
    }

    /**
     * Load stored DEKs from WordPress options.
     */
    private function load_deks() {
        $stored_deks = get_option( SPUDCRYPTION_DEK_OPTION, [] );
        if ( is_array( $stored_deks ) && isset( $stored_deks['keys'] ) && isset( $stored_deks['active_id'] ) ) {
            $this->deks = $stored_deks['keys'];
            $this->active_dek_id = $stored_deks['active_id'];
        } else {
            // Initialize if option is missing or malformed
            $this->deks = [];
            $this->active_dek_id = null;
             Spudcryption_Logger::log('dek_info', 'spudcryption_dek_manager', 'load_deks', ['info' => 'No valid DEKs found in options, initializing.']);
        }
    }

    /**
     * Save the current state of DEKs to WordPress options.
     */
    private function save_deks() {
        $data_to_store = [
            'active_id' => $this->active_dek_id,
            'keys' => $this->deks,
        ];
        update_option( SPUDCRYPTION_DEK_OPTION, $data_to_store, 'no' ); // 'no' for autoload
    }

    /**
     * Generate a new DEK, encrypt it with the KEK, and store it.
     *
     * @return string|false The ID of the newly generated DEK, or false on failure.
     */
    private function generate_and_store_new_dek() {
        if ( ! $this->kek_loaded ) {
             Spudcryption_Logger::log('dek_error', 'spudcryption_dek_manager', 'generate_new', ['error' => 'KEK not loaded']);
            return false;
        }

        $new_dek_plaintext = Spudcryption_Crypto::generate_key( 32 ); // Generate a 256-bit DEK
        if ( ! $new_dek_plaintext ) {
             Spudcryption_Logger::log('dek_error', 'spudcryption_dek_manager', 'generate_new', ['error' => 'Failed to generate random DEK']);
            return false;
        }

        $iv = '';
        $tag = '';
        $encrypted_dek = Spudcryption_Crypto::encrypt( $new_dek_plaintext, $this->kek, $iv, $tag );

        if ( $encrypted_dek === false || $iv === false || $tag === false ) {
            Spudcryption_Logger::log('dek_error', 'spudcryption_dek_manager', 'generate_new', ['error' => 'Failed to encrypt new DEK with KEK']);
            return false;
        }

        $new_dek_id = uniqid( 'dek_', true ); // Generate a unique ID for the DEK
        $this->deks[ $new_dek_id ] = [
            'encrypted_dek_b64' => base64_encode( $encrypted_dek ),
            'iv_b64'            => base64_encode( $iv ),
            'tag_b64'           => base64_encode( $tag ),
            'created_at'        => time(),
        ];

        Spudcryption_Logger::log('dek_generated', 'spudcryption_dek_manager', 'generate_new', ['dek_id' => $new_dek_id]);
        return $new_dek_id;
    }

    /**
     * Get the currently active DEK (plaintext, binary).
     * Generates one if none exists.
     *
     * @return string|false The active DEK (binary) or false on failure.
     */
    public function get_active_dek() {
        if ( ! $this->active_dek_id || ! isset( $this->deks[ $this->active_dek_id ] ) ) {
            Spudcryption_Logger::log('dek_info', 'spudcryption_dek_manager', 'get_active_dek', ['info' => 'No active DEK found, generating initial DEK.']);
            $new_id = $this->generate_and_store_new_dek();
            if ( ! $new_id ) {
                return false; // Failed to generate
            }
            $this->active_dek_id = $new_id;
            $this->save_deks(); // Save immediately after generation
        }

        return $this->get_dek_by_id( $this->active_dek_id );
    }

     /**
     * Get the ID of the currently active DEK.
     *
     * @return string|null The active DEK ID or null if none.
     */
    public function get_active_dek_id() {
         // Ensure an active DEK exists if possible
        if ( ! $this->active_dek_id && $this->kek_loaded) {
            $this->get_active_dek(); // This will generate if needed
        }
        return $this->active_dek_id;
    }


    /**
     * Retrieve and decrypt a specific DEK by its ID.
     *
     * @param string $dek_id The ID of the DEK to retrieve.
     * @return string|false The plaintext DEK (binary) or false on failure (not found, KEK error, decrypt error).
     */
    public function get_dek_by_id( $dek_id ) {
        if ( ! $this->kek_loaded ) {
             Spudcryption_Logger::log('dek_error', 'spudcryption_dek_manager', 'get_dek_by_id', ['error' => 'KEK not loaded', 'dek_id' => $dek_id]);
            return false;
        }
        if ( ! isset( $this->deks[ $dek_id ] ) ) {
             Spudcryption_Logger::log('dek_error', 'spudcryption_dek_manager', 'get_dek_by_id', ['error' => 'DEK ID not found', 'dek_id' => $dek_id]);
            return false;
        }

        $dek_info = $this->deks[ $dek_id ];

        // Decode from base64
        $encrypted_dek = base64_decode( $dek_info['encrypted_dek_b64'], true );
        $iv = base64_decode( $dek_info['iv_b64'], true );
        $tag = base64_decode( $dek_info['tag_b64'], true );

        if ( $encrypted_dek === false || $iv === false || $tag === false ) {
             Spudcryption_Logger::log('dek_error', 'spudcryption_dek_manager', 'get_dek_by_id', ['error' => 'Failed to base64 decode DEK components', 'dek_id' => $dek_id]);
            return false;
        }

        $plaintext_dek = Spudcryption_Crypto::decrypt( $encrypted_dek, $this->kek, $iv, $tag );

        if ( $plaintext_dek === false ) {
            // Decryption failed! Could be KEK changed, data corruption, etc. Critical error.
            Spudcryption_Logger::log('dek_critical', 'spudcryption_dek_manager', 'get_dek_by_id', ['error' => 'Failed to decrypt DEK with KEK!', 'dek_id' => $dek_id]);
            // TODO: Maybe trigger admin notice?
            return false;
        }

        return $plaintext_dek;
    }

    /**
     * Rotate the active DEK. Generates a new DEK and sets it as active.
     * Keeps old DEKs for decrypting older data.
     *
     * @return bool True if rotation was successful, false otherwise.
     */
    public function rotate_dek() {
        Spudcryption_Logger::log('dek_rotate_start', 'spudcryption_dek_manager', 'rotate_dek', ['current_active_id' => $this->active_dek_id]);
        $new_dek_id = $this->generate_and_store_new_dek();

        if ( $new_dek_id ) {
            $this->active_dek_id = $new_dek_id;
            $this->save_deks();
            Spudcryption_Logger::log('dek_rotate_success', 'spudcryption_dek_manager', 'rotate_dek', ['new_active_id' => $this->active_dek_id]);
            return true;
        } else {
            Spudcryption_Logger::log('dek_rotate_failed', 'spudcryption_dek_manager', 'rotate_dek', ['error' => 'Failed to generate new DEK during rotation']);
            return false;
        }
    }

    /**
     * Prune old DEKs (optional - implement if needed).
     * Be careful not to remove DEKs still needed for old data.
     */
    public function prune_old_deks( $max_age_seconds ) {
        // Implementation would involve iterating $this->deks, checking 'created_at',
        // ensuring the DEK is not the active one, and removing it.
        // Requires careful consideration of data lifecycle.
        Spudcryption_Logger::log('dek_prune_skipped', 'spudcryption_dek_manager', 'prune_old_deks', ['info' => 'Pruning not implemented']);
    }
}