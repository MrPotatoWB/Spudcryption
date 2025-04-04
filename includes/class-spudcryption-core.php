<?php
/**
 * Spudcryption Core Class
 *
 * Main class orchestrating encryption and decryption using the DEK Manager and Crypto helper.
 * Handles logging of operations without revealing sensitive internal details.
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

class Spudcryption_Core {

    private $dek_manager;

    public function __construct() {
        $this->dek_manager = new Spudcryption_DEK_Manager();
    }

    /**
     * Get the DEK Manager instance.
     * @return Spudcryption_DEK_Manager
     */
    public function get_dek_manager() {
        return $this->dek_manager;
    }

    /**
     * Encrypts a string.
     *
     * @param string $plaintext     The string to encrypt.
     * @param string $source_plugin Identifier for logging.
     * @return string|false Encrypted string (base64 encoded "dek_id:iv:ciphertext:tag") or false on failure.
     */
    public function encrypt_string( $plaintext, $source_plugin = 'unknown' ) {
        // Log the request initiation
        Spudcryption_Logger::log('encrypt_request_received', $source_plugin, 'string');

        $active_dek = $this->dek_manager->get_active_dek();
        $active_dek_id = $this->dek_manager->get_active_dek_id(); // Still needed internally for payload

        if ( ! $active_dek || ! $active_dek_id ) {
            Spudcryption_Logger::log('encrypt_failed', $source_plugin, 'string', ['error' => 'Could not retrieve active DEK']);
            return false;
        }

        $iv = '';
        $tag = '';
        $ciphertext_raw = Spudcryption_Crypto::encrypt( $plaintext, $active_dek, $iv, $tag );

        if ( $ciphertext_raw === false ) {
            // Log failure without sensitive details
            Spudcryption_Logger::log('encrypt_failed', $source_plugin, 'string', ['error' => 'Encryption crypto operation failed']);
            return false;
        }

        // Format: dek_id:base64(iv):base64(ciphertext):base64(tag)
        // Then base64 encode the whole thing for safe DB storage
        // The DEK ID is part of the payload but not logged directly
        $payload = implode( ':', [
            $active_dek_id,
            base64_encode( $iv ),
            base64_encode( $ciphertext_raw ),
            base64_encode( $tag )
        ] );

        // Log successful processing without sensitive details
        Spudcryption_Logger::log('encrypt_request_processed', $source_plugin, 'string');

        return base64_encode( $payload );
    }

    /**
     * Decrypts a string.
     *
     * @param string $ciphertext_b64 Encrypted string (base64 encoded "dek_id:iv:ciphertext:tag").
     * @param string $source_plugin  Identifier for logging.
     * @return string|false Plaintext string or false on failure.
     */
    public function decrypt_string( $ciphertext_b64, $source_plugin = 'unknown' ) {
        // Log the request initiation
        Spudcryption_Logger::log('decrypt_request_received', $source_plugin, 'string');

        $payload = base64_decode( $ciphertext_b64, true );
        if ( $payload === false ) {
             Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'string', ['error' => 'Invalid base64 input']);
            return false;
        }

        $parts = explode( ':', $payload, 4 );
        if ( count( $parts ) !== 4 ) {
            Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'string', ['error' => 'Invalid encrypted string format']);
            return false;
        }

        list( $dek_id, $iv_b64, $ciphertext_raw_b64, $tag_b64 ) = $parts; // Need ID internally

        $iv = base64_decode( $iv_b64, true );
        $ciphertext_raw = base64_decode( $ciphertext_raw_b64, true );
        $tag = base64_decode( $tag_b64, true );

        if ( $iv === false || $ciphertext_raw === false || $tag === false ) {
            // Log failure without sensitive details (like DEK ID)
            Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'string', ['error' => 'Failed to base64 decode components']);
            return false;
        }

        // Retrieve the specific DEK using the ID from the payload
        $dek = $this->dek_manager->get_dek_by_id( $dek_id );
        if ( ! $dek ) {
            // Log failure without revealing the problematic DEK ID
            Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'string', ['error' => 'Could not retrieve required DEK for decryption']);
            return false;
        }

        $plaintext = Spudcryption_Crypto::decrypt( $ciphertext_raw, $dek, $iv, $tag );

        if ( $plaintext === false ) {
            // Log failure without revealing the DEK ID
            Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'string', ['error' => 'Decryption crypto operation failed (check crypto logs if enabled)']);
            return false;
        }

        // Log successful processing without sensitive details
        Spudcryption_Logger::log('decrypt_request_processed', $source_plugin, 'string');
        return $plaintext;
    }


    /**
     * Encrypts a file stream.
     *
     * @param string $source_path   Path to the original file.
     * @param string $dest_path     Path to save the encrypted file.
     * @param string $source_plugin Identifier for logging.
     * @return bool Success or failure.
     */
    public function encrypt_file( $source_path, $dest_path, $source_plugin = 'unknown' ) {
        $source_basename = basename($source_path); // Use basename for logging
        $dest_basename = basename($dest_path);

        // Log the request initiation
        Spudcryption_Logger::log('encrypt_request_received', $source_plugin, 'file', ['source' => $source_basename]);

        if ( ! file_exists( $source_path ) || ! is_readable( $source_path ) ) {
            Spudcryption_Logger::log('encrypt_failed', $source_plugin, 'file', ['error' => 'Source file not found or not readable', 'source' => $source_basename]);
            return false;
        }

        $active_dek = $this->dek_manager->get_active_dek();
        $active_dek_id = $this->dek_manager->get_active_dek_id(); // Still needed internally for metadata

        if ( ! $active_dek || ! $active_dek_id ) {
            Spudcryption_Logger::log('encrypt_failed', $source_plugin, 'file', ['error' => 'Could not retrieve active DEK', 'source' => $source_basename]);
            return false;
        }

        // Use file handles for potentially large files
        $source_handle = @fopen( $source_path, 'rb' );
        $dest_handle = @fopen( $dest_path, 'wb' );

        if ( ! $source_handle || ! $dest_handle ) {
             Spudcryption_Logger::log('encrypt_failed', $source_plugin, 'file', ['error' => 'Could not open file handles', 'source' => $source_basename, 'dest' => $dest_basename]);
             if ($source_handle) @fclose($source_handle);
             if ($dest_handle) @fclose($dest_handle);
            return false;
        }

        // Read the entire file content - consider chunking for very large files
        // Note: openssl_encrypt operates on the whole data at once for GCM tag generation.
        // Streaming encryption with GCM is more complex. This loads the whole file into memory.
        $plaintext = fread( $source_handle, filesize( $source_path ) ?: 1 ); // Read entire file
        fclose( $source_handle );

        if ($plaintext === false) {
             Spudcryption_Logger::log('encrypt_failed', $source_plugin, 'file', ['error' => 'Could not read source file content', 'source' => $source_basename]);
             fclose($dest_handle);
             @unlink($dest_path); // Clean up empty dest file
            return false;
        }

        $iv = ''; // Will be generated by encrypt
        $tag = ''; // Will be generated by encrypt
        $ciphertext_raw = Spudcryption_Crypto::encrypt( $plaintext, $active_dek, $iv, $tag );

        if ( $ciphertext_raw === false ) {
            // Log failure without sensitive details
            Spudcryption_Logger::log('encrypt_failed', $source_plugin, 'file', ['error' => 'File encryption crypto operation failed', 'source' => $source_basename]);
            fclose( $dest_handle );
            @unlink($dest_path); // Clean up failed dest file
            return false;
        }

        // Write encrypted data
        fwrite( $dest_handle, $ciphertext_raw );
        fclose( $dest_handle );

        // --- Store Metadata ---
        // Store DEK ID, IV, Tag separately. A common way is a .meta file.
        // The DEK ID is stored in the meta file but not logged directly.
        $meta_path = $dest_path . '.meta';
        $meta_basename = basename($meta_path);
        $metadata = [
            'dek_id' => $active_dek_id,
            'iv_b64' => base64_encode( $iv ),
            'tag_b64' => base64_encode( $tag ),
            'orig_filename' => $source_basename,
            'encrypted_at' => time(),
        ];

        if ( file_put_contents( $meta_path, json_encode( $metadata ) ) === false ) {
            Spudcryption_Logger::log('encrypt_failed', $source_plugin, 'file', ['error' => 'Failed to write metadata file', 'meta_path' => $meta_basename]);
            // Critical: If metadata isn't saved, decryption is impossible.
            // Rollback: Delete the encrypted file?
            @unlink($dest_path);
            return false;
        }

        // Log successful processing without sensitive details
        Spudcryption_Logger::log('encrypt_request_processed', $source_plugin, 'file', ['source' => $source_basename, 'dest' => $dest_basename]);
        return true;
    }

    /**
     * Decrypts a file stream.
     *
     * @param string $source_path   Path to the encrypted file.
     * @param string $dest_path     Path to save the decrypted file.
     * @param string $source_plugin Identifier for logging.
     * @return bool Success or failure.
     */
    public function decrypt_file( $source_path, $dest_path, $source_plugin = 'unknown' ) {
        $source_basename = basename($source_path); // Use basename for logging
        $dest_basename = basename($dest_path);
        $meta_path = $source_path . '.meta';
        $meta_basename = basename($meta_path);

        // Log the request initiation
        Spudcryption_Logger::log('decrypt_request_received', $source_plugin, 'file', ['source' => $source_basename]);

        if ( ! file_exists( $source_path ) || ! is_readable( $source_path ) ) {
            Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'file', ['error' => 'Encrypted file not found or not readable', 'source' => $source_basename]);
            return false;
        }
         if ( ! file_exists( $meta_path ) || ! is_readable( $meta_path ) ) {
            Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'file', ['error' => 'Metadata file not found or not readable', 'meta_path' => $meta_basename]);
            return false;
        }

        // Read Metadata
        $metadata_json = file_get_contents( $meta_path );
        $metadata = json_decode( $metadata_json, true );

        if ( ! $metadata || ! isset( $metadata['dek_id'], $metadata['iv_b64'], $metadata['tag_b64'] ) ) {
            Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'file', ['error' => 'Invalid or incomplete metadata file', 'meta_path' => $meta_basename]);
            return false;
        }

        $dek_id = $metadata['dek_id']; // Need ID internally from metadata
        $iv = base64_decode( $metadata['iv_b64'], true );
        $tag = base64_decode( $metadata['tag_b64'], true );

        if ( $iv === false || $tag === false ) {
            // Log failure without sensitive details
            Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'file', ['error' => 'Failed to base64 decode IV or Tag from metadata', 'meta_path' => $meta_basename]);
            return false;
        }

        // Get the correct DEK using the ID from metadata
        $dek = $this->dek_manager->get_dek_by_id( $dek_id );
        if ( ! $dek ) {
            // Log failure without revealing the problematic DEK ID
            Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'file', ['error' => 'Could not retrieve required DEK for decryption', 'source' => $source_basename]);
            return false;
        }

        // Use file handles
        $source_handle = @fopen( $source_path, 'rb' );
        $dest_handle = @fopen( $dest_path, 'wb' );

        if ( ! $source_handle || ! $dest_handle ) {
             Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'file', ['error' => 'Could not open file handles', 'source' => $source_basename, 'dest' => $dest_basename]);
             if ($source_handle) @fclose($source_handle);
             if ($dest_handle) @fclose($dest_handle);
            return false;
        }

        // Read encrypted content - again, assumes fits in memory.
        $ciphertext_raw = fread( $source_handle, filesize( $source_path ) ?: 1 );
        fclose( $source_handle );

         if ($ciphertext_raw === false) {
             Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'file', ['error' => 'Could not read encrypted file content', 'source' => $source_basename]);
             fclose($dest_handle);
             @unlink($dest_path); // Clean up empty dest file
            return false;
        }

        // Decrypt
        $plaintext = Spudcryption_Crypto::decrypt( $ciphertext_raw, $dek, $iv, $tag );

        if ( $plaintext === false ) {
            // Log failure without revealing the DEK ID
            Spudcryption_Logger::log('decrypt_failed', $source_plugin, 'file', ['error' => 'File decryption crypto operation failed', 'source' => $source_basename]);
            fclose( $dest_handle );
            @unlink($dest_path); // Clean up failed dest file
            return false;
        }

        // Write decrypted data
        fwrite( $dest_handle, $plaintext );
        fclose( $dest_handle );

        // Log successful processing without sensitive details
        Spudcryption_Logger::log('decrypt_request_processed', $source_plugin, 'file', ['source' => $source_basename, 'dest' => $dest_basename]);
        return true;
    }
}