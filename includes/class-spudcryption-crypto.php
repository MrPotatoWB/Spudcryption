<?php
// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

/**
 * Spudcryption_Crypto Class
 *
 * Handles the low-level cryptographic operations using AES-256-GCM.
 */
class Spudcryption_Crypto {

    private const CIPHER_ALGO = 'aes-256-gcm';
    private const TAG_LENGTH = 16; // GCM tag length

    /**
     * Check if the required cipher method is available.
     *
     * @return bool
     */
    public static function is_supported() {
        return extension_loaded('openssl') && in_array(self::CIPHER_ALGO, openssl_get_cipher_methods());
    }

    /**
     * Encrypt data using AES-256-GCM.
     *
     * @param string $plaintext The data to encrypt.
     * @param string $key       The encryption key (binary).
     * @param string &$iv       Reference to store the generated IV (binary).
     * @param string &$tag      Reference to store the generated authentication tag (binary).
     * @return string|false Ciphertext (binary) or false on failure.
     */
    public static function encrypt( $plaintext, $key, &$iv, &$tag ) {
        if ( ! self::is_supported() ) {
            Spudcryption_Logger::log('crypto_error', 'spudcryption_crypto', 'encrypt', ['error' => 'AES-256-GCM not supported']);
            return false;
        }

        $iv_len = openssl_cipher_iv_length( self::CIPHER_ALGO );
        if ($iv_len === false) {
             Spudcryption_Logger::log('crypto_error', 'spudcryption_crypto', 'encrypt', ['error' => 'Could not get IV length']);
            return false;
        }
        $iv = openssl_random_pseudo_bytes( $iv_len );
        if ($iv === false) {
             Spudcryption_Logger::log('crypto_error', 'spudcryption_crypto', 'encrypt', ['error' => 'Could not generate IV']);
            return false;
        }

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER_ALGO,
            $key,
            OPENSSL_RAW_DATA, // Use OPENSSL_RAW_DATA for binary output
            $iv,
            $tag, // This will be filled by openssl_encrypt with GCM
            '',    // No AAD (Additional Associated Data) in this basic example
            self::TAG_LENGTH
        );

         if ($ciphertext === false) {
             Spudcryption_Logger::log('crypto_error', 'spudcryption_crypto', 'encrypt', ['error' => 'openssl_encrypt failed', 'openssl_error' => openssl_error_string()]);
            return false;
        }

        return $ciphertext;
    }

    /**
     * Decrypt data using AES-256-GCM.
     * Verifies the authenticity tag.
     *
     * @param string $ciphertext The ciphertext (binary).
     * @param string $key        The decryption key (binary).
     * @param string $iv         The Initialization Vector used for encryption (binary).
     * @param string $tag        The authentication tag (binary).
     * @return string|false Plaintext data (binary) or false on failure (e.g., tag mismatch).
     */
    public static function decrypt( $ciphertext, $key, $iv, $tag ) {
         if ( ! self::is_supported() ) {
            Spudcryption_Logger::log('crypto_error', 'spudcryption_crypto', 'decrypt', ['error' => 'AES-256-GCM not supported']);
            return false;
        }

        $iv_len = openssl_cipher_iv_length( self::CIPHER_ALGO );
         if ($iv_len === false || strlen($iv) !== $iv_len) {
             Spudcryption_Logger::log('crypto_error', 'spudcryption_crypto', 'decrypt', ['error' => 'Invalid IV length']);
            return false;
         }

         if (strlen($tag) !== self::TAG_LENGTH) {
              Spudcryption_Logger::log('crypto_error', 'spudcryption_crypto', 'decrypt', ['error' => 'Invalid tag length']);
             return false;
         }

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER_ALGO,
            $key,
            OPENSSL_RAW_DATA, // Use OPENSSL_RAW_DATA as input was raw
            $iv,
            $tag, // Provide the tag for verification with GCM
            ''     // No AAD
        );

        if ( $plaintext === false ) {
            // Decryption failed - could be bad key, tampered data (tag mismatch), etc.
            Spudcryption_Logger::log('crypto_error', 'spudcryption_crypto', 'decrypt', ['error' => 'openssl_decrypt failed - likely tag mismatch or wrong key', 'openssl_error' => openssl_error_string()]);
            return false;
        }

        return $plaintext;
    }

     /**
     * Generate a cryptographically secure random key.
     *
     * @param int $length Length of the key in bytes (e.g., 32 for 256 bits).
     * @return string|false The random key (binary) or false on failure.
     */
    public static function generate_key( $length = 32 ) {
        return openssl_random_pseudo_bytes( $length );
    }
}