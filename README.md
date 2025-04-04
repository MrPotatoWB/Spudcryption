=== Spudcryption ===
Contributors: Mr. Potato
Tags: encryption, security, envelope encryption, aes, gcm
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 1.0.0
Requires PHP: 7.2
Requires Extensions: openssl
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Provides envelope encryption using a KEK in wp-config.php and rotating DEKs for data and files.

== Description ==

Spudcryption implements envelope encryption for WordPress data (database entries) and files. It uses:

*   A **Key Encryption Key (KEK)** that YOU define in your `wp-config.php` file. This key protects the Data Encryption Keys.
*   Automatically rotating **Data Encryption Keys (DEKs)** used to encrypt the actual data. This limits the exposure if a single DEK were compromised.
*   **AES-256-GCM** authenticated encryption for confidentiality and integrity.

It provides simple functions for other plugins to encrypt and decrypt data with minimal changes to their database access logic. An admin page allows configuration of DEK rotation frequency and viewing activity logs.

**SECURITY IS PARAMOUNT:** The strength of this plugin depends entirely on the strength and secrecy of your KEK defined in `wp-config.php`. Use a strong, random key!

== Installation ==

1.  Upload the `spudcryption` folder to the `/wp-content/plugins/` directory.
2.  **CRITICAL:** Define your Key Encryption Key (KEK) in your `wp-config.php` file *before* activating. Add this line, replacing the placeholder with a strong random key (e.g., 64+ hex characters):
    `define( 'SPUDCRYPTION_KEK', 'YOUR_VERY_STRONG_RANDOM_HEX_KEY_GOES_HERE' );`
    You can generate a key using tools like `openssl rand -hex 32` (for 64 hex chars).
3.  Activate the plugin through the 'Plugins' menu in WordPress.
4.  Go to Settings -> Spudcryption to configure the DEK rotation frequency.

== Usage for Developers ==

To encrypt data before saving to the database (e.g., an option):

`$sensitive_data = 'This is my secret!';`
`$encrypted_data = spudcryption_encrypt_string( $sensitive_data, 'my-plugin-slug' );`
`update_option( 'my_sensitive_option', $encrypted_data );`

To decrypt data after retrieving it:

`$encrypted_data = get_option( 'my_sensitive_option' );`
`$sensitive_data = spudcryption_decrypt_string( $encrypted_data, 'my-plugin-slug' );`
`// Use $sensitive_data`

For files:

`$source_file = '/path/to/original/secret.txt';`
`$encrypted_file = '/path/to/encrypted/secret.txt.enc';`
`if ( spudcryption_encrypt_file( $source_file, $encrypted_file, 'my-plugin-slug' ) ) {`
`  // Encryption successful, maybe delete original?`
`}`

`$encrypted_file = '/path/to/encrypted/secret.txt.enc';`
`$decrypted_file = '/path/to/decrypted/secret.txt';`
`if ( spudcryption_decrypt_file( $encrypted_file, $decrypted_file, 'my-plugin-slug' ) ) {`
`  // Decryption successful`
`}`

Remember that file encryption creates a `.meta` file alongside the encrypted file (e.g., `secret.txt.enc.meta`). Both are needed for decryption.

== Frequently Asked Questions ==

= Does this encrypt existing data? =

No. You need to implement a migration process to encrypt data that was stored before Spudcryption was used.

= What happens if I lose my KEK? =

**ALL ENCRYPTED DATA WILL BE PERMANENTLY UNRECOVERABLE.** Back up your `wp-config.php` securely.

= What happens if I change my KEK? =

Data encrypted with the *old* KEK will become undecryptable unless you have a backup of the old KEK and implement logic to handle multiple KEKs (which this basic plugin does not).

= Is this secure? =

It implements standard envelope encryption practices using AES-GCM. However, security depends on the KEK strength/secrecy, server security, and correct implementation in calling plugins. Review and test thoroughly.

== Changelog ==

= 1.0.0 =
* Initial release by Mr. Potato.

== Upgrade Notice ==

= 1.0.0 =
Initial release. Ensure your KEK is defined in wp-config.php before activating.
