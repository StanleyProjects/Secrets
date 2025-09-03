package sp.kx.secrets

import javax.crypto.SecretKey

/**
 * An abstraction for working with symmetric keys.
 *
 * @author [Stanley Wintergreen](https://github.com/kepocnhh)
 * @since 0.1.0
 */
class Symmetric(
    val factory: Factory,
    val enc: Encryption,
    val generator: Generator,
) {
    /**
     * An abstraction for decoding or creating symmetric keys.
     *
     * @author [Stanley Wintergreen](https://github.com/kepocnhh)
     * @since 0.1.0
     */
    interface Factory {
        /**
         * Decoding [SecretKey].
         *
         * @author [Stanley Wintergreen](https://github.com/kepocnhh)
         * @since 0.1.0
         */
        fun toSecretKey(encoded: ByteArray): SecretKey

        /**
         * Creates new [SecretKey].
         *
         * @author [Stanley Wintergreen](https://github.com/kepocnhh)
         * @since 0.1.0
         */
        fun newSecretKey(): SecretKey
    }

    /**
     * An abstraction for encryption using symmetric keys.
     *
     * @author [Stanley Wintergreen](https://github.com/kepocnhh)
     * @since 0.1.0
     */
    interface Encryption {
        /**
         * Encrypt [decrypted] message using [key] and [iv].
         *
         * Usage:
         * ```
         * val key: SecretKey = ...
         * val decrypted: ByteArray = ...
         * val enc: Symmetric.Encryption = ...
         * val iv: ByteArray = ...
         * val encrypted = enc.encrypt(key, decrypted, iv)
         * File("foo.enc").writeBytes(encrypted)
         * File("foo.iv").writeBytes(iv)
         * ```
         * @author [Stanley Wintergreen](https://github.com/kepocnhh)
         * @since 0.1.0
         */
        fun encrypt(key: SecretKey, decrypted: ByteArray, iv: ByteArray): ByteArray

        /**
         * Decrypt [encrypted] message using [key] and [iv].
         *
         * Usage:
         * ```
         * val key: SecretKey = ...
         * val encrypted = File("foo.enc").readBytes()
         * val iv = File("foo.iv").readBytes()
         * val enc: Symmetric.Encryption = ...
         * val decrypted = enc.decrypt(key, decrypted, iv)
         * ```
         * @author [Stanley Wintergreen](https://github.com/kepocnhh)
         * @since 0.1.0
         */
        fun decrypt(key: SecretKey, encrypted: ByteArray, iv: ByteArray): ByteArray
    }

    /**
     * An abstraction for generating symmetric keys from a password.
     *
     * @author [Stanley Wintergreen](https://github.com/kepocnhh)
     * @since 0.1.0
     */
    interface Generator {
        /**
         * Creates new [SecretKey] using [password] and [salt].
         *
         * Usage:
         * ```
         * val generator: Symmetric.Generator = ...
         * val password: CharArray = ...
         * val salt = File("foo.enc").readBytes()
         * val key = generator.toSecretKey(password, salt)
         * ```
         * @author [Stanley Wintergreen](https://github.com/kepocnhh)
         * @since 0.1.0
         */
        fun toSecretKey(password: CharArray, salt: ByteArray): SecretKey
    }

    companion object {
        val AES = Symmetric(
            factory = AESFactory,
            enc = AESCBCEncryption(paddings = "PKCS5Padding"),
            generator = PBEGenerator(
                algorithm = "PBKDF2WithHmacSHA256",
                iterations = 1_048_576,
                keyLength = 256,
            ),
        )
    }
}
