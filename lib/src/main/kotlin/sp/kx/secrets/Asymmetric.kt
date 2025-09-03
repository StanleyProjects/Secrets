package sp.kx.secrets

import java.security.PrivateKey
import java.security.PublicKey

/**
 * An abstraction for working with asymmetric keys.
 *
 * @author [Stanley Wintergreen](https://github.com/kepocnhh)
 * @since 0.1.0
 */
class Asymmetric(
    val factory: Factory,
    val enc: Encryption,
    val signing: Signing,
) {
    /**
     * An abstraction for decoding asymmetric keys.
     *
     * @author [Stanley Wintergreen](https://github.com/kepocnhh)
     * @since 0.1.0
     */
    interface Factory {
        fun toPublicKey(encoded: ByteArray): PublicKey
        fun toPrivateKey(encoded: ByteArray): PrivateKey
    }

    /**
     * An abstraction for encryption using asymmetric keys.
     *
     * @author [Stanley Wintergreen](https://github.com/kepocnhh)
     * @since 0.1.0
     */
    interface Encryption {
        fun encrypt(key: PublicKey, decrypted: ByteArray): ByteArray
        fun decrypt(key: PrivateKey, encrypted: ByteArray): ByteArray
    }

    /**
     * An abstraction for signing asymmetric keys.
     *
     * @author [Stanley Wintergreen](https://github.com/kepocnhh)
     * @since 0.1.0
     */
    interface Signing {
        fun sign(key: PrivateKey, encoded: ByteArray): ByteArray
        fun verify(key: PublicKey, encoded: ByteArray, signature: ByteArray): Boolean
    }

    companion object {
        val RSA = Asymmetric(
            factory = RSAFactory,
            enc = RSAECBEncryption(paddings = "PKCS1Padding"),
            signing = RSASigning(algorithm = "SHA256withRSA"),
        )
    }
}
