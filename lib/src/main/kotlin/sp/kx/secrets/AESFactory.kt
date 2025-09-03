package sp.kx.secrets

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Implementation for decoding or creating AEC keys.
 *
 * @author [Stanley Wintergreen](https://github.com/kepocnhh)
 * @since 0.1.0
 */
object AESFactory : Symmetric.Factory {
    override fun toSecretKey(encoded: ByteArray): SecretKey {
        return SecretKeySpec(encoded, "AES")
    }

    override fun newSecretKey(): SecretKey {
        return KeyGenerator.getInstance("AES").generateKey()
    }
}
