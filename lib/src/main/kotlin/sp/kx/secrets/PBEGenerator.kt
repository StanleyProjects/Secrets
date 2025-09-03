package sp.kx.secrets

import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Implementation for generating symmetric keys from a password.
 *
 * @author [Stanley Wintergreen](https://github.com/kepocnhh)
 * @since 0.1.0
 */
class PBEGenerator(
    private val algorithm: String,
    private val iterations: Int,
    private val keyLength: Int,
) : Symmetric.Generator {
    override fun toSecretKey(password: CharArray, salt: ByteArray): SecretKey {
        val keyFactory = SecretKeyFactory.getInstance(algorithm)
        val keySpec = PBEKeySpec(password, salt, iterations, keyLength)
        return keyFactory.generateSecret(keySpec)
    }
}
