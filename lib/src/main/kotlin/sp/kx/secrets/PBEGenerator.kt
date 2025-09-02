package sp.kx.secrets

import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

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
