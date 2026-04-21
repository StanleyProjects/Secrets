package sp.kx.secrets

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class SecretKeys private constructor(
    val algorithm: String,
) {
    fun toSecretKey(encoded: ByteArray): SecretKey {
        return SecretKeySpec(encoded, algorithm)
    }

    companion object {
        val AES = SecretKeys(algorithm = "aes")
    }

    object HMAC {
        val SHA512 = SecretKeys(algorithm = "hmacsha512")
    }
}
