package sp.kx.secrets

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class Keys private constructor(val algorithm: String) {
    fun toSecretKey(encoded: ByteArray): SecretKey {
        return SecretKeySpec(encoded, algorithm)
    }

    companion object {
        val AES = Keys(algorithm = "aes")
    }

    object HMAC {
        val SHA512 = Keys(algorithm = "hmacsha512")
    }
}
