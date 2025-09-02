package sp.kx.secrets

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

object AESFactory : Symmetric.Factory {
    override fun toSecretKey(encoded: ByteArray): SecretKey {
        return SecretKeySpec(encoded, "AES")
    }
}
