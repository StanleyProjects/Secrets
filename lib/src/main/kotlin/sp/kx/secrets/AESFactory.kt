package sp.kx.secrets

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

object AESFactory : Symmetric.Factory {
    override fun toSecretKey(encoded: ByteArray): SecretKey {
        return SecretKeySpec(encoded, "AES")
    }

    override fun newSecretKey(): SecretKey {
        return KeyGenerator.getInstance("AES").generateKey()
    }
}
