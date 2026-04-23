package sp.kx.secrets

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class AsyKeys private constructor(val algorithm: String) {
    fun toPublicKey(encoded: ByteArray): PublicKey {
        val kf = KeyFactory.getInstance(algorithm)
        return kf.generatePublic(X509EncodedKeySpec(encoded))
    }

    fun toPrivateKey(encoded: ByteArray): PrivateKey {
        val kf = KeyFactory.getInstance(algorithm)
        return kf.generatePrivate(PKCS8EncodedKeySpec(encoded))
    }

    companion object {
        val RSA = AsyKeys(algorithm = "rsa")
        val EC = AsyKeys(algorithm = "ec")
    }
}