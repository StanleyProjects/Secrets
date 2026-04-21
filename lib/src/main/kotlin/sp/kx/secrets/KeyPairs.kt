package sp.kx.secrets

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

abstract class KeyPairs private constructor(
    val algorithm: String,
) {
    abstract fun newKeyPair(random: SecureRandom): KeyPair

    fun toPublicKey(encoded: ByteArray): PublicKey {
        val kf = KeyFactory.getInstance(algorithm)
        return kf.generatePublic(X509EncodedKeySpec(encoded))
    }

    fun toPrivateKey(encoded: ByteArray): PrivateKey {
        val kf = KeyFactory.getInstance(algorithm)
        return kf.generatePrivate(PKCS8EncodedKeySpec(encoded))
    }

    object RSA4096 : KeyPairs(algorithm = "rsa") {
        override fun newKeyPair(random: SecureRandom): KeyPair {
            val kpg = KeyPairGenerator.getInstance(algorithm)
            kpg.initialize(4096, random)
            return kpg.generateKeyPair()
        }
    }

    object EC {
        object SECP256R1 : KeyPairs(algorithm = "ec") {
            private val params = ECGenParameterSpec("secp256r1")

            override fun newKeyPair(random: SecureRandom): KeyPair {
                val kpg = KeyPairGenerator.getInstance(algorithm)
                kpg.initialize(params, random)
                return kpg.generateKeyPair()
            }
        }
    }
}
