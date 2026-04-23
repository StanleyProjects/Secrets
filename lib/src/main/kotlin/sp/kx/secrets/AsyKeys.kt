package sp.kx.secrets

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec

abstract class AsyKeys private constructor(val algorithm: String) {
    fun toPublicKey(encoded: ByteArray): PublicKey {
        val kf = KeyFactory.getInstance(algorithm)
        return kf.generatePublic(X509EncodedKeySpec(encoded))
    }

    fun toPrivateKey(encoded: ByteArray): PrivateKey {
        val kf = KeyFactory.getInstance(algorithm)
        return kf.generatePrivate(PKCS8EncodedKeySpec(encoded))
    }

    object RSA : AsyKeys(algorithm = "rsa") {
        fun getPublicKey(key: PrivateKey): PublicKey {
            if (key !is RSAPrivateCrtKey) TODO("AsyKeys:RSA:getPublicKey")
            val kf = KeyFactory.getInstance("rsa")
            val spec = RSAPublicKeySpec(key.modulus, key.publicExponent)
            return kf.generatePublic(spec)
        }

        fun newKeyPair(random: SecureRandom, keySize: Int): KeyPair {
            val kpg = KeyPairGenerator.getInstance("rsa")
            kpg.initialize(keySize, random)
            return kpg.generateKeyPair()
        }
    }

    object EC : AsyKeys(algorithm = "ec") {
        val SECP256R1 = ECKeys(name = "secp256r1")
    }
}
