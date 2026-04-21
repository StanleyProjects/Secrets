package sp.kx.secrets

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import org.bouncycastle.jce.ECNamedCurveTable

abstract class KeyPairs private constructor(
    val algorithm: String,
) {
    abstract fun newKeyPair(random: SecureRandom): KeyPair
    abstract fun getPublicKey(key: PrivateKey): PublicKey

    fun toPublicKey(encoded: ByteArray): PublicKey {
        val kf = KeyFactory.getInstance(algorithm)
        return kf.generatePublic(X509EncodedKeySpec(encoded))
    }

    fun toPrivateKey(encoded: ByteArray): PrivateKey {
        val kf = KeyFactory.getInstance(algorithm)
        return kf.generatePrivate(PKCS8EncodedKeySpec(encoded))
    }

    object EC {
        object SECP256R1 : KeyPairs(algorithm = "ec") {
            private val spec = ECNamedCurveTable.getParameterSpec("secp256r1")

            override fun newKeyPair(random: SecureRandom): KeyPair {
                val kpg = KeyPairGenerator.getInstance(algorithm)
                kpg.initialize(ECGenParameterSpec(spec.name), random)
                return kpg.generateKeyPair()
            }

            override fun getPublicKey(key: PrivateKey): PublicKey {
                if (key !is ECPrivateKey) TODO()
                val generator = key.params.generator
                val p = spec.curve.createPoint(generator.affineX, generator.affineY)
                val point = spec
                    .curve
                    .multiplier
                    .multiply(p, key.s)
                    .normalize()
                val w = ECPoint(point.affineXCoord.toBigInteger(), point.affineYCoord.toBigInteger())
                val kf = KeyFactory.getInstance(algorithm)
                return kf.generatePublic(ECPublicKeySpec(w, key.params))
            }
        }
    }
}
