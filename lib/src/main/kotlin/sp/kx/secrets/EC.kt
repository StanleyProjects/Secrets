package sp.kx.secrets

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import org.bouncycastle.jce.ECNamedCurveTable

object EC {
    fun toPublicKey(encoded: ByteArray): PublicKey {
        val kf = KeyFactory.getInstance("ec")
        return kf.generatePublic(X509EncodedKeySpec(encoded))
    }

    fun toPrivateKey(encoded: ByteArray): PrivateKey {
        val kf = KeyFactory.getInstance("ec")
        return kf.generatePrivate(PKCS8EncodedKeySpec(encoded))
    }

    class Keys internal constructor(name: String) {
        private val spec = ECNamedCurveTable.getParameterSpec(name)

        fun newKeyPair(random: SecureRandom): KeyPair {
            val kpg = KeyPairGenerator.getInstance("ec")
            kpg.initialize(ECGenParameterSpec(spec.name), random)
            return kpg.generateKeyPair()
        }

        fun getPublicKey(key: PrivateKey): PublicKey {
            if (key !is ECPrivateKey) TODO("EC:getPublicKey")
            val generator = key.params.generator
            val p = spec.curve.createPoint(generator.affineX, generator.affineY)
            val point = spec
                .curve
                .multiplier
                .multiply(p, key.s)
                .normalize()
            val w = ECPoint(point.affineXCoord.toBigInteger(), point.affineYCoord.toBigInteger())
            val kf = KeyFactory.getInstance("ec")
            return kf.generatePublic(ECPublicKeySpec(w, key.params))
        }

        fun getPrivateKey(magnitude: ByteArray): PrivateKey {
            val ap = AlgorithmParameters.getInstance("ec")
            ap.init(ECGenParameterSpec(spec.name))
            val params = ap.getParameterSpec(ECParameterSpec::class.java)
            if (magnitude.size != params.order.bitLength().plus(7).div(8)) {
                TODO("magnitude:size: ${magnitude.size} but curve:size: ${params.order.bitLength()}")
            }
            val s = BigInteger(1, magnitude)
            if (s < BigInteger.ONE || s >= params.order) TODO("s: $s but n: ${params.order}")
            val kf = KeyFactory.getInstance("ec")
            return kf.generatePrivate(ECPrivateKeySpec(s, params))
        }
    }

    val SECP256R1 = Keys(name = "secp256r1")
}
