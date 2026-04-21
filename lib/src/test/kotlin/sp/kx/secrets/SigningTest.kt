package sp.kx.secrets

import java.security.SecureRandom
import java.security.Signature
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

object SigningTest {
    object SHA256ECDSA {
        @Test
        fun signTest() {
            val seed = ByteArray(32) { 32.minus(it).toByte() }
            val random = SecureRandom(seed)
            val keyPair = EC.SECP256R1.newKeyPair(random = random)
            val signee = "foobarbaz".toByteArray(Charsets.UTF_8)
            val signature = SHA256.ECDSA.sign(key = keyPair.private, signee = signee)
            val sig = Signature.getInstance("sha256withecdsa")
            sig.initVerify(keyPair.public)
            sig.update(signee)
            assertTrue(sig.verify(signature))
        }

        @Test
        fun verifyTest() {
            val seed = ByteArray(32) { 32.minus(it).toByte() }
            val random = SecureRandom(seed)
            val keyPair = EC.SECP256R1.newKeyPair(random = random)
            val signee = "foobarbaz".toByteArray(Charsets.UTF_8)
            val sig = Signature.getInstance("sha256withecdsa")
            sig.initSign(keyPair.private)
            sig.update(signee)
            val signature = sig.sign()
            SHA256.ECDSA.verify(key = keyPair.public, signee = signee, signature = signature)
        }
    }

    object SHA256RSA {
        @Test
        fun signTest() {
            val seed = ByteArray(32) { 32.minus(it).toByte() }
            val random = SecureRandom(seed)
            val keyPair = RSA.newKeyPair(random = random, keySize = 4096)
            val signee = "foobarbaz".toByteArray(Charsets.UTF_8)
            val signature = SHA256.RSA.sign(key = keyPair.private, signee = signee)
            val sig = Signature.getInstance("sha256withrsa")
            sig.initVerify(keyPair.public)
            sig.update(signee)
            assertTrue(sig.verify(signature))
        }

        @Test
        fun verifyTest() {
            val seed = ByteArray(32) { 32.minus(it).toByte() }
            val random = SecureRandom(seed)
            val keyPair = RSA.newKeyPair(random = random, keySize = 4096)
            val signee = "foobarbaz".toByteArray(Charsets.UTF_8)
            val sig = Signature.getInstance("sha256withrsa")
            sig.initSign(keyPair.private)
            sig.update(signee)
            val signature = sig.sign()
            SHA256.RSA.verify(key = keyPair.public, signee = signee, signature = signature)
        }
    }
}
