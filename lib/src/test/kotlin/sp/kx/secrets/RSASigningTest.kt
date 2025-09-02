package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature

internal class RSASigningTest {
    @Test
    fun signTest() {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048, SecureRandom.getInstanceStrong())
        val keyPair = generator.generateKeyPair()
        val decrypted = "foobarbaz".toByteArray()
        val algorithm = "SHA256withRSA"
        val signing: Asymmetric.Signing = Asymmetric.RSA.signing
        val actual = signing.sign(key = keyPair.private, encoded = decrypted)
        val sig = Signature.getInstance(algorithm)
        sig.initVerify(keyPair.public)
        sig.update(decrypted)
        assertTrue(sig.verify(actual))
    }

    @Test
    fun verifyTest() {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048, SecureRandom.getInstanceStrong())
        val keyPair = generator.generateKeyPair()
        val decrypted = "foobarbaz".toByteArray()
        val algorithm = "SHA256withRSA"
        val sig = Signature.getInstance(algorithm)
        sig.initSign(keyPair.private)
        sig.update(decrypted)
        val signature = sig.sign()
        val signing: Asymmetric.Signing = Asymmetric.RSA.signing
        assertTrue(signing.verify(key = keyPair.public, encoded = decrypted, signature = signature))
        val other = "qwe123asd".toByteArray()
        check(!decrypted.contentEquals(other))
        assertFalse(signing.verify(key = keyPair.public, encoded = other, signature = signature))
    }
}
