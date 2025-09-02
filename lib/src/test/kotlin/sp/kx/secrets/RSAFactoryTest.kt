package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom

internal class RSAFactoryTest {
    @Test
    fun toPublicKeyTest() {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048, SecureRandom.getInstanceStrong())
        val keyPair = generator.generateKeyPair()
        val factory: Asymmetric.Factory = RSAFactory
        val actual = factory.toPublicKey(encoded = keyPair.public.encoded)
        assertTrue(keyPair.public.encoded.contentEquals(actual.encoded))
    }

    @Test
    fun toPrivateKeyTest() {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048, SecureRandom.getInstanceStrong())
        val keyPair = generator.generateKeyPair()
        val factory: Asymmetric.Factory = RSAFactory
        val actual = factory.toPrivateKey(encoded = keyPair.private.encoded)
        assertTrue(keyPair.private.encoded.contentEquals(actual.encoded))
    }
}
