package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom

internal object RSATest {
    @Test
    fun toPublicKeyTest() {
        val kpg = KeyPairGenerator.getInstance("rsa")
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        md.update(byte++)
        kpg.initialize(4096, SecureRandom(md.digest()))
        val keyPair = kpg.generateKeyPair()
        val expected = keyPair.public.encoded
        assertTrue(expected.contentEquals(AsyKeys.RSA.toPublicKey(keyPair.public.encoded).encoded))
        assertTrue(expected.contentEquals(AsyKeys.RSA.plus(keyPair.public.encoded).encoded))
    }

    @Test
    fun toPrivateKeyTest() {
        val kpg = KeyPairGenerator.getInstance("rsa")
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        md.update(byte++)
        kpg.initialize(4096, SecureRandom(md.digest()))
        val keyPair = kpg.generateKeyPair()
        val expected = keyPair.private.encoded
        assertTrue(expected.contentEquals(AsyKeys.RSA.toPrivateKey(keyPair.private.encoded).encoded))
        assertTrue(expected.contentEquals(AsyKeys.RSA.minus(keyPair.private.encoded).encoded))
    }

    @Test
    fun getPublicKeyTest() {
        val kpg = KeyPairGenerator.getInstance("rsa")
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        md.update(byte++)
        kpg.initialize(4096, SecureRandom(md.digest()))
        val keyPair = kpg.generateKeyPair()
        val expected = keyPair.public.encoded
        val actual = AsyKeys.RSA.getPublicKey(keyPair.private).encoded
        assertTrue(expected.contentEquals(actual))
    }
}
