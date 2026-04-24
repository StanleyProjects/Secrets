package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher

internal object RSAECBPKCS1PaddingTest {
    @Test
    fun encryptTest() {
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        md.update(byte++)
        val random = SecureRandom(md.digest().copyOf(32))
        val keyPair = AsyKeys.RSA.newKeyPair(random = random, keySize = 4096)
        md.update(byte++)
        val expected = md.digest().copyOf(32)
        val encrypted = AsyCiphers.RSA.ECB.PKCS1Padding.encrypt(key = keyPair.public, decrypted = expected)
        val cipher = Cipher.getInstance("rsa/ecb/pkcs1padding")
        cipher.init(Cipher.DECRYPT_MODE, keyPair.private)
        val decrypted = cipher.doFinal(encrypted)
        assertTrue(expected.contentEquals(decrypted))
    }

    @Test
    fun decryptTest() {
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        md.update(byte++)
        val random = SecureRandom(md.digest().copyOf(32))
        val keyPair = AsyKeys.RSA.newKeyPair(random = random, keySize = 4096)
        md.update(byte++)
        val expected = md.digest().copyOf(32)
        val cipher = Cipher.getInstance("rsa/ecb/pkcs1padding")
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
        val encrypted = cipher.doFinal(expected)
        val decrypted = AsyCiphers.RSA.ECB.PKCS1Padding.decrypt(key = keyPair.private, encrypted = encrypted)
        assertTrue(expected.contentEquals(decrypted))
    }
}
