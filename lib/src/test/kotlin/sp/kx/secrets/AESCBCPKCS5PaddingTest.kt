package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

internal object AESCBCPKCS5PaddingTest {
    @Test
    fun encryptTest() {
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        for (i in 0 until 32) {
            md.update(byte++)
            val expected = md.digest().copyOf(32)
            md.update(byte++)
            val key = Keys.AES + md.digest().copyOf(32)
            md.update(byte++)
            val specs = IVSpecs(iv = md.digest().copyOf(16))
            val encrypted = Ciphers.AES.CBC.PKCS5Padding.encrypt(key = key, decrypted = expected, specs = specs)
            val cipher = Cipher.getInstance("aes/cbc/pkcs5padding")
            cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(specs.iv))
            val decrypted = cipher.doFinal(encrypted)
            assertTrue(expected.contentEquals(decrypted))
        }
    }

    @Test
    fun decryptTest() {
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        for (i in 0 until 32) {
            md.update(byte++)
            val expected = md.digest().copyOf(32)
            md.update(byte++)
            val key = Keys.AES + md.digest().copyOf(32)
            md.update(byte++)
            val specs = IVSpecs(iv = md.digest().copyOf(16))
            val cipher = Cipher.getInstance("aes/cbc/pkcs5padding")
            cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(specs.iv))
            val encrypted = cipher.doFinal(expected)
            val decrypted = Ciphers.AES.CBC.PKCS5Padding.decrypt(key = key, encrypted = encrypted, specs = specs)
            assertTrue(expected.contentEquals(decrypted))
        }
    }
}
