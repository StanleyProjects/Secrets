package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

internal object AESGCMNoPaddingTest {
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
            val specs = GCMSpecs(tagSize = 128, iv = md.digest().copyOf(12))
            val encrypted = Ciphers.AES.GCM.NoPadding.encrypt(key = key, decrypted = expected, specs = specs)
            val cipher = Cipher.getInstance("aes/gcm/nopadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(specs.tagSize, specs.iv))
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
            val specs = GCMSpecs(tagSize = 128, iv = md.digest().copyOf(12))
            val cipher = Cipher.getInstance("aes/gcm/nopadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(specs.tagSize, specs.iv))
            val encrypted = cipher.doFinal(expected)
            val decrypted = Ciphers.AES.GCM.NoPadding.decrypt(key = key, encrypted = encrypted, specs = specs)
            assertTrue(expected.contentEquals(decrypted))
        }
    }
}
