package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object AESGCMNoPaddingTest {
    @Test
    fun encryptTest() {
        val expected = "foo bar baz".toByteArray(Charsets.UTF_8)
        val key = SecretKeySpec(ByteArray(32) { (32 - it).toByte() }, "aes")
        val iv = ByteArray(12) { (12 - it).toByte() }
        val specs = GCMSpecs(tagSize = 128, iv = iv)
        val encrypted = Ciphers.AES.GCM.NoPadding.encrypt(key = key, decrypted = expected, specs = specs)
        val cipher = Cipher.getInstance("aes/gcm/nopadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(specs.tagSize, specs.iv))
        val decrypted = cipher.doFinal(encrypted)
        assertTrue(expected.contentEquals(decrypted))
    }

    @Test
    fun decryptTest() {
        val expected = "foo bar baz".toByteArray(Charsets.UTF_8)
        val key = SecretKeySpec(ByteArray(32) { (32 - it).toByte() }, "aes")
        val iv = ByteArray(12) { (12 - it).toByte() }
        val specs = GCMSpecs(tagSize = 128, iv = iv)
        val cipher = Cipher.getInstance("aes/gcm/nopadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(specs.tagSize, specs.iv))
        val encrypted = cipher.doFinal(expected)
        val decrypted = Ciphers.AES.GCM.NoPadding.decrypt(key = key, encrypted = encrypted, specs = specs)
        assertTrue(expected.contentEquals(decrypted))
    }
}
