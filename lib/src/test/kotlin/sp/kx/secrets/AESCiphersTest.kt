package sp.kx.secrets

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

internal class AESCiphersTest {
    @Test
    fun encryptTest() {
        val generator = KeyGenerator.getInstance("AES")
        val seed = ByteArray(32) { 32.minus(it).toByte() }
        val random = SecureRandom(seed)
        generator.init(256, random)
        val key = generator.generateKey()
        //
        val iv = ByteArray(12) { 12.minus(it).toByte() }
        val specs = GCMSpecs(tagSize = 128, iv = iv)
        //
        val decrypted = "foobarbaz".toByteArray(Charsets.UTF_8)
        val encrypted = AESCiphers.GCM.NoPadding.encrypt(key = key, decrypted = decrypted, specs = specs)
        //
        val cipher = Cipher.getInstance("aes/gcm/nopadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(specs.tagSize, specs.iv))
        assertTrue(cipher.doFinal(encrypted).contentEquals(decrypted))
    }
}
