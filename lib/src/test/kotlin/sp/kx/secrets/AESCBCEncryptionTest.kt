package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec

internal class AESCBCEncryptionTest {
    @Test
    fun encryptTest() {
        val generator = KeyGenerator.getInstance("AES")
        val random: SecureRandom = SecureRandom.getInstanceStrong()
        generator.init(256, random)
        val key = generator.generateKey()
        val decrypted = "foobarbaz".toByteArray()
        val paddings = "PKCS5Padding"
        val enc: Symmetric.Encryption = Symmetric.AES.enc
        val iv = ByteArray(16)
        random.nextBytes(iv)
        val actual = enc.encrypt(key = key, decrypted = decrypted, iv = iv)
        val cipher = Cipher.getInstance("AES/CBC/$paddings")
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
        assertTrue(cipher.doFinal(actual).contentEquals(decrypted))
    }

    @Test
    fun decryptTest() {
        val generator = KeyGenerator.getInstance("AES")
        val random: SecureRandom = SecureRandom.getInstanceStrong()
        generator.init(256, random)
        val key = generator.generateKey()
        val decrypted = "foobarbaz".toByteArray()
        val paddings = "PKCS5Padding"
        val cipher = Cipher.getInstance("AES/CBC/$paddings")
        val iv = ByteArray(16)
        random.nextBytes(iv)
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
        val encrypted = cipher.doFinal(decrypted)
        val enc: Symmetric.Encryption = Symmetric.AES.enc
        val actual = enc.decrypt(key = key, encrypted = encrypted, iv = iv)
        assertTrue(decrypted.contentEquals(actual))
    }
}
