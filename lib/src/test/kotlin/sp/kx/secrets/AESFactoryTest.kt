package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec

internal class AESFactoryTest {
    @Test
    fun toSecretKeyTest() {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(256, SecureRandom.getInstanceStrong())
        val key = generator.generateKey()
        val factory: Symmetric.Factory = Symmetric.AES.factory
        val actual = factory.toSecretKey(encoded = key.encoded)
        assertTrue(key.encoded.contentEquals(actual.encoded))
    }

    @Test
    fun newSecretKeyTest() {
        val factory: Symmetric.Factory = Symmetric.AES.factory
        val key = factory.newSecretKey()
        val random: SecureRandom = SecureRandom.getInstanceStrong()
        val decrypted = "foobarbaz".toByteArray()
        val paddings = "PKCS5Padding"
        val iv = ByteArray(16)
        random.nextBytes(iv)
        val cipher = Cipher.getInstance("AES/CBC/$paddings")
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
        val encrypted = cipher.doFinal(decrypted)
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
        assertTrue(cipher.doFinal(encrypted).contentEquals(decrypted))
    }
}
