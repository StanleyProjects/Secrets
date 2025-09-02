package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.Cipher

internal class RSAECBEncryptionTest {
    @Test
    fun encryptTest() {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048, SecureRandom.getInstanceStrong())
        val keyPair = generator.generateKeyPair()
        val decrypted = "foobarbaz".toByteArray()
        val paddings = "PKCS1Padding"
        val encryption: Asymmetric.Encryption = Asymmetric.RSA.enc
        val actual = encryption.encrypt(key = keyPair.public, decrypted = decrypted)
        val cipher = Cipher.getInstance("RSA/ECB/$paddings")
        cipher.init(Cipher.DECRYPT_MODE, keyPair.private)
        assertTrue(cipher.doFinal(actual).contentEquals(decrypted))
    }

    @Test
    fun decryptTest() {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048, SecureRandom.getInstanceStrong())
        val keyPair = generator.generateKeyPair()
        val decrypted = "foobarbaz".toByteArray()
        val paddings = "PKCS1Padding"
        val cipher = Cipher.getInstance("RSA/ECB/$paddings")
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
        val encrypted = cipher.doFinal(decrypted)
        val encryption: Asymmetric.Encryption = Asymmetric.RSA.enc
        val actual = encryption.decrypt(key = keyPair.private, encrypted = encrypted)
        assertTrue(decrypted.contentEquals(actual))
    }
}
