package sp.kx.secrets

import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.Cipher
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

internal object RSACiphersTest {
    object ECB {
        class PKCS1Padding {
            @Test
            fun encryptTest() {
                val expected = "foobarbaz".toByteArray(Charsets.UTF_8)
                val seed = ByteArray(32) { 32.minus(it).toByte() }
                val random = SecureRandom(seed)
                //
                val kpg = KeyPairGenerator.getInstance("rsa")
                kpg.initialize(4_096, random)
                val keyPair = kpg.generateKeyPair()
                //
                val encrypted = RSACiphers.ECB.PKCS1Padding.encrypt(keyPair.public, expected)
                val cipher = Cipher.getInstance("rsa/ecb/pkcs1padding")
                cipher.init(Cipher.DECRYPT_MODE, keyPair.private)
                val decrypted = cipher.doFinal(encrypted)
                //
                assertTrue(expected.contentEquals(decrypted))
            }

            @Test
            fun decryptTest() {
                val expected = "foobarbaz".toByteArray(Charsets.UTF_8)
                val seed = ByteArray(32) { 32.minus(it).toByte() }
                val random = SecureRandom(seed)
                //
                val kpg = KeyPairGenerator.getInstance("rsa")
                kpg.initialize(4_096, random)
                val keyPair = kpg.generateKeyPair()
                //
                val cipher = Cipher.getInstance("rsa/ecb/pkcs1padding")
                cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
                val encrypted = cipher.doFinal(expected)
                val decrypted = RSACiphers.ECB.PKCS1Padding.decrypt(keyPair.private, encrypted)
                //
                assertTrue(expected.contentEquals(decrypted))
            }
        }
    }
}
