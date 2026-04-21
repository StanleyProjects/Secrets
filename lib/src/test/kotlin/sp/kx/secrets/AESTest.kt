package sp.kx.secrets

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

internal object AESTest {
    object GCM {
        object NoPadding {
            @Test
            fun encryptTest() {
                val expected = "foobarbaz".toByteArray(Charsets.UTF_8)
                val seed = ByteArray(32) { 32.minus(it).toByte() }
                val key = SecretKeySpec(seed, "aes")
                //
                val iv = ByteArray(12) { 12.minus(it).toByte() }
                val specs = GCMSpecs(tagSize = 128, iv = iv)
                //
                val encrypted = AES.GCM.NoPadding.encrypt(key = key, decrypted = expected, specs = specs)
                val cipher = Cipher.getInstance("aes/gcm/nopadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(specs.tagSize, specs.iv))
                val decrypted = cipher.doFinal(encrypted)
                //
                assertTrue(expected.contentEquals(decrypted))
            }

            @Test
            fun decryptTest() {
                val expected = "foobarbaz".toByteArray(Charsets.UTF_8)
                val seed = ByteArray(32) { 32.minus(it).toByte() }
                val key = SecretKeySpec(seed, "aes")
                //
                val iv = ByteArray(12) { 12.minus(it).toByte() }
                val specs = GCMSpecs(tagSize = 128, iv = iv)
                //
                val cipher = Cipher.getInstance("aes/gcm/nopadding")
                cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(specs.tagSize, specs.iv))
                val encrypted = cipher.doFinal(expected)
                val decrypted = AES.GCM.NoPadding.decrypt(key = key, encrypted = encrypted, specs = specs)
                //
                assertTrue(expected.contentEquals(decrypted))
            }
        }
    }

    object CBC {
        object PKCS5Padding {
            @Test
            fun encryptTest() {
                val expected = "foobarbaz".toByteArray(Charsets.UTF_8)
                val seed = ByteArray(32) { 32.minus(it).toByte() }
                val key = SecretKeySpec(seed, "aes")
                //
                val iv = ByteArray(16) { 16.minus(it).toByte() }
                val specs = IVSpecs(iv = iv)
                //
                val encrypted = AES.CBC.PKCS5Padding.encrypt(key = key, decrypted = expected, specs = specs)
                val cipher = Cipher.getInstance("aes/cbc/pkcs5padding")
                cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(specs.iv))
                val decrypted = cipher.doFinal(encrypted)
                //
                assertTrue(expected.contentEquals(decrypted))
            }

            @Test
            fun decryptTest() {
                val expected = "foobarbaz".toByteArray(Charsets.UTF_8)
                val seed = ByteArray(32) { 32.minus(it).toByte() }
                val key = SecretKeySpec(seed, "aes")
                //
                val iv = ByteArray(16) { 16.minus(it).toByte() }
                val specs = IVSpecs(iv = iv)
                //
                val cipher = Cipher.getInstance("aes/cbc/pkcs5padding")
                cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(specs.iv))
                val encrypted = cipher.doFinal(expected)
                val decrypted = AES.CBC.PKCS5Padding.decrypt(key = key, encrypted = encrypted, specs = specs)
                //
                assertTrue(expected.contentEquals(decrypted))
            }
        }
    }
}
