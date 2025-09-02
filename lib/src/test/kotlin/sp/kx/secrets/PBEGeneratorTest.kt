package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

internal class PBEGeneratorTest {
    @Test
    fun toSecretKeyTest() {
        val password = "qweasdzxc".toCharArray()
        val generator: Symmetric.Generator = Symmetric.AES.generator
        val random: SecureRandom = SecureRandom.getInstanceStrong()
        val keyLength = 256
        val salt = ByteArray(keyLength / 8)
        random.nextBytes(salt)
        val key = generator.toSecretKey(password = password, salt = salt)
        val keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val iterations = 1_048_576
        val keySpec = PBEKeySpec(password, salt, iterations, keyLength)
        val expected = keyFactory.generateSecret(keySpec).encoded
        val actual = key.encoded
        assertTrue(expected.contentEquals(actual))
        assertEquals(keyLength / 8, actual.size)
    }
}
