package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.MessageDigest
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

internal object PBKDF2HMACSHA256Test {
    @Test
    fun generateTest() {
        val keyFactory = SecretKeyFactory.getInstance("pbkdf2withhmacsha256")
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        for (i in 0 until 32) {
            md.update(byte++)
            val password = BigInteger(1, md.digest()).toString().toCharArray()
            md.update(byte++)
            val specs = PBKDF2Specs(
                salt = md.digest(),
                iterations = 1024,
                keySize = 256,
            )
            val keySpec = PBEKeySpec(password, specs.salt, specs.iterations, specs.keySize)
            val expected = keyFactory.generateSecret(keySpec).encoded
            val actual = Bytes.PBKDF2.HMAC.SHA256.generate(password = password, specs = specs)
            assertEquals(specs.keySize / 8, actual.size)
            assertTrue(expected.contentEquals(actual))
        }
    }
}
