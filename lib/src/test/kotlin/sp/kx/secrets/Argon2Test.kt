package sp.kx.secrets

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.MessageDigest

internal object Argon2Test {
    @Test
    fun generateTest() {
        val generator = Argon2BytesGenerator()
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        for (i in 0 until 32) {
            md.update(byte++)
            val password = BigInteger(1, md.digest()).toString().toCharArray()
            md.update(byte++)
            val specs = Argon2Specs(
                type = Argon2Parameters.ARGON2_id,
                version = Argon2Parameters.ARGON2_VERSION_13,
                salt = md.digest().copyOf(32),
                iterations = 2,
                memorySize = 1024,
                parallelism = 1,
                keySize = 32,
            )
            val params = Argon2Parameters.Builder(specs.type)
                .withVersion(specs.version)
                .withSalt(specs.salt)
                .withIterations(specs.iterations)
                .withMemoryAsKB(specs.memorySize)
                .withParallelism(specs.parallelism)
                .build()
            generator.init(params)
            val expected = ByteArray(specs.keySize)
            generator.generateBytes(password, expected)
            val actual = Bytes.Argon2.generate(password = password, specs = specs)
            assertEquals(specs.keySize, actual.size)
            assertTrue(expected.contentEquals(actual))
        }
    }
}
