package sp.kx.secrets

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

internal object BytesGeneratorTest {
    object Argon2 {
        @Test
        fun generateTest() {
            val password = "foobarbaz".toCharArray()
            val salt = ByteArray(32) { 32.minus(it).toByte() }
            val specs = Argon2Specs(
                type = Argon2Parameters.ARGON2_id,
                version = Argon2Parameters.ARGON2_VERSION_13,
                salt = salt,
                iterations = 3,
                memorySize = 32_768,
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
            val generator = Argon2BytesGenerator()
            generator.init(params)
            val expected = ByteArray(specs.keySize)
            generator.generateBytes(password, expected)
            val actual = BytesGenerator.Argon2.generate(password = password, specs = specs)
            assertTrue(expected.contentEquals(actual))
        }
    }
}
