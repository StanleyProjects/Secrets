package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.Objects

internal object Argon2SpecsTest {
    @Test
    fun toStringTest() {
        val salt = ByteArray(32)
        val specs = Argon2Specs(
            type = 0,
            version = 1,
            iterations = 2,
            memorySize = 3,
            parallelism = 4,
            keySize = 5,
            salt = salt,
        )
        val expected = "Argon2Specs(type: 0, version: 1, salt:size: ${salt.size}, iterations: 2, memorySize: 3, parallelism: 4, keySize: 5)"
        val actual = specs.toString()
        assertEquals(expected, actual)
    }

    @Test
    fun equalsTest() {
        val salt = ByteArray(32) { (32 - it).toByte() }
        val specs = Argon2Specs(
            type = 0,
            version = 1,
            iterations = 2,
            memorySize = 3,
            parallelism = 4,
            keySize = 5,
            salt = salt,
        )
        listOf(
            specs to true,
            specs.copy(type = -1) to false,
            specs.copy(version = -1) to false,
            specs.copy(iterations = -1) to false,
            specs.copy(memorySize = -1) to false,
            specs.copy(parallelism = -1) to false,
            specs.copy(keySize = -1) to false,
            specs.copy(salt = ByteArray(0)) to false,
        ).forEach { (it, expected) ->
            assertEquals(specs == it, expected)
        }
    }

    @Test
    fun hashCodeTest() {
        val salt = ByteArray(32)
        val specs = Argon2Specs(
            type = 0,
            version = 1,
            iterations = 2,
            memorySize = 3,
            parallelism = 4,
            keySize = 5,
            salt = salt,
        )
        val expected = Objects.hash(
            specs.type,
            specs.version,
            salt.contentHashCode(),
            specs.iterations,
            specs.memorySize,
            specs.parallelism,
            specs.keySize,
        )
        val actual = specs.hashCode()
        assertEquals(expected, actual)
    }

    @Test
    fun copyTest() {
        val salt = ByteArray(32) { (32 - it).toByte() }
        val specs = Argon2Specs(
            type = 0,
            version = 1,
            iterations = 2,
            memorySize = 3,
            parallelism = 4,
            keySize = 5,
            salt = salt,
        )
        assertEquals(specs, specs.copy())
    }
}
