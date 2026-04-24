package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.Objects

internal object PBKDF2SpecsTest {
    @Test
    fun toStringTest() {
        val salt = ByteArray(32) { (32 - it).toByte() }
        val specs = PBKDF2Specs(
            salt = salt,
            iterations = 0,
            keySize = 1,
        )
        val expected = "PBKDF2Specs(salt:size: ${salt.size}, iterations: 0, keySize: 1)"
        val actual = specs.toString()
        assertEquals(expected, actual)
    }

    @Test
    fun equalsTest() {
        val salt = ByteArray(32) { (32 - it).toByte() }
        val specs = PBKDF2Specs(
            salt = salt,
            iterations = 0,
            keySize = 1,
        )
        listOf(
            specs to true,
            specs.copy(salt = ByteArray(0)) to false,
            specs.copy(iterations = -1) to false,
            specs.copy(keySize = -1) to false,
        ).forEach { (it, expected) ->
            assertEquals(specs == it, expected)
        }
    }

    @Test
    fun hashCodeTest() {
        val salt = ByteArray(32) { (32 - it).toByte() }
        val specs = PBKDF2Specs(
            salt = salt,
            iterations = 0,
            keySize = 1,
        )
        val expected = Objects.hash(
            salt.contentHashCode(),
            specs.iterations,
            specs.keySize,
        )
        val actual = specs.hashCode()
        assertEquals(expected, actual)
    }

    @Test
    fun copyTest() {
        val salt = ByteArray(32) { (32 - it).toByte() }
        val specs = PBKDF2Specs(
            salt = salt,
            iterations = 0,
            keySize = 1,
        )
        assertEquals(specs, specs.copy())
    }
}
