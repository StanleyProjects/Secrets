package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal object IVSpecsTest {
    @Test
    fun toStringTest() {
        val iv = ByteArray(32) { (32 - it).toByte() }
        val specs = IVSpecs(
            iv = iv,
        )
        val expected = "IVSpecs(iv:size: ${iv.size})"
        val actual = specs.toString()
        assertEquals(expected, actual)
    }

    @Test
    fun equalsTest() {
        val iv = ByteArray(32) { (32 - it).toByte() }
        val specs = IVSpecs(
            iv = iv,
        )
        listOf(
            specs to true,
            specs.copy(iv = ByteArray(0)) to false,
        ).forEach { (it, expected) ->
            assertEquals(specs == it, expected)
        }
    }

    @Test
    fun hashCodeTest() {
        val iv = ByteArray(32) { (32 - it).toByte() }
        val specs = IVSpecs(
            iv = iv,
        )
        val expected = iv.contentHashCode()
        val actual = specs.hashCode()
        assertEquals(expected, actual)
    }

    @Test
    fun copyTest() {
        val iv = ByteArray(32) { (32 - it).toByte() }
        val specs = IVSpecs(
            iv = iv,
        )
        assertEquals(specs, specs.copy())
    }
}
