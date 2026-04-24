package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.Objects

internal object GCMSpecsTest {
    @Test
    fun toStringTest() {
        val iv = ByteArray(32) { (32 - it).toByte() }
        val specs = GCMSpecs(
            tagSize = 0,
            iv = iv,
        )
        val expected = "GCMSpecs(tagSize: 0, iv:size: ${iv.size})"
        val actual = specs.toString()
        assertEquals(expected, actual)
    }

    @Test
    fun equalsTest() {
        val iv = ByteArray(32) { (32 - it).toByte() }
        val specs = GCMSpecs(
            tagSize = 0,
            iv = iv,
        )
        listOf(
            specs to true,
            specs.copy(tagSize = -1) to false,
            specs.copy(iv = ByteArray(0)) to false,
        ).forEach { (it, expected) ->
            assertEquals(specs == it, expected)
        }
    }

    @Test
    fun hashCodeTest() {
        val iv = ByteArray(32) { (32 - it).toByte() }
        val specs = GCMSpecs(
            tagSize = 0,
            iv = iv,
        )
        val expected = Objects.hash(
            specs.tagSize,
            iv.contentHashCode(),
        )
        val actual = specs.hashCode()
        assertEquals(expected, actual)
    }

    @Test
    fun copyTest() {
        val iv = ByteArray(32) { (32 - it).toByte() }
        val specs = GCMSpecs(
            tagSize = 0,
            iv = iv,
        )
        assertEquals(specs, specs.copy())
    }
}
