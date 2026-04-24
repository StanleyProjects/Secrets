package sp.kx.secrets

import java.util.Objects

class GCMSpecs(
    val tagSize: Int,
    val iv: ByteArray,
) {
    override fun toString(): String {
        return "GCMSpecs(tagSize: $tagSize, iv:size: ${iv.size})"
    }

    override fun equals(other: Any?): Boolean {
        return when (other) {
            is GCMSpecs -> tagSize == other.tagSize && iv.contentEquals(other.iv)
            else -> false
        }
    }

    override fun hashCode(): Int {
        return Objects.hash(
            tagSize,
            iv.contentHashCode(),
        )
    }

    fun copy(
        tagSize: Int = this.tagSize,
        iv: ByteArray = this.iv,
    ): GCMSpecs {
        return GCMSpecs(
            tagSize = tagSize,
            iv = iv,
        )
    }
}
