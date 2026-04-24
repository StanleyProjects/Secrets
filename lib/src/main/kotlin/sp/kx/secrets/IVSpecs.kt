package sp.kx.secrets

class IVSpecs(
    val iv: ByteArray,
) {
    override fun toString(): String {
        return "IVSpecs(iv:size: ${iv.size})"
    }

    override fun equals(other: Any?): Boolean {
        return when (other) {
            is IVSpecs -> iv.contentEquals(other.iv)
            else -> false
        }
    }

    override fun hashCode(): Int {
        return iv.contentHashCode()
    }

    fun copy(
        iv: ByteArray = this.iv.copyOf(),
    ): IVSpecs {
        return IVSpecs(
            iv = iv,
        )
    }
}
