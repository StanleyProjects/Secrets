package sp.kx.secrets

import java.util.Objects

class PBKDF2Specs(
    val salt: ByteArray,
    val iterations: Int,
    val keySize: Int,
) {
    override fun toString(): String {
        return "PBKDF2Specs(salt:size: ${salt.size}, iterations: $iterations, keySize: $keySize)"
    }

    override fun equals(other: Any?): Boolean {
        return when (other) {
            is PBKDF2Specs -> {
                salt.contentEquals(other.salt) &&
                    iterations == other.iterations &&
                    keySize == other.keySize
            }
            else -> false
        }
    }

    override fun hashCode(): Int {
        return Objects.hash(
            salt.contentHashCode(),
            iterations,
            keySize,
        )
    }

    fun copy(
        salt: ByteArray = this.salt.copyOf(),
        iterations: Int = this.iterations,
        keySize: Int = this.keySize,
    ): PBKDF2Specs {
        return PBKDF2Specs(
            salt = salt,
            iterations = iterations,
            keySize = keySize,
        )
    }
}
