package sp.kx.secrets

import java.util.Objects

class Argon2Specs(
    val type: Int,
    val version: Int,
    val salt: ByteArray,
    val iterations: Int,
    val memorySize: Int,
    val parallelism: Int,
    val keySize: Int,
) {
    override fun toString(): String {
        return "Argon2Specs(type: $type, version: $version, salt:size: ${salt.size}, iterations: $iterations, memorySize: $memorySize, parallelism: $parallelism, keySize: $keySize)"
    }

    override fun equals(other: Any?): Boolean {
        return when (other) {
            is Argon2Specs -> {
                type == other.type &&
                version == other.version &&
                salt.contentEquals(other.salt) &&
                iterations == other.iterations &&
                memorySize == other.memorySize &&
                parallelism == other.parallelism &&
                keySize == other.keySize
            }
            else -> false
        }
    }

    override fun hashCode(): Int {
        return Objects.hash(
            type,
            version,
            salt.contentHashCode(),
            iterations,
            memorySize,
            parallelism,
            keySize,
        )
    }
}
