package sp.kx.secrets

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class Macs private constructor(
    val algorithm: String,
) {
    fun sign(key: SecretKeySpec, signee: ByteArray): ByteArray {
        val mac = Mac.getInstance(algorithm)
        mac.init(key)
        return mac.doFinal(signee)
    }

    object HMAC {
        val SHA512 = Macs(algorithm = "hmacsha512")
    }
}
