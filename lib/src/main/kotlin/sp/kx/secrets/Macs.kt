package sp.kx.secrets

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class Macs internal constructor(
    val algorithm: String,
) {
    fun sign(key: ByteArray, signee: ByteArray): ByteArray {
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(key, algorithm))
        return mac.doFinal(signee)
    }

    object HMAC {
        val SHA512 = Macs(algorithm = "hmacsha512")
    }
}
