package sp.kx.secrets

import javax.crypto.Mac
import javax.crypto.SecretKey

class Macs private constructor(
    val algorithm: String,
) {
    fun sign(key: SecretKey, signee: ByteArray): ByteArray {
        val mac = Mac.getInstance(algorithm)
        mac.init(key)
        return mac.doFinal(signee)
    }

    object HMAC {
        val SHA512 = Macs(algorithm = "hmacsha512")
    }
}
