package sp.kx.secrets

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

fun ByteArray.aes(): SecretKey {
    return SecretKeySpec(this, "aes")
}

fun ByteArray.hmacsha512(): SecretKey {
    return SecretKeySpec(this, "hmacsha512")
}
