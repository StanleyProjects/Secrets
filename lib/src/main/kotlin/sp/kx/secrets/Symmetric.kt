package sp.kx.secrets

import javax.crypto.SecretKey

class Symmetric(
    val factory: Factory,
//    val enc: Encryption,
) {
    interface Factory {
        fun toSecretKey(encoded: ByteArray): SecretKey
    }

    interface Encryption {
        fun encrypt(key: SecretKey, decrypted: ByteArray): ByteArray
        fun decrypt(key: SecretKey, encrypted: ByteArray): ByteArray
    }

    companion object {
        val AES = Symmetric(
            factory = AESFactory,
//            enc = TODO(),
        )
    }
}
