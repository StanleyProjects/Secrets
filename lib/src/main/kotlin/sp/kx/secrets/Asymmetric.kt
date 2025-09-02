package sp.kx.secrets

import java.security.PrivateKey
import java.security.PublicKey

class Asymmetric(
    val factory: Factory,
    val enc: Encryption,
    val signing: Signing,
) {
    interface Factory {
        fun toPublicKey(encoded: ByteArray): PublicKey
        fun toPrivateKey(encoded: ByteArray): PrivateKey
    }

    interface Encryption {
        fun encrypt(key: PublicKey, decrypted: ByteArray): ByteArray
        fun decrypt(key: PrivateKey, encrypted: ByteArray): ByteArray
    }

    interface Signing {
        fun sign(key: PrivateKey, encoded: ByteArray): ByteArray
        fun verify(key: PublicKey, encoded: ByteArray, signature: ByteArray): Boolean
    }

    companion object {
        val RSA = Asymmetric(
            factory = RSAFactory,
            enc = RSAECBEncryption(paddings = "PKCS1Padding"),
            signing = RSASigning(algorithm = "SHA256withRSA"),
        )
    }
}
