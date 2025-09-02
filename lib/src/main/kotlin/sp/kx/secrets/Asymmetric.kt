package sp.kx.secrets

import java.security.PrivateKey
import java.security.PublicKey

interface Asymmetric {
    interface Encryption {
        fun toPublicKey(encoded: ByteArray): PublicKey
        fun toPrivateKey(encoded: ByteArray): PrivateKey
        fun encrypt(key: PublicKey, decrypted: ByteArray): ByteArray
        fun decrypt(key: PrivateKey, encrypted: ByteArray): ByteArray
    }

    interface Signing {
        fun sign(key: PrivateKey, encoded: ByteArray): ByteArray
        fun verify(key: PublicKey, encoded: ByteArray, signature: ByteArray): Boolean
    }

    val rsa: Encryption
    val signing: Signing
}
