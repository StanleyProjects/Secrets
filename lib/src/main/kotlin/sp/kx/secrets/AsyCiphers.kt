package sp.kx.secrets

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher

class AsyCiphers internal constructor(private val transformation: String) {
    fun encrypt(key: PublicKey, decrypted: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(decrypted)
    }

    fun decrypt(key: PrivateKey, encrypted: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, key)
        return cipher.doFinal(encrypted)
    }

    object RSA {
        object ECB {
            val PKCS1Padding = AsyCiphers(transformation = "rsa/ecb/pkcs1padding")
        }
    }
}
