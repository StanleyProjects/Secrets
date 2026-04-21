package sp.kx.secrets

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher

sealed interface RSACiphers {
    fun encrypt(key: PublicKey, decrypted: ByteArray): ByteArray
    fun decrypt(key: PrivateKey, encrypted: ByteArray): ByteArray

    object ECB {
        object PKCS1Padding : RSACiphers {
            override fun encrypt(key: PublicKey, decrypted: ByteArray): ByteArray {
                val cipher = Cipher.getInstance("rsa/ecb/pkcs1padding")
                cipher.init(Cipher.ENCRYPT_MODE, key)
                return cipher.doFinal(decrypted)
            }

            override fun decrypt(key: PrivateKey, encrypted: ByteArray): ByteArray {
                val cipher = Cipher.getInstance("rsa/ecb/pkcs1padding")
                cipher.init(Cipher.DECRYPT_MODE, key)
                return cipher.doFinal(encrypted)
            }
        }
    }
}
