package sp.kx.secrets

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

sealed interface AESCiphers<T : Any> {
    fun encrypt(key: SecretKey, decrypted: ByteArray, specs: T): ByteArray
    fun decrypt(key: SecretKey, encrypted: ByteArray, specs: T): ByteArray

    object GCM {
        object NoPadding : AESCiphers<GCMSpecs> {
            override fun encrypt(
                key: SecretKey,
                decrypted: ByteArray,
                specs: GCMSpecs,
            ): ByteArray {
                val cipher = Cipher.getInstance("aes/gcm/nopadding")
                cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(specs.tagSize, specs.iv))
                return cipher.doFinal(decrypted)
            }

            override fun decrypt(
                key: SecretKey,
                encrypted: ByteArray,
                specs: GCMSpecs,
            ): ByteArray {
                val cipher = Cipher.getInstance("aes/gcm/nopadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(specs.tagSize, specs.iv))
                return cipher.doFinal(encrypted)
            }
        }
    }

    object CBC {
        object PKCS5Padding : AESCiphers<IVSpecs> {
            override fun encrypt(
                key: SecretKey,
                decrypted: ByteArray,
                specs: IVSpecs,
            ): ByteArray {
                val cipher = Cipher.getInstance("aes/cbc/pkcs5padding")
                cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(specs.iv))
                return cipher.doFinal(decrypted)
            }

            override fun decrypt(
                key: SecretKey,
                encrypted: ByteArray,
                specs: IVSpecs,
            ): ByteArray {
                val cipher = Cipher.getInstance("aes/cbc/pkcs5padding")
                cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(specs.iv))
                return cipher.doFinal(encrypted)
            }
        }
    }
}
