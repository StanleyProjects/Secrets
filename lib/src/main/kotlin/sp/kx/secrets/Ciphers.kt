package sp.kx.secrets

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

sealed interface Ciphers<T : Any> {
    fun encrypt(key: SecretKey, decrypted: ByteArray, specs: T): ByteArray
    fun decrypt(key: SecretKey, encrypted: ByteArray, specs: T): ByteArray

    class Asy internal constructor(private val transformation: String) {
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
    }

    object AES {
        object GCM {
            object NoPadding : Ciphers<GCMSpecs> {
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
            object PKCS5Padding : Ciphers<IVSpecs> {
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

    object RSA {
        object ECB {
            val PKCS1Padding = Asy(transformation = "rsa/ecb/pkcs1padding")
        }
    }
}
