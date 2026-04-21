package sp.kx.secrets

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

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
}
