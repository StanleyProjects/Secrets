package sp.kx.secrets

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class AESCBCEncryption(private val paddings: String) : Symmetric.Encryption {
    override fun encrypt(
        key: SecretKey,
        decrypted: ByteArray,
        iv: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/$paddings")
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
        return cipher.doFinal(decrypted)
    }

    override fun decrypt(
        key: SecretKey,
        encrypted: ByteArray,
        iv: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/$paddings")
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
        return cipher.doFinal(encrypted)
    }
}
