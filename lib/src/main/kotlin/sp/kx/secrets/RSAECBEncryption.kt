package sp.kx.secrets

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher

internal class RSAECBEncryption(private val paddings: String) : Asymmetric.Encryption {
    override fun encrypt(key: PublicKey, decrypted: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/$paddings")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(decrypted)
    }

    override fun decrypt(key: PrivateKey, encrypted: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/$paddings")
        cipher.init(Cipher.DECRYPT_MODE, key)
        return cipher.doFinal(encrypted)
    }
}
