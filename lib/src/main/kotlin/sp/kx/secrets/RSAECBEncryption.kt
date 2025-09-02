package sp.kx.secrets

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

internal class RSAECBEncryption(private val paddings: String) : Asymmetric.Encryption {
    override fun toPublicKey(encoded: ByteArray): PublicKey {
        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = X509EncodedKeySpec(encoded)
        return keyFactory.generatePublic(keySpec)
    }

    override fun toPrivateKey(encoded: ByteArray): PrivateKey {
        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = PKCS8EncodedKeySpec(encoded)
        return keyFactory.generatePrivate(keySpec)
    }

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
