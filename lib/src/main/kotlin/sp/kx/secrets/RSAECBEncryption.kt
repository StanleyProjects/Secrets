package sp.kx.secrets

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher

/**
 * The RSA encryption algorithm as defined in [PKCS #1](http://www.rsa.com/rsalabs/node.asp?id=2125).
 * Electronic Codebook Mode, as defined in [FIPS PUB 81](http://csrc.nist.gov/publications/fips/index.html).
 *
 * @author [Stanley Wintergreen](https://github.com/kepocnhh)
 * @since 0.1.0
 */
class RSAECBEncryption(private val paddings: String) : Asymmetric.Encryption {
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
