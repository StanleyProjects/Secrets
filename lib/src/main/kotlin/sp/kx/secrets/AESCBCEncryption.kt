package sp.kx.secrets

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/**
 * Advanced Encryption Standard as specified by NIST in [FIPS 197](http://csrc.nist.gov/publications/fips/index.html).
 * Cipher Block Chaining Mode, as defined in [FIPS PUB 81](http://csrc.nist.gov/publications/fips/index.html).
 *
 * @author [Stanley Wintergreen](https://github.com/kepocnhh)
 * @since 0.1.0
 */
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
