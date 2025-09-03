package sp.kx.secrets

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

/**
 * Implementation for signing using RSA keys.
 *
 * @author [Stanley Wintergreen](https://github.com/kepocnhh)
 * @since 0.1.0
 */
class RSASigning(private val algorithm: String) : Asymmetric.Signing {
    override fun sign(key: PrivateKey, encoded: ByteArray): ByteArray {
        val sig = Signature.getInstance(algorithm)
        sig.initSign(key)
        sig.update(encoded)
        return sig.sign()
    }

    override fun verify(key: PublicKey, encoded: ByteArray, signature: ByteArray): Boolean {
        val sig = Signature.getInstance(algorithm)
        sig.initVerify(key)
        sig.update(encoded)
        return sig.verify(signature)
    }
}
