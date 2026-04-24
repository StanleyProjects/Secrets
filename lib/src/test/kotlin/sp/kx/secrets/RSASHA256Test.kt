package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature

internal object RSASHA256Test {
    @Test
    fun signTest() {
        val sig = Signature.getInstance("sha256withrsa")
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        for (i in 0 until 4) {
            md.update(byte++)
            val signee = md.digest()
            md.update(byte++)
            val keyPair = AsyKeys.RSA.newKeyPair(random = SecureRandom(md.digest()), keySize = 4096)
            val signature = Signing.RSA.SHA256.sign(key = keyPair.private, signee = signee)
            sig.initVerify(keyPair.public)
            sig.update(signee)
            assertTrue(sig.verify(signature))
        }
    }

    @Test
    fun verifyTest() {
        val sig = Signature.getInstance("sha256withrsa")
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        for (i in 0 until 4) {
            md.update(byte++)
            val signee = md.digest()
            md.update(byte++)
            val keyPair = AsyKeys.RSA.newKeyPair(random = SecureRandom(md.digest()), keySize = 4096)
            sig.initSign(keyPair.private)
            sig.update(signee)
            val signature = sig.sign()
            Signing.RSA.SHA256.verify(key = keyPair.public, signee = signee, signature = signature)
        }
    }
}
