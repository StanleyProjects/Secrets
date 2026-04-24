package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature

internal object ECDSASHA256Test {
    @Test
    fun signTest() {
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        for (i in 0 until 32) {
            md.update(byte++)
            val signee = md.digest()
            md.update(byte++)
            val keyPair = AsyKeys.EC.SECP256R1.newKeyPair(random = SecureRandom(md.digest()))
            val signature = Signing.ECDSA.SHA256.sign(key = keyPair.private, signee = signee)
            val sig = Signature.getInstance("sha256withecdsa")
            sig.initVerify(keyPair.public)
            sig.update(signee)
            assertTrue(sig.verify(signature))
        }
    }

    @Test
    fun verifyTest() {
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        for (i in 0 until 32) {
            md.update(byte++)
            val signee = md.digest()
            md.update(byte++)
            val keyPair = AsyKeys.EC.SECP256R1.newKeyPair(random = SecureRandom(md.digest()))
            val sig = Signature.getInstance("sha256withecdsa")
            sig.initSign(keyPair.private)
            sig.update(signee)
            val signature = sig.sign()
            Signing.ECDSA.SHA256.verify(key = keyPair.public, signee = signee, signature = signature)
        }
    }
}
