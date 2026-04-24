package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.KeyAgreement

internal object ECDHTest {
    @Test
    fun getSharedBytesTest() {
        val ka = KeyAgreement.getInstance("ecdh")
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        md.update(byte++)
        val k1 = AsyKeys.EC.SECP256R1.newKeyPair(random = SecureRandom(md.digest()))
        md.update(byte++)
        val k2 = AsyKeys.EC.SECP256R1.newKeyPair(random = SecureRandom(md.digest()))
        ka.init(k1.private)
        ka.doPhase(k2.public, true)
        val expected = ka.generateSecret()
        val a12 = Shared.ECDH.getSharedBytes(thisKey = k1.private, thatKey = k2.public)
        assertTrue(expected.contentEquals(a12))
        val a21 = Shared.ECDH.getSharedBytes(thisKey = k2.private, thatKey = k1.public)
        assertTrue(expected.contentEquals(a21))
    }
}
