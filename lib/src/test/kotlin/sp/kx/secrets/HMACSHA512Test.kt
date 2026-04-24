package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import javax.crypto.Mac

internal object HMACSHA512Test {
    @Test
    fun signTest() {
        val mac = Mac.getInstance("hmacsha512")
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        for (i in 0 until 32) {
            md.update(byte++)
            val signee = md.digest().copyOf(32)
            md.update(byte++)
            val key = Keys.HMAC.SHA512 + md.digest()
            mac.init(key)
            val expected = mac.doFinal(signee)
            val actual = Macs.HMAC.SHA512.sign(key = key, signee = signee)
            assertTrue(expected.contentEquals(actual))
        }
    }
}
