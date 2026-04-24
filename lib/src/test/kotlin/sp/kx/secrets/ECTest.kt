package sp.kx.secrets

import org.bouncycastle.jce.ECNamedCurveTable
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec

internal object ECTest {
    @Test
    fun getPublicKeyTest() {
        val spec = ECNamedCurveTable.getParameterSpec("secp256r1")
        val kpg = KeyPairGenerator.getInstance("ec")
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        md.update(byte++)
        kpg.initialize(ECGenParameterSpec(spec.name), SecureRandom(md.digest()))
        val keyPair = kpg.generateKeyPair()
        val expected = keyPair.public.encoded
        val actual = AsyKeys.EC.SECP256R1.getPublicKey(keyPair.private).encoded
        assertTrue(expected.contentEquals(actual))
    }
}
