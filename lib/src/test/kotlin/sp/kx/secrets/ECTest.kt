package sp.kx.secrets

import org.bouncycastle.jce.ECNamedCurveTable
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec

internal object ECTest {
    @Test
    fun getPublicKeyTest() {
        val spec = ECNamedCurveTable.getParameterSpec("secp256r1")
        val kpg = KeyPairGenerator.getInstance("ec")
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        for (i in 0 until 32) {
            md.update(byte++)
            kpg.initialize(ECGenParameterSpec(spec.name), SecureRandom(md.digest()))
            val keyPair = kpg.generateKeyPair()
            val expected = keyPair.public.encoded
            val actual = AsyKeys.EC.SECP256R1.getPublicKey(keyPair.private).encoded
            assertTrue(expected.contentEquals(actual))
        }
    }

    @Test
    fun getPrivateKeyTest() {
        val md = MessageDigest.getInstance("sha512")
        var byte: Byte = -1
        for (i in 0 until 32) {
            md.update(byte++)
            val magnitude = md.digest().copyOf(32)
            val expected = BigInteger(1, magnitude)
            val pk = AsyKeys.EC.SECP256R1.getPrivateKey(magnitude = magnitude)
            check(pk is ECPrivateKey)
            assertEquals(expected, pk.s)
        }
    }
}
