package sp.kx.secrets

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom

internal class RSAECBEncryptionTest {
    @Test
    fun toPublicKeyTest() {
        val encryption: Asymmetric.Encryption = RSAECBEncryption(paddings = "PKCS1Padding")
        TODO()
    }
}
