package sp.service.sample

import sp.kx.secrets.AESCBCEncryption
import sp.kx.secrets.AESFactory
import sp.kx.secrets.Symmetric
import java.security.SecureRandom

fun main() {
    val encoded = Thread.currentThread().contextClassLoader.getResourceAsStream("foo.aes")!!.use { it.readBytes() }
    val factory: Symmetric.Factory = AESFactory
    val key = factory.toSecretKey(encoded = encoded)
    val enc: Symmetric.Encryption = AESCBCEncryption(paddings = "PKCS5Padding")
    val decrypted = "foobarbaz".toByteArray()
    val random: SecureRandom = SecureRandom.getInstanceStrong()
    val iv = ByteArray(16)
    random.nextBytes(iv)
    enc.encrypt(key = key, decrypted = decrypted, iv = iv)
}
