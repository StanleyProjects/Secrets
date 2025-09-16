package sp.service.sample

import sp.kx.secrets.Symmetric

fun main() {
    val cl = Thread.currentThread().contextClassLoader
    val generator: Symmetric.Generator = Symmetric.AES.generator
    val password = "qwe123".toCharArray()
    val salt = cl.getResourceAsStream("f1.salt")!!.use { it.readBytes() }
    val expected = generator.toSecretKey(password = password, salt = salt)
    val encoded = cl.getResourceAsStream("f1.aes")!!.use { it.readBytes() }
    val factory: Symmetric.Factory = Symmetric.AES.factory
    val actual = factory.toSecretKey(encoded = encoded)
    check(expected.encoded.contentEquals(actual.encoded))
}
