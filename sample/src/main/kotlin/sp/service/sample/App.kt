package sp.service.sample

import java.security.SecureRandom
import java.util.Locale
import javax.crypto.KeyGenerator
import sp.kx.secrets.AESCiphers
import sp.kx.secrets.GCMSpecs

private fun Int.hex(locale: Locale = Locale.US): String {
    return String.format(locale, "%02x", and(0xff))
}

private fun ByteArray.hex(locale: Locale = Locale.US): String {
    if (isEmpty()) return ""
    val builder = StringBuilder()
    builder.append(get(0).toInt().hex(locale))
    for (i in 1 until size) {
        builder.append(get(i).toInt().hex(locale))
    }
    return builder.toString()
}

fun main() {
    val seed = ByteArray(32) { 32.minus(it).toByte() }
    println("seed: ${seed.copyOf(16).hex()}")
    val random = SecureRandom(seed)
    //
    val generator = KeyGenerator.getInstance("AES")
    generator.init(256, random)
    val key = generator.generateKey()
    println("key: ${key.encoded.copyOf(16).hex()}")
    //
    val iv = ByteArray(12) { 12.minus(it).toByte() }
    println("iv: ${iv.copyOf(16).hex()}")
    val specs = GCMSpecs(tagSize = 128, iv = iv)
    //
    val expected = "foobarbaz".toByteArray(Charsets.UTF_8)
    val encrypted = AESCiphers.GCM.NoPadding.encrypt(key = key, decrypted = expected, specs = specs)
    println("encrypted: ${encrypted.copyOf(16).hex()}")
    val actual = AESCiphers.GCM.NoPadding.decrypt(key = key, encrypted = encrypted, specs = specs)
    check(expected.contentEquals(actual))
}
