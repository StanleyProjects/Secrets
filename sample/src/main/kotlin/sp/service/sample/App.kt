package sp.service.sample

import org.bouncycastle.crypto.params.Argon2Parameters
import sp.kx.secrets.Argon2Specs
import sp.kx.secrets.Bytes
import sp.kx.secrets.Ciphers
import sp.kx.secrets.GCMSpecs
import sp.kx.secrets.Keys
import sp.kx.secrets.Macs
import java.security.MessageDigest
import java.util.Locale

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
    val salt = ByteArray(32) { 32.minus(it).toByte() }
    println("salt: ${salt.copyOf(16).hex()}")
    val seedSpecs = Argon2Specs(
        type = Argon2Parameters.ARGON2_id,
        version = Argon2Parameters.ARGON2_VERSION_13,
        salt = salt,
        iterations = 3,
        memorySize = 32_768,
        parallelism = 1,
        keySize = 32,
    )
    val seed = Bytes.Argon2.generate(password = "foobarbaz".toCharArray(), seedSpecs)
    val key = Keys.AES + seed
    println("key: ${key.encoded.copyOf(16).hex()}")
    //
    val iv = ByteArray(12) { 12.minus(it).toByte() }
    println("iv: ${iv.hex()}")
    val specs = GCMSpecs(tagSize = 128, iv = iv)
    //
    val expected = "foobarbaz".toByteArray(Charsets.UTF_8)
    val encrypted = Ciphers.AES.GCM.NoPadding.encrypt(key = key, decrypted = expected, specs = specs)
    println("encrypted: ${encrypted.copyOf(16).hex()}")
    val actual = Ciphers.AES.GCM.NoPadding.decrypt(key = key, encrypted = encrypted, specs = specs)
    check(expected.contentEquals(actual))
    //
    val md = MessageDigest.getInstance("sha256")
    val signature = Macs.HMAC.SHA512.sign(key = Keys.HMAC.SHA512 + md.digest(seed), signee = expected)
    println("signature: ${signature.copyOf(16).hex()}")
}
