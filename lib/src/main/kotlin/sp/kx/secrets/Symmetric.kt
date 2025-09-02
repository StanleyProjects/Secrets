package sp.kx.secrets

import javax.crypto.SecretKey

class Symmetric(
    val factory: Factory,
    val enc: Encryption,
    val generator: Generator,
) {
    interface Factory {
        fun toSecretKey(encoded: ByteArray): SecretKey
    }

    interface Encryption {
        fun encrypt(key: SecretKey, decrypted: ByteArray, iv: ByteArray): ByteArray
        fun decrypt(key: SecretKey, encrypted: ByteArray, iv: ByteArray): ByteArray
    }

    interface Generator {
        fun toSecretKey(password: CharArray, salt: ByteArray): SecretKey
    }

    companion object {
        val AES = Symmetric(
            factory = AESFactory,
            enc = AESCBCEncryption(paddings = "PKCS5Padding"),
            generator = PBEGenerator(
                algorithm = "PBKDF2WithHmacSHA256",
                iterations = 1_048_576,
                keyLength = 256,
            ),
        )
    }
}
