package sp.kx.secrets

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

object RSA {
    fun toPublicKey(encoded: ByteArray): PublicKey {
        val kf = KeyFactory.getInstance("rsa")
        return kf.generatePublic(X509EncodedKeySpec(encoded))
    }

    fun toPrivateKey(encoded: ByteArray): PrivateKey {
        val kf = KeyFactory.getInstance("rsa")
        return kf.generatePrivate(PKCS8EncodedKeySpec(encoded))
    }

    fun getPublicKey(key: PrivateKey): PublicKey {
        if (key !is RSAPrivateCrtKey) TODO("RSA:getPublicKey")
        val kf = KeyFactory.getInstance("rsa")
        val spec = RSAPublicKeySpec(key.modulus, key.publicExponent)
        return kf.generatePublic(spec)
    }

    fun newKeyPair(random: SecureRandom, keySize: Int): KeyPair {
        val kpg = KeyPairGenerator.getInstance("rsa")
        kpg.initialize(keySize, random)
        return kpg.generateKeyPair()
    }

    sealed interface Ciphers {
        fun encrypt(key: PublicKey, decrypted: ByteArray): ByteArray
        fun decrypt(key: PrivateKey, encrypted: ByteArray): ByteArray
    }

    object ECB {
        object PKCS1Padding : Ciphers {
            override fun encrypt(key: PublicKey, decrypted: ByteArray): ByteArray {
                val cipher = Cipher.getInstance("rsa/ecb/pkcs1padding")
                cipher.init(Cipher.ENCRYPT_MODE, key)
                return cipher.doFinal(decrypted)
            }

            override fun decrypt(key: PrivateKey, encrypted: ByteArray): ByteArray {
                val cipher = Cipher.getInstance("rsa/ecb/pkcs1padding")
                cipher.init(Cipher.DECRYPT_MODE, key)
                return cipher.doFinal(encrypted)
            }
        }
    }
}
