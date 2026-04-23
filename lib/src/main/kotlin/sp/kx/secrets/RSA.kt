package sp.kx.secrets

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.RSAPublicKeySpec

object RSA {
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
}
