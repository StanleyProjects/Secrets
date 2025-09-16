package sp.kx.secrets

import java.security.KeyStore

object PKCS12KeyStores : Asymmetric.KeyStores {
    override fun toKeyStore(encoded: ByteArray, password: CharArray): KeyStore {
        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(encoded.inputStream(), password)
        return keyStore
    }
}
