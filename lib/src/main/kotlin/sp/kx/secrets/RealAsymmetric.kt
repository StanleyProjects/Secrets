package sp.kx.secrets

internal object RealAsymmetric : Asymmetric {
    override val rsa: Asymmetric.Encryption = RSAECBEncryption(paddings = "PKCS1Padding")
    override val signing: Asymmetric.Signing = RSASigning(algorithm = "SHA256withRSA")
}
