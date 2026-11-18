using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Plugin.EA.DirtySdk.ProtoSsl;

/// <summary>
/// BouncyCastle crypto provider extended with the RC4 support it dropped, so the
/// ProtoSSL RC4 cipher suites can be served. Everything except the RC4 record
/// cipher is the stock implementation.
/// </summary>
public sealed class EaTlsCrypto(SecureRandom random) : BcTlsCrypto(random)
{
    public override bool HasEncryptionAlgorithm(int encryptionAlgorithm) =>
        encryptionAlgorithm == EncryptionAlgorithm.RC4_128 || base.HasEncryptionAlgorithm(encryptionAlgorithm);

    public override TlsCipher CreateCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm) =>
        encryptionAlgorithm == EncryptionAlgorithm.RC4_128
            ? new Rc4SslCipher(cryptoParams, macAlgorithm)
            : base.CreateCipher(cryptoParams, encryptionAlgorithm, macAlgorithm);
}
