using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Plugin.EA.DirtySdk.ProtoSsl;

/// <summary>
/// The TLS policy ProtoSSL clients of this era expect: SSL 3.0, RSA key
/// exchange, and the RC4 cipher suites. Modern stacks disable all three, which
/// is why the handshake is served here rather than by ServerApp's
/// <c>SslStream</c> listeners.
/// </summary>
/// <remarks>
/// The accepted cipher suites and protocol bounds are confirmed against a live
/// client handshake (docs/PROTOSSL.md) before being relied on; RC4 over SSLv3
/// is the documented starting point.
/// </remarks>
internal sealed class EaTlsServer(TlsCrypto crypto, EaCertificates.Material certificate)
    : DefaultTlsServer(crypto)
{
    private readonly EaCertificates.Material _certificate = certificate;

    protected override ProtocolVersion[] GetSupportedVersions() =>
        [ProtocolVersion.SSLv3];

    protected override int[] GetSupportedCipherSuites() =>
    [
        CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
        CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
    ];

    public override TlsCredentials GetCredentials()
    {
        // SSLv3 RC4 suites use RSA key transport, so the server authenticates
        // with an RSA key-exchange (decryptor) credential rather than a signer.
        var bcCrypto = (BcTlsCrypto)Crypto;
        var certificate = new Certificate([new BcTlsCertificate(bcCrypto, _certificate.Certificate.GetEncoded())]);
        return new BcDefaultTlsCredentialedDecryptor(bcCrypto, certificate, _certificate.PrivateKey);
    }
}
