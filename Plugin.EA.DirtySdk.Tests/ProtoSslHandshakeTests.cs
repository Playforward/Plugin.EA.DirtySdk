using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Plugin.EA.DirtySdk.ProtoSsl;

namespace Plugin.EA.DirtySdk.Tests;

/// <summary>
/// Proves the ProtoSSL server can actually complete an SSLv3 + RC4 handshake and
/// then carry application bytes, by driving a BouncyCastle client against it in
/// memory. This is the one thing a live BC2 test depends on: if SSLv3 or RC4 are
/// refused by the TLS stack, no amount of FESL work matters until that is fixed.
/// </summary>
public class ProtoSslHandshakeTests
{
    // ProtoSSL is SSLv3 + RC4, which stock BouncyCastle 2.7.0 cannot do (RC4 stream cipher removed). Our
    // Rc4SslCipher / EaTlsCrypto supply it; this proves the server completes the handshake and carries data.
    [Fact]
    public void Completes_sslv3_rc4_handshake_and_exchanges_application_data()
    {
        EaCertificates.Material cert = EaCertificates.Generate(new EaCertificates.Request("fesl.ea.com"));
        var server = new ProtoSslConnection(cert);

        var clientProtocol = new TlsClientProtocol();
        clientProtocol.Connect(new Sslv3Rc4Client(new EaTlsCrypto(new SecureRandom())));

        // Pump handshake records between the two engines until the client is connected.
        for (int round = 0; round < 20 && !clientProtocol.IsConnected; round++)
        {
            byte[] toServer = Drain(clientProtocol);
            if (toServer.Length > 0)
                server.OfferInbound(toServer);

            byte[] toClient = server.DrainOutbound();
            if (toClient.Length > 0)
                clientProtocol.OfferInput(toClient);
        }

        Assert.True(clientProtocol.IsConnected, "client handshake did not complete");
        Assert.True(server.HandshakeComplete, "server handshake did not complete");

        // Client sends a FESL-style request; server reads it back as plaintext.
        byte[] payload = Encoding.ASCII.GetBytes("TXN=Hello\n");
        clientProtocol.WriteApplicationData(payload, 0, payload.Length);
        server.OfferInbound(Drain(clientProtocol));

        byte[] received = server.ReadApplicationData();
        Assert.Equal("TXN=Hello\n", Encoding.ASCII.GetString(received));
    }

    private static byte[] Drain(TlsProtocol protocol)
    {
        int available = protocol.GetAvailableOutputBytes();
        if (available == 0)
            return [];
        byte[] buffer = new byte[available];
        int read = protocol.ReadOutput(buffer, 0, available);
        return read == buffer.Length ? buffer : buffer[..read];
    }

    /// <summary>A minimal SSLv3 + RC4 client that trusts any server certificate (we only test the transport here).</summary>
    private sealed class Sslv3Rc4Client(TlsCrypto crypto) : DefaultTlsClient(crypto)
    {
        protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.SSLv3];

        public override int[] GetCipherSuites() =>
        [
            CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
            CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
        ];

        public override TlsAuthentication GetAuthentication() => new TrustEverything();

        private sealed class TrustEverything : TlsAuthentication
        {
            public void NotifyServerCertificate(TlsServerCertificate serverCertificate) { }
            public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest) => null;
        }
    }
}
