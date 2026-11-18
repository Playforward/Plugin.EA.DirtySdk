using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Security;

namespace Plugin.EA.DirtySdk.ProtoSsl;

/// <summary>
/// One ProtoSSL (SSLv3) connection, driven in non-blocking mode: ServerApp
/// hands us the raw TCP bytes for an EA FESL port, we run the handshake and the
/// record layer, and a protocol plugin (FESL, Blaze) works in plaintext through
/// <see cref="ReadApplicationData"/> / <see cref="WriteApplicationData"/>.
/// Theater and QoS are plain text and do not use this class.
/// </summary>
public sealed class ProtoSslConnection : IDisposable
{
    private readonly TlsServerProtocol _protocol = new();
    private readonly EaTlsServer _server;
    private bool _accepted;

    public ProtoSslConnection(EaCertificates.Material certificate)
    {
        _server = new EaTlsServer(new EaTlsCrypto(new SecureRandom()), certificate);
    }

    /// <summary>True once the SSLv3 handshake has completed.</summary>
    public bool HandshakeComplete { get; private set; }

    /// <summary>
    /// Feeds inbound ciphertext from the socket into the TLS engine. Call
    /// <see cref="DrainOutbound"/> afterwards to collect anything the engine
    /// wants sent back (handshake records, alerts).
    /// </summary>
    public void OfferInbound(ReadOnlySpan<byte> ciphertext)
    {
        if (!_accepted)
        {
            // Starts the non-blocking handshake; must run exactly once, before the first input.
            _protocol.Accept(_server);
            _accepted = true;
        }

        byte[] buffer = ciphertext.ToArray();
        _protocol.OfferInput(buffer);
        if (!HandshakeComplete && !_protocol.IsHandshaking && _protocol.IsConnected)
            HandshakeComplete = true;
    }

    /// <summary>Collects ciphertext the TLS engine wants written to the socket, or an empty array.</summary>
    public byte[] DrainOutbound()
    {
        int available = _protocol.GetAvailableOutputBytes();
        if (available == 0)
            return [];
        byte[] output = new byte[available];
        int read = _protocol.ReadOutput(output, 0, available);
        return read == output.Length ? output : output[..read];
    }

    /// <summary>Reads any decrypted application bytes the peer has sent, or an empty array.</summary>
    public byte[] ReadApplicationData()
    {
        int available = _protocol.GetAvailableInputBytes();
        if (available == 0)
            return [];
        byte[] output = new byte[available];
        int read = _protocol.ReadInput(output, 0, available);
        return read == output.Length ? output : output[..read];
    }

    /// <summary>Encrypts and queues application bytes; follow with <see cref="DrainOutbound"/> to get the ciphertext.</summary>
    public void WriteApplicationData(ReadOnlySpan<byte> plaintext)
    {
        byte[] buffer = plaintext.ToArray();
        _protocol.WriteApplicationData(buffer, 0, buffer.Length);
    }

    public void Dispose() => _protocol.Close();
}
