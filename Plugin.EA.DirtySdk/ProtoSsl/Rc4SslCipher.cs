using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl;
using Plugin.EA.DirtySdk.Crypto;
using HashAlgorithm = System.Security.Cryptography.HashAlgorithm;

namespace Plugin.EA.DirtySdk.ProtoSsl;

/// <summary>
/// The SSL 3.0 record layer for the RC4-MD5 / RC4-SHA cipher suites ProtoSSL
/// uses. BouncyCastle 2.7.0 no longer ships an RC4 stream cipher, so we supply
/// the whole record transform ourselves: our own <see cref="Rc4"/> for the
/// stream and the SSLv3 MAC (RFC 6101 §5.2.3.1) built on the framework's MD5/SHA1.
/// Only the negotiated key block is taken from BouncyCastle
/// (<see cref="TlsImplUtilities.CalculateKeyBlock"/>), so this stays consistent
/// with the handshake. Clean-room, from the RFC — no emulator code.
/// </summary>
/// <remarks>
/// SSLv3 stream-cipher key block order (no IVs): client MAC secret, server MAC
/// secret, client write key, server write key. RC4 keystreams are continuous per
/// direction, so one <see cref="Rc4"/> per direction lives for the connection.
/// </remarks>
internal sealed class Rc4SslCipher : TlsCipher
{
    private const int Rc4KeySize = 16; // RC4-128

    private readonly int _macSize;
    private readonly byte[] _writeMacSecret;
    private readonly byte[] _readMacSecret;
    private readonly Rc4 _encrypt;
    private readonly Rc4 _decrypt;
    private readonly Func<HashAlgorithm> _newHash;
    private readonly int _padLength;

    public Rc4SslCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
    {
        // MAC primitive and its SSLv3 padding length (RFC 6101: 48 bytes for MD5, 40 for SHA-1).
        (_macSize, _padLength, _newHash) = macAlgorithm switch
        {
            MacAlgorithm.md5 or MacAlgorithm.hmac_md5 => (16, 48, (Func<HashAlgorithm>)MD5.Create),
            MacAlgorithm.sha or MacAlgorithm.hmac_sha1 => (20, 40, SHA1.Create),
            _ => throw new NotSupportedException($"ProtoSSL RC4 cipher supports MD5/SHA1 MAC only, not {macAlgorithm}"),
        };

        byte[] keyBlock = TlsImplUtilities.CalculateKeyBlock(cryptoParams, 2 * _macSize + 2 * Rc4KeySize);
        int o = 0;
        byte[] clientMac = Slice(keyBlock, ref o, _macSize);
        byte[] serverMac = Slice(keyBlock, ref o, _macSize);
        byte[] clientKey = Slice(keyBlock, ref o, Rc4KeySize);
        byte[] serverKey = Slice(keyBlock, ref o, Rc4KeySize);

        // We are the server: we write with the server key/secret and read with the client's.
        bool isServer = cryptoParams.IsServer;
        _writeMacSecret = isServer ? serverMac : clientMac;
        _readMacSecret = isServer ? clientMac : serverMac;
        _encrypt = new Rc4(isServer ? serverKey : clientKey);
        _decrypt = new Rc4(isServer ? clientKey : serverKey);
    }

    public bool UsesOpaqueRecordType => false;

    public int GetPlaintextLimit(int ciphertextLimit) => ciphertextLimit - _macSize;
    public int GetCiphertextDecodeLimit(int plaintextLimit) => plaintextLimit + _macSize;
    public int GetCiphertextEncodeLimit(int plaintextLength, int plaintextLimit) =>
        Math.Min(plaintextLength, plaintextLimit) + _macSize;

    public TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
        int headerAllocation, byte[] plaintext, int offset, int len)
    {
        byte[] mac = ComputeMac(_writeMacSecret, seqNo, contentType, plaintext, offset, len);

        byte[] output = new byte[headerAllocation + len + _macSize];
        Buffer.BlockCopy(plaintext, offset, output, headerAllocation, len);
        Buffer.BlockCopy(mac, 0, output, headerAllocation + len, _macSize);

        // RC4 only covers the fragment + MAC, never the record header BC fills in [headerAllocation).
        _encrypt.Process(output.AsSpan(headerAllocation, len + _macSize));
        return new TlsEncodeResult(output, 0, output.Length, contentType);
    }

    public TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
        int headerAllocation, ReadOnlySpan<byte> plaintext) =>
        EncodePlaintext(seqNo, contentType, recordVersion, headerAllocation, plaintext.ToArray(), 0, plaintext.Length);

    public TlsDecodeResult DecodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
        byte[] ciphertext, int offset, int len)
    {
        if (len < _macSize)
            throw new TlsFatalAlert(AlertDescription.decode_error);

        _decrypt.Process(ciphertext.AsSpan(offset, len));

        int contentLen = len - _macSize;
        byte[] expected = ComputeMac(_readMacSecret, seqNo, recordType, ciphertext, offset, contentLen);
        if (!CryptographicOperations.FixedTimeEquals(
                ciphertext.AsSpan(offset + contentLen, _macSize), expected))
            throw new TlsFatalAlert(AlertDescription.bad_record_mac);

        return new TlsDecodeResult(ciphertext, offset, contentLen, recordType);
    }

    public void RekeyDecoder() => throw new TlsFatalAlert(AlertDescription.internal_error);
    public void RekeyEncoder() => throw new TlsFatalAlert(AlertDescription.internal_error);

    /// <summary>
    /// SSLv3 MAC (RFC 6101 §5.2.3.1):
    /// hash(secret + pad2 + hash(secret + pad1 + seq(8) + type(1) + length(2) + content)).
    /// </summary>
    private byte[] ComputeMac(byte[] secret, long seqNo, short contentType, byte[] content, int offset, int len)
    {
        Span<byte> pad1 = stackalloc byte[_padLength];
        Span<byte> pad2 = stackalloc byte[_padLength];
        pad1.Fill(0x36);
        pad2.Fill(0x5c);

        Span<byte> prefix = stackalloc byte[8 + 1 + 2];
        BinaryPrimitives.WriteInt64BigEndian(prefix[..8], seqNo);
        prefix[8] = (byte)contentType;
        BinaryPrimitives.WriteUInt16BigEndian(prefix[9..], (ushort)len);

        using HashAlgorithm inner = _newHash();
        Feed(inner, secret);
        Feed(inner, pad1);
        Feed(inner, prefix);
        Feed(inner, content.AsSpan(offset, len), final: true);
        byte[] innerHash = inner.Hash!;

        using HashAlgorithm outer = _newHash();
        Feed(outer, secret);
        Feed(outer, pad2);
        Feed(outer, innerHash, final: true);
        return outer.Hash!;
    }

    private static void Feed(HashAlgorithm hash, ReadOnlySpan<byte> data, bool final = false)
    {
        byte[] buffer = data.ToArray();
        if (final)
            hash.TransformFinalBlock(buffer, 0, buffer.Length);
        else
            hash.TransformBlock(buffer, 0, buffer.Length, null, 0);
    }

    private static byte[] Slice(byte[] source, ref int offset, int length)
    {
        byte[] slice = source[offset..(offset + length)];
        offset += length;
        return slice;
    }
}
