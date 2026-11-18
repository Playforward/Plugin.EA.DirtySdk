namespace Plugin.EA.DirtySdk.Crypto;

/// <summary>
/// RC4 stream cipher. EA's ProtoSSL negotiates SSLv3 with the RC4-MD5 / RC4-SHA
/// cipher suites, which modern TLS stacks (including .NET's <c>SslStream</c> and
/// BouncyCastle's defaults) refuse, so the ProtoSSL server supplies the cipher
/// itself. The algorithm is public and self-contained; this is our own
/// implementation, written from its definition, not taken from any emulator.
/// </summary>
public sealed class Rc4
{
    private readonly byte[] _s = new byte[256];
    private int _i;
    private int _j;

    public Rc4(ReadOnlySpan<byte> key)
    {
        if (key.IsEmpty)
            throw new ArgumentException("RC4 key must not be empty", nameof(key));

        for (int i = 0; i < 256; i++)
            _s[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + _s[i] + key[i % key.Length]) & 0xff;
            (_s[i], _s[j]) = (_s[j], _s[i]);
        }
    }

    /// <summary>XORs the keystream into <paramref name="data"/> in place. Encrypt and decrypt are the same operation.</summary>
    public void Process(Span<byte> data)
    {
        for (int n = 0; n < data.Length; n++)
        {
            _i = (_i + 1) & 0xff;
            _j = (_j + _s[_i]) & 0xff;
            (_s[_i], _s[_j]) = (_s[_j], _s[_i]);
            int k = _s[(_s[_i] + _s[_j]) & 0xff];
            data[n] ^= (byte)k;
        }
    }

    /// <summary>Returns a processed copy, leaving the input untouched.</summary>
    public byte[] ProcessToArray(ReadOnlySpan<byte> data)
    {
        byte[] output = data.ToArray();
        Process(output.AsSpan());
        return output;
    }
}
