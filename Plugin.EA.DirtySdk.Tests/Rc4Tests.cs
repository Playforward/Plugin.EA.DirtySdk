using System.Text;
using Plugin.EA.DirtySdk.Crypto;

namespace Plugin.EA.DirtySdk.Tests;

public class Rc4Tests
{
    // Test vectors from the original RC4 specification (key "Key" / "Wiki" / "Secret").
    [Theory]
    [InlineData("Key", "Plaintext", "BBF316E8D940AF0AD3")]
    [InlineData("Wiki", "pedia", "1021BF0420")]
    [InlineData("Secret", "Attack at dawn", "45A01F645FC35B383552544B9BF5")]
    public void Matches_known_vectors(string key, string plaintext, string expectedHex)
    {
        byte[] output = new Rc4(Encoding.ASCII.GetBytes(key)).ProcessToArray(Encoding.ASCII.GetBytes(plaintext));
        Assert.Equal(expectedHex, Convert.ToHexString(output));
    }

    [Fact]
    public void Decrypt_is_encrypt_with_a_fresh_cipher()
    {
        byte[] key = Encoding.ASCII.GetBytes("session-key");
        byte[] plaintext = Encoding.ASCII.GetBytes("FESL hello packet");

        byte[] cipher = new Rc4(key).ProcessToArray(plaintext);
        byte[] roundTrip = new Rc4(key).ProcessToArray(cipher);

        Assert.Equal(plaintext, roundTrip);
    }

    [Fact]
    public void Empty_key_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => new Rc4([]));
    }
}
