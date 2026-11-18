using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Plugin.EA.DirtySdk.ProtoSsl;

/// <summary>
/// Builds the server certificate ProtoSSL clients are shown during the SSLv3
/// handshake. EA signed its real <c>*.fesl.ea.com</c> certificates with its
/// "OTG3" certificate authority; the client's ProtoSSL does not verify that
/// signature correctly, so a certificate carrying the expected subject name is
/// accepted without EA's private key. We therefore generate our own key pair
/// and self-sign, rather than reproduce any captured EA key material.
/// </summary>
/// <remarks>
/// The exact shape the client accepts (RSA modulus size, the public exponent,
/// which name fields are checked) is confirmed against a live handshake and
/// recorded in docs/PROTOSSL.md; the defaults here are the documented starting
/// point and are overridable from title data so no value is hard-coded into a
/// single game.
/// </remarks>
public static class EaCertificates
{
    /// <summary>Issuer DN EA used for its online certificate authority (public, from the retail certificates).</summary>
    public const string DefaultIssuer =
        "C=US, ST=California, L=Redwood City, O=\"Electronic Arts, Inc.\", OU=Online Technology Group, CN=OTG3 Certificate Authority";

    public sealed record Request(string SubjectCommonName, string Issuer = DefaultIssuer, int KeyBits = 1024);

    public sealed record Material(X509Certificate Certificate, AsymmetricKeyParameter PrivateKey);

    /// <summary>
    /// Generates a self-signed certificate whose subject CN is
    /// <paramref name="request"/>.<see cref="Request.SubjectCommonName"/> (for
    /// example <c>fesl.ea.com</c>), with a fresh RSA key pair.
    /// </summary>
    public static Material Generate(Request request)
    {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, request.KeyBits));
        AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();

        var subject = new X509Name($"O=\"Electronic Arts, Inc.\", OU=Online Technology Group, CN={request.SubjectCommonName}");
        var issuer = new X509Name(request.Issuer);

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(Math.Abs(DateTime.UtcNow.Ticks)));
        generator.SetIssuerDN(issuer);
        generator.SetSubjectDN(subject);
        generator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddYears(30));
        generator.SetPublicKey(keyPair.Public);

        ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA1WithRSA", keyPair.Private, random);
        X509Certificate certificate = generator.Generate(signatureFactory);
        return new Material(certificate, keyPair.Private);
    }
}
