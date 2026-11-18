using Plugin.EA.DirtySdk.ProtoSsl;

namespace Plugin.EA.DirtySdk.Tests;

public class EaCertificatesTests
{
    [Fact]
    public void Generates_certificate_with_the_requested_subject_common_name()
    {
        EaCertificates.Material material = EaCertificates.Generate(new EaCertificates.Request("fesl.ea.com"));

        string subject = material.Certificate.SubjectDN.ToString();
        Assert.Contains("CN=fesl.ea.com", subject);
        Assert.NotNull(material.PrivateKey);
    }

    [Fact]
    public void Uses_the_ea_online_ca_as_issuer_by_default()
    {
        EaCertificates.Material material = EaCertificates.Generate(new EaCertificates.Request("theater.ps3.ea.com"));

        Assert.Contains("OTG3 Certificate Authority", material.Certificate.IssuerDN.ToString());
    }

    [Fact]
    public void Each_host_gets_a_distinct_key()
    {
        var a = EaCertificates.Generate(new EaCertificates.Request("fesl.ea.com"));
        var b = EaCertificates.Generate(new EaCertificates.Request("fesl.ea.com"));

        Assert.NotEqual(a.Certificate.GetEncoded(), b.Certificate.GetEncoded());
    }
}
