using Plugin.EA.DirtySdk.Accounts;
using Plugin.EA.DirtySdk.ProtoSsl;

namespace Plugin.EA.DirtySdk;

/// <summary>
/// The shared state the base plugin owns and the protocol plugins (Plasma,
/// Blaze) read: the account store and the ProtoSSL certificate material. The
/// base sets it when it starts; a protocol plugin that loads before it, or
/// without it, sees <see cref="IsReady"/> false and logs that the base is
/// missing rather than failing hard.
/// </summary>
/// <remarks>
/// This mirrors how Plugin.MagGameServer attaches to Plugin.Medius: a static
/// hook between separately-built plugins that share one assembly load context.
/// </remarks>
public static class DirtySdkRuntime
{
    public static EaAccountStore Accounts { get; private set; } = new();

    /// <summary>
    /// Supplies the server certificate for a given EA host name (for example
    /// <c>fesl.ea.com</c>). Set by the base plugin; one certificate is reused
    /// per host and generated on first request.
    /// </summary>
    public static Func<string, EaCertificates.Material>? CertificateFor { get; private set; }

    public static bool IsReady => CertificateFor is not null;

    internal static void Publish(EaAccountStore accounts, Func<string, EaCertificates.Material> certificateFor)
    {
        Accounts = accounts;
        CertificateFor = certificateFor;
    }

    internal static void Clear() => CertificateFor = null;
}
