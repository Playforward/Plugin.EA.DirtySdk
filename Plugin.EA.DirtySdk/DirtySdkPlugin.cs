using System.Collections.Concurrent;
using Plugin.EA.DirtySdk.Accounts;
using Plugin.EA.DirtySdk.ProtoSsl;
using ServerShared.Plugins;

namespace Plugin.EA.DirtySdk;

/// <summary>
/// The shared base for EA's online stack: the transport pieces every EA title
/// used from the same DirtySDK release, regardless of whether the service layer
/// on top is Plasma (FESL + Theater) or Blaze. It owns the ProtoSSL server
/// certificate material, the shared account store, and (later) the QoS and NAT
/// helpers; the Plasma and Blaze plugins build on it through
/// <see cref="DirtySdkRuntime"/>.
/// </summary>
/// <remarks>
/// Loads first (low <see cref="Priority"/>) so the runtime is published before
/// the protocol plugins start. All EA plugins load into ServerApp's one
/// assembly load context, so they share these types directly.
/// </remarks>
public sealed class DirtySdkPlugin : ServerPlugin<DirtySdkSettings>
{
    public override uint Priority => 0;
    public override string Name => "EaDirtySdk";

    private readonly EaAccountStore _accounts = new();
    private readonly ConcurrentDictionary<string, EaCertificates.Material> _certificates = new(StringComparer.OrdinalIgnoreCase);

    public override void Start()
    {
        DirtySdkRuntime.Publish(_accounts, CertificateFor);
        Log.Information("[ea/dirtysdk] base ready: ProtoSSL certificates and the shared account store are available to the EA protocol plugins");
    }

    public override void Stop()
    {
        DirtySdkRuntime.Clear();
        _certificates.Clear();
    }

    /// <summary>One self-signed certificate per EA host name, generated on first request and reused.</summary>
    private EaCertificates.Material CertificateFor(string hostName) =>
        _certificates.GetOrAdd(hostName, host =>
        {
            Log.Information("[ea/dirtysdk] generating ProtoSSL certificate for {Host}", host);
            return EaCertificates.Generate(new EaCertificates.Request(host));
        });
}
