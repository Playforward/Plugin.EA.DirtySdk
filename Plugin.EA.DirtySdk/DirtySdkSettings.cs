using System.Net;
using System.Net.Sockets;

namespace Plugin.EA.DirtySdk;

/// <summary>
/// Plugin-wide settings for the EA base layer, kept in
/// <c>Configs/EaDirtySdkConfig.json</c>. Per-game values (SKU, ports, host
/// names) live in each title's own data, not here.
/// </summary>
public sealed class DirtySdkSettings
{
    /// <summary>
    /// The address announced to clients as the FESL/Theater/QoS host. Empty
    /// means this machine's first non-loopback IPv4 address.
    /// </summary>
    public string PublicHost { get; set; } = "";

    /// <summary>QoS (latency probe) listeners. Empty until QoS is implemented; see docs/JOURNAL.md.</summary>
    public List<DirtySdkListener> Listeners { get; set; } = [];

    /// <summary>Log every handshake and request at Debug level.</summary>
    public bool LogTraffic { get; set; } = true;

    public IPAddress PublicAddress()
    {
        if (!string.IsNullOrWhiteSpace(PublicHost))
        {
            if (IPAddress.TryParse(PublicHost, out IPAddress? parsed))
                return parsed;
            return Dns.GetHostAddresses(PublicHost).First(a => a.AddressFamily == AddressFamily.InterNetwork);
        }
        return Dns.GetHostAddresses(Dns.GetHostName())
                  .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
               ?? IPAddress.Loopback;
    }
}

public sealed class DirtySdkListener
{
    public string Component { get; set; } = "";
    public int Port { get; set; }
    public bool Udp { get; set; }
}
