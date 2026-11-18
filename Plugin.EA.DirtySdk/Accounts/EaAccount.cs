namespace Plugin.EA.DirtySdk.Accounts;

/// <summary>
/// An EA "Nucleus" account: the master login a console signs in to, which owns
/// one or more personas (the per-game display names). Shared by every EA
/// protocol so one player keeps one identity across FESL (Plasma) and Blaze
/// titles.
/// </summary>
public sealed class EaAccount
{
    /// <summary>Numeric Nucleus id (NUID) the protocols echo back as <c>nuid</c> / account id.</summary>
    public long Id { get; init; }

    /// <summary>Login name. For PS3 ticket logins this is derived from the PSN online id, not a typed address.</summary>
    public string Name { get; init; } = "";

    /// <summary>How the account was established, e.g. a PSN or RPCN NP ticket. Kept for auditing, never trusted as authorization on its own.</summary>
    public string Origin { get; init; } = "";

    public List<EaPersona> Personas { get; } = [];
}

/// <summary>A per-game display identity under an <see cref="EaAccount"/>.</summary>
public sealed class EaPersona
{
    public long Id { get; init; }
    public string Name { get; init; } = "";
}

/// <summary>
/// A live login. The key (EA calls it the <c>LKEY</c>) is issued by FESL at
/// login and then presented by the client to Theater and Messenger to prove the
/// same session, so all three services share one of these.
/// </summary>
public sealed class EaSession
{
    public required string LoginKey { get; init; }
    public required EaAccount Account { get; init; }
    public EaPersona? Persona { get; set; }

    /// <summary>Which game this session belongs to (title id), so services never mix players across titles.</summary>
    public string TitleId { get; init; } = "";
}
