using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Plugin.EA.DirtySdk.Accounts;

/// <summary>
/// In-memory store of EA accounts, personas and live sessions, shared by the
/// Plasma and Blaze plugins through <see cref="DirtySdkRuntime"/>. A durable
/// backing store can replace this later behind the same surface; nothing here
/// is persisted yet, which is recorded in docs/JOURNAL.md.
/// </summary>
public sealed class EaAccountStore
{
    private readonly ConcurrentDictionary<long, EaAccount> _accounts = new();
    private readonly ConcurrentDictionary<string, EaSession> _sessionsByKey = new();
    private long _nextAccountId = 1_000_000;
    private long _nextPersonaId = 2_000_000;

    /// <summary>Finds an account by login name, or creates one. The <paramref name="origin"/> records how it was proven (e.g. "psn", "rpcn").</summary>
    public EaAccount GetOrCreate(string name, string origin)
    {
        foreach (EaAccount existing in _accounts.Values)
            if (string.Equals(existing.Name, name, StringComparison.OrdinalIgnoreCase))
                return existing;

        var account = new EaAccount
        {
            Id = Interlocked.Increment(ref _nextAccountId),
            Name = name,
            Origin = origin,
        };
        _accounts[account.Id] = account;
        return account;
    }

    public EaPersona AddPersona(EaAccount account, string name)
    {
        var persona = new EaPersona { Id = Interlocked.Increment(ref _nextPersonaId), Name = name };
        account.Personas.Add(persona);
        return persona;
    }

    /// <summary>Opens a session and returns it with a fresh login key.</summary>
    public EaSession OpenSession(EaAccount account, string titleId)
    {
        var session = new EaSession { LoginKey = NewLoginKey(), Account = account, TitleId = titleId };
        _sessionsByKey[session.LoginKey] = session;
        return session;
    }

    public EaSession? FindSession(string loginKey) =>
        _sessionsByKey.GetValueOrDefault(loginKey);

    public void CloseSession(string loginKey) =>
        _sessionsByKey.TryRemove(loginKey, out _);

    private static string NewLoginKey() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
}
