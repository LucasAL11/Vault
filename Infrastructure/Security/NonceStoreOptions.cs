namespace Infrastructure.Security;

public sealed class NonceStoreOptions
{
    public string Provider { get; init; } = NonceStoreProviders.InMemory;
    public bool Enabled { get; init; } = true;
    public int TtlSeconds { get; init; } = 300;
    public int MaxEntries { get; init; } = 50_000;
}

public static class NonceStoreProviders
{
    public const string InMemory = "InMemory";
    public const string Postgres = "Postgres";
}
