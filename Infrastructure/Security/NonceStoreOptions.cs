namespace Infrastructure.Security;

public sealed class NonceStoreOptions
{
    public bool Enabled { get; init; } = true;
    public int TtlSeconds { get; init; } = 300;
    public int MaxEntries { get; init; } = 50_000;
}
