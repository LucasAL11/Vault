namespace Infrastructure.Security;

public sealed class NonceStoreEntry
{
    public long Id { get; set; }
    public string Scope { get; set; } = string.Empty;
    public string NonceHash { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
}
