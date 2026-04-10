namespace VaultClient.Desktop.Models;

public sealed record SecretItem(
    string Name,
    int CurrentVersion,
    string? ContentType,
    string? KeyReference,
    bool? IsRevoked,
    DateTimeOffset? Expires);
