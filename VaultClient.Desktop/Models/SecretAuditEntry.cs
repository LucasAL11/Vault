namespace VaultClient.Desktop.Models;

public sealed record SecretAuditEntry(
    string Action,
    string Actor,
    DateTimeOffset OccurredAtUtc,
    string? Details);
