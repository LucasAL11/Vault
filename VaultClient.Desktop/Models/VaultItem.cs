namespace VaultClient.Desktop.Models;

public record VaultItem(
    Guid Id,
    string Name,
    string Slug,
    string Description,
    string TenantId,
    string Group,
    string Environment);
