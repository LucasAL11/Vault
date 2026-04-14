namespace VaultClient.Desktop.Models;

public sealed record AutofillRuleItem(
    Guid Id,
    Guid VaultId,
    string UrlPattern,
    string Login,
    string SecretName,
    bool IsActive,
    DateTimeOffset CreatedAt);
