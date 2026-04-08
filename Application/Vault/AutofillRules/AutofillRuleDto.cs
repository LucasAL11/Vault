namespace Application.Vault.AutofillRules;

public sealed record AutofillRuleDto(
    Guid Id,
    Guid VaultId,
    string UrlPattern,
    string Login,
    string SecretName,
    bool IsActive,
    DateTimeOffset CreatedAt);
