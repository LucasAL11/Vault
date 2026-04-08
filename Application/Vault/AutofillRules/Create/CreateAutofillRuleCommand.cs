using Application.Abstractions.Messaging.Message;

namespace Application.Vault.AutofillRules.Create;

public sealed record CreateAutofillRuleCommand(
    Guid VaultId,
    string UrlPattern,
    string Login,
    string SecretName,
    bool IsActive) : ICommand<AutofillRuleDto>;
