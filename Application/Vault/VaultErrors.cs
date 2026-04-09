using Shared;

namespace Application.Vault;

internal static class VaultErrors
{
    public static Error VaultNotFound(Guid vaultId) =>
        Error.NotFound("Vault.NotFound", $"Vault '{vaultId}' was not found.");

    public static Error SlugAlreadyExists(string slug) =>
        Error.Conflict("Vault.SlugAlreadyExists", $"A vault with slug '{slug}' already exists.");

    public static Error VaultMissingGroup(Guid vaultId) =>
        Error.Forbidden("Vault.GroupPolicyMissing", $"Vault '{vaultId}' does not have an authorization group configured.");

    public static Error ComputerNotFound(int computerId) =>
        Error.NotFound("Computer.NotFound", $"Computer '{computerId}' was not found.");

    public static Error MachineAlreadyLinked(Guid vaultId, int computerId) =>
        Error.Conflict("VaultMachine.AlreadyExists", $"Computer '{computerId}' is already linked to vault '{vaultId}'.");

    public static Error MachineNotFound(Guid vaultId, Guid machineId) =>
        Error.NotFound("VaultMachine.NotFound", $"Machine '{machineId}' was not found in vault '{vaultId}'.");

    public static Error InvalidComputerId() =>
        Error.BadRequest("VaultMachine.InvalidComputerId", "computerId must be greater than zero.");

    public static Error InvalidGroupId() =>
        Error.BadRequest("AdMap.InvalidGroupId", "groupId is required.");

    public static Error AdMapAlreadyExists(Guid vaultId, string groupId) =>
        Error.Conflict("AdMap.AlreadyExists", $"Group '{groupId}' is already mapped in vault '{vaultId}'.");

    public static Error AdMapNotFound(Guid vaultId, Guid adMapId) =>
        Error.NotFound("AdMap.NotFound", $"AD map '{adMapId}' was not found in vault '{vaultId}'.");

    public static Error InvalidUrlPattern() =>
        Error.BadRequest("AutofillRule.InvalidUrlPattern", "urlPattern is required.");

    public static Error InvalidLogin() =>
        Error.BadRequest("AutofillRule.InvalidLogin", "login is required.");

    public static Error InvalidSecretName() =>
        Error.BadRequest("AutofillRule.InvalidSecretName", "secretName is required.");

    public static Error AutofillRuleAlreadyExists(Guid vaultId, string urlPattern) =>
        Error.Conflict("AutofillRule.AlreadyExists", $"A rule for URL '{urlPattern}' already exists in vault '{vaultId}'.");

    public static Error AutofillRuleNotFound(Guid vaultId, Guid ruleId) =>
        Error.NotFound("AutofillRule.NotFound", $"Autofill rule '{ruleId}' was not found in vault '{vaultId}'.");
}
