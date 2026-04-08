using Shared;

namespace Application.Vault.Secrets;

internal static class SecretErrors
{
    public static Error SecretNotFound(Guid vaultId, string secretName) =>
        Error.NotFound(
            "Secret.NotFound",
            $"Secret '{secretName}' was not found in vault '{vaultId}'.");

    public static Error SecretVersionNotFound(Guid vaultId, string secretName, int version) =>
        Error.NotFound(
            "SecretVersion.NotFound",
            $"Version '{version}' for secret '{secretName}' was not found in vault '{vaultId}'.");

    public static Error InvalidExpiration(string message) =>
        Error.BadRequest("Secret.InvalidExpiration", message);
}
