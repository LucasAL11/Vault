namespace Application.Abstractions.Security;

public interface ISecretProtector
{
    ValueTask<ProtectedSecret> ProtectAsync(
        string plaintext,
        SecretProtectionContext? context = null,
        CancellationToken cancellationToken = default);

    ValueTask<string> UnprotectAsync(
        ProtectedSecret protectedSecret,
        SecretProtectionContext? context = null,
        CancellationToken cancellationToken = default);
}

public sealed record ProtectedSecret(
    byte[] CipherText,
    byte[] Nonce,
    string KeyId);

public sealed record SecretProtectionContext(
    Guid VaultId,
    Guid SecretId,
    int Version);
