using System.Security.Cryptography;
using System.Text;
using Application.Abstractions.Security;

namespace Infrastructure.Security;

internal sealed class AesGcmSecretProtector(IKeyProvider keyProvider, INonceStore nonceStore) : ISecretProtector
{
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int MaxNonceGenerationAttempts = 5;

    public async ValueTask<ProtectedSecret> ProtectAsync(
        string plaintext,
        SecretProtectionContext? context = null,
        CancellationToken cancellationToken = default)
    {
        if (plaintext is null)
        {
            throw new InvalidOperationException("Plaintext cannot be null.");
        }

        var key = await keyProvider.GetCurrentKeyAsync(cancellationToken);
        var nonce = await GenerateUniqueNonceAsync(key.KeyId, context, cancellationToken);
        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var cipher = new byte[plainBytes.Length];
        var tag = new byte[TagLength];
        var aad = BuildAad(context);

        using var aes = new AesGcm(key.KeyBytes, TagLength);
        aes.Encrypt(nonce, plainBytes, cipher, tag, aad);

        var combined = new byte[cipher.Length + tag.Length];
        Buffer.BlockCopy(cipher, 0, combined, 0, cipher.Length);
        Buffer.BlockCopy(tag, 0, combined, cipher.Length, tag.Length);

        return new ProtectedSecret(combined, nonce, key.KeyId);
    }

    public async ValueTask<string> UnprotectAsync(
        ProtectedSecret protectedSecret,
        SecretProtectionContext? context = null,
        CancellationToken cancellationToken = default)
    {
        if (protectedSecret.CipherText.Length <= TagLength)
        {
            throw new InvalidOperationException("Cipher text payload is invalid.");
        }

        var key = await keyProvider.GetKeyByIdAsync(protectedSecret.KeyId, cancellationToken);
        if (key is null)
        {
            throw new InvalidOperationException($"Key '{protectedSecret.KeyId}' was not found.");
        }

        var cipherLength = protectedSecret.CipherText.Length - TagLength;
        var cipher = new byte[cipherLength];
        var tag = new byte[TagLength];

        Buffer.BlockCopy(protectedSecret.CipherText, 0, cipher, 0, cipherLength);
        Buffer.BlockCopy(protectedSecret.CipherText, cipherLength, tag, 0, TagLength);

        var plaintext = new byte[cipher.Length];
        var aad = BuildAad(context);

        using var aes = new AesGcm(key.KeyBytes, TagLength);
        aes.Decrypt(protectedSecret.Nonce, cipher, tag, plaintext, aad);

        return Encoding.UTF8.GetString(plaintext);
    }

    private static byte[]? BuildAad(SecretProtectionContext? context)
    {
        if (context is null)
        {
            return null;
        }

        var serialized = $"{context.VaultId:D}|{context.SecretId:D}|{context.Version}";
        return Encoding.UTF8.GetBytes(serialized);
    }

    private async ValueTask<byte[]> GenerateUniqueNonceAsync(
        string keyId,
        SecretProtectionContext? context,
        CancellationToken cancellationToken)
    {
        var scope = BuildNonceScope(keyId, context);

        for (var attempt = 0; attempt < MaxNonceGenerationAttempts; attempt++)
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceLength);
            var accepted = await nonceStore.TryAddAsync(scope, nonce, cancellationToken);
            if (accepted)
            {
                return nonce;
            }
        }

        throw new InvalidOperationException("Unable to allocate a unique nonce in the configured nonce store window.");
    }

    private static string BuildNonceScope(string keyId, SecretProtectionContext? context)
    {
        if (context is null)
        {
            return $"key:{keyId}";
        }

        return $"key:{keyId}|vault:{context.VaultId:D}|secret:{context.SecretId:D}";
    }
}
