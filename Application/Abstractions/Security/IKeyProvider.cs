namespace Application.Abstractions.Security;

public interface IKeyProvider
{
    ValueTask<KeyMaterial> GetCurrentKeyAsync(CancellationToken cancellationToken = default);

    ValueTask<KeyMaterial?> GetKeyByIdAsync(string keyId, CancellationToken cancellationToken = default)
        => ValueTask.FromResult<KeyMaterial?>(null);

    ValueTask<IReadOnlyCollection<string>> GetKnownKeyIdsAsync(CancellationToken cancellationToken = default)
        => ValueTask.FromResult<IReadOnlyCollection<string>>(Array.Empty<string>());

    ValueTask<KeyMaterial> RotateCurrentKeyAsync(string keyId, CancellationToken cancellationToken = default)
        => throw new InvalidOperationException("Key rotation is not supported by the current key provider.");
}

public sealed record KeyMaterial(
    string KeyId,
    byte[] KeyBytes);
