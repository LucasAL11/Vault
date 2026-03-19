using Application.Abstractions.Security;
using Microsoft.Extensions.Options;

namespace Infrastructure.Security;

internal sealed class DevKeyProvider : IKeyProvider
{
    private readonly KeyMaterial _key;

    public DevKeyProvider(IOptions<KeyProviderOptions> options)
    {
        var devOptions = options.Value.Dev;
        if (string.IsNullOrWhiteSpace(devOptions.Base64Key))
        {
            throw new InvalidOperationException("KeyProvider:Dev:Base64Key is required in Dev mode.");
        }

        _key = BuildKey(devOptions.KeyId, devOptions.Base64Key);
    }

    public ValueTask<KeyMaterial> GetCurrentKeyAsync(CancellationToken cancellationToken = default)
        => ValueTask.FromResult(_key);

    public ValueTask<KeyMaterial?> GetKeyByIdAsync(string keyId, CancellationToken cancellationToken = default)
    {
        if (string.Equals(_key.KeyId, keyId, StringComparison.OrdinalIgnoreCase))
        {
            return ValueTask.FromResult<KeyMaterial?>(_key);
        }

        return ValueTask.FromResult<KeyMaterial?>(null);
    }

    public ValueTask<IReadOnlyCollection<string>> GetKnownKeyIdsAsync(CancellationToken cancellationToken = default)
        => ValueTask.FromResult<IReadOnlyCollection<string>>(new[] { _key.KeyId });

    public ValueTask<KeyMaterial> RotateCurrentKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        if (string.Equals(_key.KeyId, keyId, StringComparison.OrdinalIgnoreCase))
        {
            return ValueTask.FromResult(_key);
        }

        throw new InvalidOperationException("DevKeyProvider supports only a single key and cannot rotate to a different key id.");
    }

    private static KeyMaterial BuildKey(string keyId, string base64Key)
    {
        var parsed = ParseAndValidate(base64Key);
        var normalizedKeyId = string.IsNullOrWhiteSpace(keyId) ? "dev-local-key-v1" : keyId.Trim();
        return new KeyMaterial(normalizedKeyId, parsed);
    }

    private static byte[] ParseAndValidate(string base64Key)
    {
        try
        {
            var bytes = Convert.FromBase64String(base64Key);
            if (bytes.Length is not (16 or 24 or 32))
            {
                throw new InvalidOperationException("KeyProvider key must be 16, 24, or 32 bytes.");
            }

            return bytes;
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("KeyProvider key is not valid base64.", ex);
        }
    }
}
