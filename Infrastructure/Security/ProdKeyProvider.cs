using Application.Abstractions.Security;
using Microsoft.Extensions.Options;

namespace Infrastructure.Security;

internal sealed class ProdKeyProvider : IKeyProvider
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, KeyMaterial> _keyRing = new(StringComparer.OrdinalIgnoreCase);
    private string _currentKeyId;

    public ProdKeyProvider(IOptions<KeyProviderOptions> options)
    {
        var prodOptions = options.Value.Prod;

        foreach (var key in prodOptions.Keys)
        {
            if (string.IsNullOrWhiteSpace(key.KeyId) 
                || string.IsNullOrWhiteSpace(key.Base64Key))
            {
                continue;
            }

            _keyRing[key.KeyId.Trim()] = new KeyMaterial(key.KeyId.Trim(), ParseAndValidate(key.Base64Key, key.KeyId));
        }

        if (!string.IsNullOrWhiteSpace(prodOptions.KeyId) && !string.IsNullOrWhiteSpace(prodOptions.Base64Key))
        {
            var legacyKeyId = prodOptions.KeyId.Trim();
            _keyRing[legacyKeyId] = new KeyMaterial(legacyKeyId, ParseAndValidate(prodOptions.Base64Key, legacyKeyId));
        }

        var envKeyId = Environment.GetEnvironmentVariable("APP_KEY_ID");
        var envKeyBase64 = Environment.GetEnvironmentVariable("APP_KEY_BASE64");
        if (!string.IsNullOrWhiteSpace(envKeyId) && !string.IsNullOrWhiteSpace(envKeyBase64))
        {
            var normalizedEnvKeyId = envKeyId.Trim();
            _keyRing[normalizedEnvKeyId] = new KeyMaterial(
                normalizedEnvKeyId,
                ParseAndValidate(envKeyBase64, normalizedEnvKeyId));
        }

        var currentFromEnv = Environment.GetEnvironmentVariable("APP_KEY_CURRENT_ID");
        _currentKeyId = FirstNonEmpty(
            currentFromEnv,
            envKeyId,
            prodOptions.CurrentKeyId,
            prodOptions.KeyId) ?? string.Empty;

        if (string.IsNullOrWhiteSpace(_currentKeyId) && _keyRing.Count == 1)
        {
            _currentKeyId = _keyRing.Keys.Single();
        }

        if (string.IsNullOrWhiteSpace(_currentKeyId))
        {
            throw new InvalidOperationException("Production current key id is missing. Configure APP_KEY_CURRENT_ID or KeyProvider:Prod:CurrentKeyId.");
        }

        if (!_keyRing.ContainsKey(_currentKeyId))
        {
            throw new InvalidOperationException($"Current production key '{_currentKeyId}' is not present in KeyProvider:Prod:Keys or APP_KEY_ID/APP_KEY_BASE64.");
        }
    }

    public ValueTask<KeyMaterial> GetCurrentKeyAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return ValueTask.FromResult(_keyRing[_currentKeyId]);
        }
    }

    public ValueTask<KeyMaterial?> GetKeyByIdAsync(string keyId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            return ValueTask.FromResult<KeyMaterial?>(null);
        }

        lock (_gate)
        {
            if (_keyRing.TryGetValue(keyId.Trim(), out var key))
            {
                return ValueTask.FromResult<KeyMaterial?>(key);
            }
        }

        return ValueTask.FromResult<KeyMaterial?>(null);
    }

    public ValueTask<IReadOnlyCollection<string>> GetKnownKeyIdsAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return ValueTask.FromResult<IReadOnlyCollection<string>>(_keyRing.Keys.OrderBy(x => x).ToArray());
        }
    }

    public ValueTask<KeyMaterial> RotateCurrentKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new InvalidOperationException("Key id is required for rotation.");
        }

        lock (_gate)
        {
            var normalized = keyId.Trim();
            if (!_keyRing.ContainsKey(normalized))
            {
                throw new InvalidOperationException($"Cannot rotate to key '{normalized}' because it is not present in the key ring.");
            }

            _currentKeyId = normalized;
            return ValueTask.FromResult(_keyRing[_currentKeyId]);
        }
    }

    private static byte[] ParseAndValidate(string base64Key, string keyId)
    {
        try
        {
            var bytes = Convert.FromBase64String(base64Key);
            if (bytes.Length is not (16 or 24 or 32))
            {
                throw new InvalidOperationException($"Key '{keyId}' must be 16, 24, or 32 bytes.");
            }

            return bytes;
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException($"Key '{keyId}' is not valid base64.", ex);
        }
    }

    private static string? FirstNonEmpty(params string?[] candidates)
        => candidates.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
}
