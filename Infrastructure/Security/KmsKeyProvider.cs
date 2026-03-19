using System.Net.Http.Json;
using Application.Abstractions.Security;
using Microsoft.Extensions.Options;

namespace Infrastructure.Security;

internal sealed class KmsKeyProvider(
    IHttpClientFactory httpClientFactory,
    IOptions<KeyProviderOptions> options) : IKeyProvider
{
    private readonly Lock _gate = new();
    private readonly ProdKmsKeyProviderOptions _kmsOptions = ValidateOptions(options.Value.ProdKms);
    private Dictionary<string, KeyMaterial> _keyRing = new(StringComparer.OrdinalIgnoreCase);
    private string _currentKeyId = string.Empty;
    private DateTimeOffset _expiresAtUtc = DateTimeOffset.MinValue;

    public async ValueTask<KeyMaterial> GetCurrentKeyAsync(CancellationToken cancellationToken = default)
    {
        await RefreshIfNeededAsync(cancellationToken);

        lock (_gate)
        {
            return _keyRing[_currentKeyId];
        }
    }

    public async ValueTask<KeyMaterial?> GetKeyByIdAsync(string keyId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            return null;
        }

        await RefreshIfNeededAsync(cancellationToken);

        lock (_gate)
        {
            return _keyRing.TryGetValue(keyId.Trim(), out var found) ? found : null;
        }
    }

    public async ValueTask<IReadOnlyCollection<string>> GetKnownKeyIdsAsync(CancellationToken cancellationToken = default)
    {
        await RefreshIfNeededAsync(cancellationToken);

        lock (_gate)
        {
            return _keyRing.Keys.OrderBy(x => x).ToArray();
        }
    }

    public async ValueTask<KeyMaterial> RotateCurrentKeyAsync(string keyId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            throw new InvalidOperationException("Key id is required for rotation.");
        }

        if (string.IsNullOrWhiteSpace(_kmsOptions.RotateEndpointPath))
        {
            throw new InvalidOperationException("KMS rotation endpoint is not configured. Rotation must be executed in KMS/HSM.");
        }

        var client = BuildClient();
        using var response = await client.PostAsJsonAsync(
            _kmsOptions.RotateEndpointPath,
            new { keyId = keyId.Trim() },
            cancellationToken);
        response.EnsureSuccessStatusCode();

        lock (_gate)
        {
            _expiresAtUtc = DateTimeOffset.MinValue;
        }

        return await GetCurrentKeyAsync(cancellationToken);
    }

    private async Task RefreshIfNeededAsync(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        lock (_gate)
        {
            if (_keyRing.Count > 0 && now < _expiresAtUtc)
            {
                return;
            }
        }

        var client = BuildClient();
        var payload = await client.GetFromJsonAsync<KmsKeyRingResponse>(
            _kmsOptions.KeysEndpointPath,
            cancellationToken) ?? throw new InvalidOperationException("KMS response is empty.");

        if (string.IsNullOrWhiteSpace(payload.CurrentKeyId))
        {
            throw new InvalidOperationException("KMS response does not provide currentKeyId.");
        }

        var parsedRing = new Dictionary<string, KeyMaterial>(StringComparer.OrdinalIgnoreCase);
        foreach (var key in payload.Keys ?? [])
        {
            if (string.IsNullOrWhiteSpace(key.KeyId) || string.IsNullOrWhiteSpace(key.Base64Key))
            {
                continue;
            }

            var normalizedKeyId = key.KeyId.Trim();
            parsedRing[normalizedKeyId] = new KeyMaterial(normalizedKeyId, ParseAndValidate(key.Base64Key, normalizedKeyId));
        }

        if (parsedRing.Count == 0)
        {
            throw new InvalidOperationException("KMS response does not provide any usable keys.");
        }

        var normalizedCurrent = payload.CurrentKeyId.Trim();
        if (!parsedRing.ContainsKey(normalizedCurrent))
        {
            throw new InvalidOperationException($"KMS current key '{normalizedCurrent}' is not present in returned key ring.");
        }

        lock (_gate)
        {
            _keyRing = parsedRing;
            _currentKeyId = normalizedCurrent;
            _expiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(_kmsOptions.CacheTtlSeconds);
        }
    }

    private HttpClient BuildClient()
    {
        var client = httpClientFactory.CreateClient("KmsKeyProvider");

        if (!string.IsNullOrWhiteSpace(_kmsOptions.ApiKey))
        {
            client.DefaultRequestHeaders.Remove(_kmsOptions.ApiKeyHeaderName);
            client.DefaultRequestHeaders.TryAddWithoutValidation(_kmsOptions.ApiKeyHeaderName, _kmsOptions.ApiKey);
        }

        return client;
    }

    private static ProdKmsKeyProviderOptions ValidateOptions(ProdKmsKeyProviderOptions options)
    {
        if (!options.Enabled)
        {
            throw new InvalidOperationException("KeyProvider:ProdKms:Enabled must be true when mode is ProdKms.");
        }

        if (!Uri.TryCreate(options.BaseUrl, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException("KeyProvider:ProdKms:BaseUrl is invalid.");
        }

        if (string.IsNullOrWhiteSpace(options.KeysEndpointPath))
        {
            throw new InvalidOperationException("KeyProvider:ProdKms:KeysEndpointPath is required.");
        }

        if (options.TimeoutSeconds <= 0 || options.TimeoutSeconds > 60)
        {
            throw new InvalidOperationException("KeyProvider:ProdKms:TimeoutSeconds must be between 1 and 60.");
        }

        if (options.CacheTtlSeconds <= 0 || options.CacheTtlSeconds > 300)
        {
            throw new InvalidOperationException("KeyProvider:ProdKms:CacheTtlSeconds must be between 1 and 300.");
        }

        return options;
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

    private sealed class KmsKeyRingResponse
    {
        public string CurrentKeyId { get; init; } = string.Empty;
        public List<KmsKeyEntryResponse>? Keys { get; init; }
    }

    private sealed class KmsKeyEntryResponse
    {
        public string KeyId { get; init; } = string.Empty;
        public string Base64Key { get; init; } = string.Empty;
    }
}
