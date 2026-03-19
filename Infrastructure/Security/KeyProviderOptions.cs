namespace Infrastructure.Security;

public sealed class KeyProviderOptions
{
    public string Mode { get; init; } = "Dev";
    public string? OperatorsGroup { get; init; }
    public DevKeyProviderOptions Dev { get; init; } = new();
    public ProdKeyProviderOptions Prod { get; init; } = new();
    public ProdKmsKeyProviderOptions ProdKms { get; init; } = new();
}

public sealed class DevKeyProviderOptions
{
    public string KeyId { get; init; } = "dev-local-key-v1";
    public string Base64Key { get; init; } = string.Empty;
}

public sealed class ProdKeyProviderOptions
{
    // Backward compatibility with older single-key configuration.
    public string KeyId { get; init; } = string.Empty;
    public string Base64Key { get; init; } = string.Empty;

    public string CurrentKeyId { get; init; } = string.Empty;
    public List<KeyProviderKeyEntryOptions> Keys { get; init; } = new();
}

public sealed class KeyProviderKeyEntryOptions
{
    public string KeyId { get; init; } = string.Empty;
    public string Base64Key { get; init; } = string.Empty;
}

public sealed class ProdKmsKeyProviderOptions
{
    public bool Enabled { get; init; }
    public string BaseUrl { get; init; } = string.Empty;
    public string KeysEndpointPath { get; init; } = "/v1/keyring";
    public string? RotateEndpointPath { get; init; }
    public string? ApiKey { get; init; }
    public string ApiKeyHeaderName { get; init; } = "X-API-Key";
    public int TimeoutSeconds { get; init; } = 5;
    public int CacheTtlSeconds { get; init; } = 30;
}
