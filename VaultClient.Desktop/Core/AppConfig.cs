namespace VaultClient.Desktop.Core;

/// <summary>
/// Chaves usadas no CredentialStore para persistir a configuração do app (DPAPI).
/// </summary>
internal static class AppConfig
{
    internal const string BaseUrlKey      = "config:baseUrl";
    internal const string VaultIdKey      = "config:vaultId";
    internal const string ClientIdKey     = "config:clientId";
    internal const string ClientSecretKey = "config:clientSecret";
    internal const string DomainKey       = "config:domain";

    internal static bool IsConfigured(CredentialStore store)
        => store.Get(BaseUrlKey) is not null;

    internal static void Save(
        CredentialStore store,
        string baseUrl,
        string vaultId,
        string clientId,
        string clientSecret,
        string? domain = null)
    {
        store.Set(BaseUrlKey,      baseUrl.TrimEnd('/'));
        store.Set(VaultIdKey,      vaultId);
        store.Set(ClientIdKey,     clientId);
        store.Set(ClientSecretKey, clientSecret);

        if (!string.IsNullOrWhiteSpace(domain))
            store.Set(DomainKey, domain);
        else
            store.Remove(DomainKey);
    }
}
