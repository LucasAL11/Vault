using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace VaultClient.Desktop.Core;

/// <summary>
/// Armazena segredos do cliente (JWT, client secret) usando DPAPI do Windows.
/// Os dados são encriptados vinculados ao perfil do usuário corrente do SO.
/// </summary>
public sealed class CredentialStore
{
    private static readonly byte[] Entropy =
        "VaultClientDesktop_v1"u8.ToArray();

    private readonly string _storePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "VaultClient", "creds.dat");

    private Dictionary<string, string> _cache = new(StringComparer.Ordinal);

    public CredentialStore()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_storePath)!);
        Load();
    }

    public string? Get(string key)
        => _cache.TryGetValue(key, out var val) ? val : null;

    public void Set(string key, string value)
    {
        _cache[key] = value;
        Persist();
    }

    public void Remove(string key)
    {
        _cache.Remove(key);
        Persist();
    }

    private void Load()
    {
        if (!File.Exists(_storePath))
        {
            _cache = new(StringComparer.Ordinal);
            return;
        }

        try
        {
            var encrypted = File.ReadAllBytes(_storePath);
            var plain = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
            var json = Encoding.UTF8.GetString(plain);
            _cache = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json)
                     ?? new(StringComparer.Ordinal);
        }
        catch
        {
            _cache = new(StringComparer.Ordinal);
        }
    }

    private void Persist()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(_cache);
        var plain = Encoding.UTF8.GetBytes(json);
        var encrypted = ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(_storePath, encrypted);

        // Zera os bytes em memória após persistir
        CryptographicOperations.ZeroMemory(plain);
    }
}
