using System.Text;
using System.Text.Json;

namespace VaultClient.Desktop.Core;

/// <summary>
/// Extrai claims do JWT localmente (sem validar assinatura — validacao e no servidor).
/// Usado apenas para mostrar/esconder UI com base nos grupos do usuario.
/// </summary>
internal static class JwtHelper
{
    /// <summary>Default admin groups — overridden by appsettings or server config.</summary>
    private static string[] _adminGroupNames =
    [
        "Admins",
        "Admin",
        "Administrators",
        "Domain Admins",
        "Administradores",
        "Administradores de Chaves"
    ];

    /// <summary>
    /// Configures the admin group names from external config (appsettings or server).
    /// Call this at startup or when config changes.
    /// </summary>
    internal static void ConfigureAdminGroups(string[]? groups)
    {
        if (groups is { Length: > 0 })
            _adminGroupNames = groups;
    }

    /// <summary>Verifica se o JWT contem um grupo de admin nas claims role ou groups.</summary>
    internal static bool IsAdmin(string? jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
            return false;

        try
        {
            var claims = ParsePayload(jwt);
            foreach (var group in _adminGroupNames)
            {
                if (HasClaim(claims, "role", group)
                    || HasClaim(claims, "groups", group)
                    || HasClaim(claims,
                        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
                        group))
                    return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Verifica se o JWT contem pelo menos um grupo no formato <c>admin-vault-{tenant}</c>,
    /// indicando que o usuario e Admin de Cofre (multi-empresa).
    /// </summary>
    internal static bool IsVaultAdmin(string? jwt)
        => GetAdminTenants(jwt).Count > 0;

    /// <summary>
    /// Retorna os tenant IDs extraidos dos grupos <c>admin-vault-{tenant}</c> presentes no JWT.
    /// </summary>
    internal static IReadOnlyList<string> GetAdminTenants(string? jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
            return [];

        try
        {
            var claims = ParsePayload(jwt);
            var tenants = new List<string>();

            foreach (var claimName in ClaimNames)
            {
                if (!claims.TryGetProperty(claimName, out var prop)) continue;

                if (prop.ValueKind == JsonValueKind.String)
                    TryExtractTenant(prop.GetString(), tenants);
                else if (prop.ValueKind == JsonValueKind.Array)
                    foreach (var item in prop.EnumerateArray())
                        if (item.ValueKind == JsonValueKind.String)
                            TryExtractTenant(item.GetString(), tenants);
            }

            return tenants;
        }
        catch
        {
            return [];
        }
    }

    /// <summary>Retorna todos os grupos do JWT (para debug).</summary>
    internal static IReadOnlyList<string> GetGroups(string? jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
            return [];

        try
        {
            var claims = ParsePayload(jwt);
            var groups = new List<string>();

            foreach (var claimName in new[] { "role", "groups",
                "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" })
            {
                if (!claims.TryGetProperty(claimName, out var prop)) continue;

                if (prop.ValueKind == JsonValueKind.String)
                    groups.Add($"{claimName}={prop.GetString()}");
                else if (prop.ValueKind == JsonValueKind.Array)
                    foreach (var item in prop.EnumerateArray())
                        if (item.ValueKind == JsonValueKind.String)
                            groups.Add($"{claimName}={item.GetString()}");
            }

            return groups;
        }
        catch
        {
            return [];
        }
    }

    /// <summary>Extrai o username (sub ou unique_name) do JWT.</summary>
    internal static string? GetUsername(string? jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
            return null;

        try
        {
            var claims = ParsePayload(jwt);
            if (claims.TryGetProperty("unique_name", out var un))
                return un.GetString();
            if (claims.TryGetProperty("sub", out var sub))
                return sub.GetString();
            if (claims.TryGetProperty(
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", out var name))
                return name.GetString();
            return null;
        }
        catch
        {
            return null;
        }
    }

    private const string VaultAdminPrefix = "admin-vault-";

    private static readonly string[] ClaimNames =
    [
        "role", "groups",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    ];

    private static void TryExtractTenant(string? group, List<string> tenants)
    {
        if (group is null) return;

        // Strip domain prefix (e.g. "PLT\admin-vault-acme" → "admin-vault-acme")
        var normalized = group;
        var bsIdx = normalized.IndexOf('\\');
        if (bsIdx >= 0)
            normalized = normalized[(bsIdx + 1)..];

        if (normalized.StartsWith(VaultAdminPrefix, StringComparison.OrdinalIgnoreCase)
            && normalized.Length > VaultAdminPrefix.Length)
        {
            tenants.Add(normalized[VaultAdminPrefix.Length..].ToLowerInvariant());
        }
    }

    private static JsonElement ParsePayload(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2)
            throw new FormatException("JWT invalido.");

        var payload = parts[1];
        // Fix base64url padding
        payload = payload.Replace('-', '+').Replace('_', '/');
        switch (payload.Length % 4)
        {
            case 2: payload += "=="; break;
            case 3: payload += "=";  break;
        }

        var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
        return JsonDocument.Parse(json).RootElement;
    }

    private static bool HasClaim(JsonElement claims, string claimName, string value)
    {
        if (!claims.TryGetProperty(claimName, out var prop))
            return false;

        if (prop.ValueKind == JsonValueKind.String)
            return string.Equals(prop.GetString(), value, StringComparison.OrdinalIgnoreCase);

        if (prop.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in prop.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String
                    && string.Equals(item.GetString(), value, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }
}
