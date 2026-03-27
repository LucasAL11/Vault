using System.Text;
using System.Text.Json;

namespace VaultClient.Desktop.Core;

/// <summary>
/// Extrai claims do JWT localmente (sem validar assinatura — validação é no servidor).
/// Usado apenas para mostrar/esconder UI com base nos grupos do usuário.
/// </summary>
internal static class JwtHelper
{
    /// <summary>Verifica se o JWT contém o grupo "Admins" nas claims role ou groups.</summary>
    internal static bool IsAdmin(string? jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
            return false;

        try
        {
            var claims = ParsePayload(jwt);
            return HasClaim(claims, "role", "Admins")
                || HasClaim(claims, "groups", "Admins")
                || HasClaim(claims,
                    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
                    "Admins");
        }
        catch
        {
            return false;
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

    private static JsonElement ParsePayload(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2)
            throw new FormatException("JWT inválido.");

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
