using System.Security.Claims;

namespace Api.Security;

/// <summary>
/// Extensões de <see cref="ClaimsPrincipal"/> para interpretar grupos AD com convenção
/// <c>admin-vault-{empresa}</c> e derivar escopo de administração por tenant.
///
/// Estas extensões NÃO checam o Admin Geral — para isso use
/// <c>IAuthorizationService.AuthorizeAsync(user, AdGroupPolicyProvider.AdminPolicyName)</c>,
/// que já resolve via configuração <c>Authorization:AdminGroups</c>.
/// </summary>
public static class ClaimsPrincipalExtensions
{
    private const string AdminVaultPrefix = "admin-vault-";

    /// <summary>
    /// Tenants (lowercase) para os quais o usuário é Admin de Cofre, extraídos dos grupos
    /// AD no padrão <c>admin-vault-{tenant}</c>.
    ///
    /// Lê tanto a claim <c>groups</c> quanto <see cref="ClaimTypes.Role"/> porque
    /// <c>JwtTokenProvider.Create</c> emite ambas para cada grupo AD do usuário.
    /// </summary>
    public static IReadOnlySet<string> GetAdminTenants(this ClaimsPrincipal user)
    {
        var tenants = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var claim in user.Claims)
        {
            if (claim.Type != "groups" && claim.Type != ClaimTypes.Role)
            {
                continue;
            }

            var normalized = NormalizeGroupName(claim.Value);
            if (normalized.StartsWith(AdminVaultPrefix, StringComparison.Ordinal) &&
                normalized.Length > AdminVaultPrefix.Length)
            {
                tenants.Add(normalized[AdminVaultPrefix.Length..]);
            }
        }

        return tenants;
    }

    /// <summary>
    /// Verifica se o usuário é Admin de Cofre do tenant informado (caso-insensível).
    /// </summary>
    public static bool IsVaultAdminOf(this ClaimsPrincipal user, string tenantId)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            return false;
        }

        var normalizedTenant = tenantId.Trim().ToLowerInvariant();
        return user.GetAdminTenants().Contains(normalizedTenant);
    }

    /// <summary>
    /// Normaliza o valor de um grupo: remove prefixo <c>DOMAIN\</c>, trim, lowercase.
    /// Mantido consistente com o <c>AdGroupAuthorizationHandler</c> para que
    /// matching leia os grupos do mesmo jeito que o handler de policy.
    /// </summary>
    private static string NormalizeGroupName(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        var trimmed = raw.Trim();
        var backslashIdx = trimmed.IndexOf('\\');
        if (backslashIdx >= 0 && backslashIdx < trimmed.Length - 1)
        {
            trimmed = trimmed[(backslashIdx + 1)..];
        }

        return trimmed.ToLowerInvariant();
    }
}
