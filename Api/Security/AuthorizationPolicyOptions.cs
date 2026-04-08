namespace Api.Security;

public sealed class AuthorizationPolicyOptions
{
    /// <summary>
    /// AD group names that grant full admin access (vault creation, user management, etc.).
    /// Configurable via appsettings.json: Authorization:AdminGroups
    /// </summary>
    public string[] AdminGroups { get; set; } = ["Admins", "Admin", "Administrators"];

    /// <summary>
    /// When true, skips AD group checks entirely (useful for local-only auth dev scenarios).
    /// All authenticated users are treated as admins.
    /// </summary>
    public bool BypassAdGroupCheck { get; set; }
}
