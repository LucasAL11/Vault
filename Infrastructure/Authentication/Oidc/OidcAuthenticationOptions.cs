namespace Infrastructure.Authentication.Oidc;

public sealed class OidcAuthenticationOptions
{
    public bool Enabled { get; set; }
    public string? Authority { get; set; }
    public string? Issuer { get; set; }
    public string? Audience { get; set; }
    public bool RequireHttpsMetadata { get; set; } = true;
    public string RoleClaimType { get; set; } = "groups";
    public string NameClaimType { get; set; } = "name";
}
