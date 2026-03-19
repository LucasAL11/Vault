namespace Api.Security;

public sealed class CorsPolicyOptions
{
    public string[] AllowedOrigins { get; set; } = Array.Empty<string>();
    public string[] AllowedMethods { get; set; } = new[] { "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS" };
    public string[] AllowedHeaders { get; set; } = new[] { "Authorization", "Content-Type", "X-Requested-With", "X-Correlation-Id" };
    public string[] ExposedHeaders { get; set; } = new[] { "X-Correlation-Id", "Retry-After" };
    public bool AllowCredentials { get; set; }
}
