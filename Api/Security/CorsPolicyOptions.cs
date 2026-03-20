namespace Api.Security;

public sealed class CorsPolicyOptions
{
    public string[] AllowedOrigins { get; set; } = [];
    public string[] AllowedMethods { get; set; } = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
    public string[] AllowedHeaders { get; set; } = ["Authorization", "Content-Type", "X-Requested-With", "X-Correlation-Id", "X-Trace-Id"
    ];
    public string[] ExposedHeaders { get; set; } = ["X-Correlation-Id", "X-Trace-Id", "X-API-Version", "Retry-After"];
    public bool AllowCredentials { get; set; }
}
