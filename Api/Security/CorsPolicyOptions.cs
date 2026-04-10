namespace Api.Security;

public sealed class CorsPolicyOptions
{
    public string[] AllowedOrigins { get; set; } = [];
    public string[] AllowedMethods { get; set; } = ["GET", "POST", "PUT", "DELETE", "OPTIONS"];
    public string[] AllowedHeaders { get; set; } = ["Authorization", "Content-Type", "X-Requested-With", "X-Correlation-Id", "X-Trace-Id"];
    public string[] ExposedHeaders { get; set; } = ["X-Correlation-Id", "X-Trace-Id", "X-API-Version", "Retry-After"];
    public bool AllowCredentials { get; set; }
    public int PreflightMaxAgeSeconds { get; set; } = 600;

    public CorsPolicyOptions GetNormalized()
    {
        return new CorsPolicyOptions
        {
            AllowedOrigins = NormalizeOrigins(AllowedOrigins),
            AllowedMethods = NormalizeTokens(AllowedMethods, ["GET", "POST", "PUT", "DELETE", "OPTIONS"]),
            AllowedHeaders = NormalizeTokens(AllowedHeaders, ["Authorization", "Content-Type", "X-Requested-With", "X-Correlation-Id", "X-Trace-Id"]),
            ExposedHeaders = NormalizeTokens(ExposedHeaders, []),
            AllowCredentials = AllowCredentials,
            PreflightMaxAgeSeconds = Math.Clamp(PreflightMaxAgeSeconds, 0, 86_400)
        };
    }

    private static string[] NormalizeOrigins(string[]? values)
    {
        if (values is null || values.Length == 0)
        {
            return [];
        }

        var hasWildcard = values.Any(x => string.Equals(x?.Trim(), "*", StringComparison.Ordinal));
        if (hasWildcard)
        {
            return ["*"];
        }

        return values
            .Where(static x => !string.IsNullOrWhiteSpace(x))
            .Select(static x => NormalizeOrigin(x.Trim()))
            .Where(static x => x is not null)
            .Select(static x => x!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string[] NormalizeTokens(string[]? values, string[] fallback)
    {
        var normalized = (values ?? [])
            .Where(static x => !string.IsNullOrWhiteSpace(x))
            .Select(static x => x.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return normalized.Length > 0 ? normalized : fallback;
    }

    private static string? NormalizeOrigin(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return null;
        }

        if (uri.Scheme is not ("http" or "https"))
        {
            return null;
        }

        return uri.GetLeftPart(UriPartial.Authority);
    }
}
