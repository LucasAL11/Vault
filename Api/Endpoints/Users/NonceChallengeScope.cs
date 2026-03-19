namespace Api.Endpoints.Users;

internal static class NonceChallengeScope
{
    public static string Build(HttpContext httpContext, string? clientId)
    {
        var normalizedClientId = string.IsNullOrWhiteSpace(clientId)
            ? "anonymous"
            : clientId.Trim();
        var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown-ip";
        return $"auth-challenge:{normalizedClientId}:{ip}";
    }
}
