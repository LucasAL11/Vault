using System.Diagnostics;
using Api.Observability;
using Microsoft.AspNetCore.Routing;

namespace Api.Middleware;

public sealed class SecurityMetricsMiddleware(RequestDelegate next)
{
    public async Task Invoke(HttpContext context, SecurityMetrics securityMetrics)
    {
        var domain = ResolveDomain(context.Request.Path);
        if (domain is null)
        {
            await next(context);
            return;
        }

        var startedAt = Stopwatch.GetTimestamp();
        await next(context);
        var elapsedMs = Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds;

        var route = (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? context.Request.Path.Value ?? "unknown";

        securityMetrics.Track(
            domain,
            context.Request.Method,
            route,
            context.Response.StatusCode,
            elapsedMs);
    }

    private static string? ResolveDomain(PathString path)
    {
        var value = path.Value;
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (value.Contains("/users", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("/auth/", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("/debug/auth", StringComparison.OrdinalIgnoreCase))
        {
            return "auth";
        }

        if (value.Contains("/cryptography/", StringComparison.OrdinalIgnoreCase))
        {
            return "zk";
        }

        if (value.Contains("/vaults/", StringComparison.OrdinalIgnoreCase) &&
            value.Contains("/secrets", StringComparison.OrdinalIgnoreCase))
        {
            return "secrets";
        }

        return null;
    }
}
