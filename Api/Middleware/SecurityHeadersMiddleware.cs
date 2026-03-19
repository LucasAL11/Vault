using Api.Security;
using Microsoft.Extensions.Options;

namespace Api.Middleware;

public sealed class SecurityHeadersMiddleware : IMiddleware
{
    private readonly SecurityHeadersOptions _options;

    public SecurityHeadersMiddleware(IOptions<SecurityHeadersOptions> options)
    {
        _options = options.Value;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var headers = context.Response.Headers;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = _options.ReferrerPolicy;
        headers["Permissions-Policy"] = _options.PermissionsPolicy;
        headers["Content-Security-Policy"] = _options.ContentSecurityPolicy;
        headers["Cross-Origin-Opener-Policy"] = "same-origin";

        await next(context);
    }
}
