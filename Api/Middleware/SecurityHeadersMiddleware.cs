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
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;

            SetHeaderIfMissing(headers, "X-Content-Type-Options", "nosniff");
            SetHeaderIfMissing(headers, "X-Frame-Options", _options.XFrameOptions);
            SetHeaderIfMissing(headers, "Referrer-Policy", _options.ReferrerPolicy);
            SetHeaderIfMissing(headers, "Permissions-Policy", _options.PermissionsPolicy);
            SetHeaderIfMissing(headers, "Content-Security-Policy", _options.ContentSecurityPolicy);
            SetHeaderIfMissing(headers, "Cross-Origin-Opener-Policy", _options.CrossOriginOpenerPolicy);
            SetHeaderIfMissing(headers, "Cross-Origin-Resource-Policy", _options.CrossOriginResourcePolicy);
            SetHeaderIfMissing(headers, "X-Permitted-Cross-Domain-Policies", _options.XPermittedCrossDomainPolicies);

            return Task.CompletedTask;
        });

        await next(context);
    }

    private static void SetHeaderIfMissing(IHeaderDictionary headers, string name, string value)
    {
        if (string.IsNullOrWhiteSpace(value) || headers.ContainsKey(name))
        {
            return;
        }

        headers[name] = value;
    }
}
