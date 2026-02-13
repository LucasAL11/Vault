using Application.Authentication;
using Microsoft.Extensions.Options;

namespace Api.Middleware;

public sealed class KillSwitchMiddleware : IMiddleware
{
    private readonly IOptions<KillSwitchOptions> _options;
    private readonly IUserContext _userContext;

    public KillSwitchMiddleware(IOptions<KillSwitchOptions> options, IUserContext userContext)
    {
        _options = options;
        _userContext = userContext;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var config = _options.Value;
        
        if (!config.Enabled 
            || context.Request.Path.StartsWithSegments("/health"))
        {
            await next(context);
            return;
        }

        if (!string.IsNullOrWhiteSpace(config.AllowedGroup) &&
            _userContext.Groups.Any(g =>
                string.Equals(g.Name, config.AllowedGroup, StringComparison.OrdinalIgnoreCase)))
        {
            await next(context);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.Headers["Retry-After"] = "120";
        await context.Response.WriteAsJsonAsync("Service temporarily unavailable.");
    }
}

public sealed class KillSwitchOptions
{
    public bool Enabled { get; init; }
    public string? AllowedGroup { get; init; }
}

