using Application.Authentication;
using Domain.KillSwitch;

namespace Api.Middleware;

public sealed class KillSwitchMiddleware : IMiddleware
{
    private static readonly PathString[] OperationalPaths =
    [
        new("/health"),
        new("/ops/killswitch"),
        new("/ops/key-provider")
    ];

    private readonly KillSwitchState _state;
    private readonly IUserContext _userContext;
    private readonly ILogger<KillSwitchMiddleware> _logger;

    public KillSwitchMiddleware(
        KillSwitchState state,
        IUserContext userContext,
        ILogger<KillSwitchMiddleware> logger)
    {
        _state = state;
        _userContext = userContext;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var config = _state.Current;

        if (IsOperationalPath(context.Request.Path))
        {
            await next(context);
            return;
        }

        var username = _userContext.Identity.Username;
        if (_state.TryGetDeniedUser(username, out var denyUser))
        {
            _logger.LogWarning(
                "Denylist blocked request. Path={Path}, User={User}, ExpiresAtUtc={ExpiresAtUtc}, Reason={Reason}",
                context.Request.Path,
                username,
                denyUser!.ExpiresAtUtc,
                denyUser.Reason ?? "<none>");

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                message = "User temporarily blocked by denylist.",
                username = denyUser.Username,
                expiresAtUtc = denyUser.ExpiresAtUtc,
                reason = denyUser.Reason
            });
            return;
        }

        if (!config.Enabled)
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

        _logger.LogWarning(
            "KillSwitch blocked request. Path={Path}, User={User}, AllowedGroup={AllowedGroup}",
            context.Request.Path,
            _userContext.Identity.ToString(),
            config.AllowedGroup ?? "<none>");

        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.Headers.RetryAfter = config.RetryAfterSeconds.ToString();
        await context.Response.WriteAsJsonAsync(new
        {
            message = config.Message,
            retryAfterSeconds = config.RetryAfterSeconds
        });
    }

    private static bool IsOperationalPath(PathString path)
        => OperationalPaths.Any(path.StartsWithSegments);
}
