using Domain.KillSwitch;
using Application.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Operations;

public sealed class KillSwitchOperations : IEndpoint
{
    private sealed record Response(bool Enabled, string? AllowedGroup, int? RetryAfterSeconds, string? Message);
    private sealed record DenylistAddRequest(string Username, int DurationMinutes, string? Reason);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/ops/killswitch", async (
            KillSwitchState state,
            IAuthorizationService authorizationService,
            HttpContext httpContext) =>
        {
            var current = state.Current;

            if (!await CanOperateAsync(current, authorizationService, httpContext))
            {
                return Results.Json(new
                {
                    message = "Forbidden: user is not in the AD group allowed to operate the kill switch."
                }, statusCode: StatusCodes.Status403Forbidden);
            }

            return Results.Ok(new
            {
                current.Enabled,
                current.AllowedGroup,
                current.RetryAfterSeconds,
                current.Message,
                current.DenyUsers
            });
        }).RequireAuthorization().RequireRateLimiting("OpsSensitivePolicy");

        builder.MapPost("/ops/killswitch", async (
            Response response,
            KillSwitchState state,
            IAuthorizationService authorizationService,
            HttpContext httpContext) =>
        {
            var current = state.Current;

            if (!await CanOperateAsync(current, authorizationService, httpContext))
            {
                return Results.Json(new
                {
                    message = "Forbidden: user is not in the AD group allowed to operate the kill switch."
                }, statusCode: StatusCodes.Status403Forbidden);
            }

            state.Set(response.Enabled, response.AllowedGroup, response.RetryAfterSeconds, response.Message);
            current = state.Current;

            return Results.Ok(new
            {
                current.Enabled,
                current.AllowedGroup,
                current.RetryAfterSeconds,
                current.Message,
                current.DenyUsers
            });
        }).RequireAuthorization().RequireRateLimiting("OpsSensitivePolicy");

        builder.MapGet("/ops/killswitch/debug", async (
            KillSwitchState state,
            IUserContext userContext,
            IAuthorizationService authorizationService,
            HttpContext httpContext) =>
        {
            var current = state.Current;
            var canOperate = await CanOperateAsync(current, authorizationService, httpContext);

            return Results.Ok(new
            {
                userContext.Identity.Domain,
                userContext.Identity.Username,
                requiredGroup = current.AllowedGroup,
                canOperate
            });
        }).RequireAuthorization().RequireRateLimiting("OpsSensitivePolicy");

        builder.MapGet("/ops/killswitch/denylist", async (
            KillSwitchState state,
            IAuthorizationService authorizationService,
            HttpContext httpContext) =>
        {
            var current = state.Current;

            if (!await CanOperateAsync(current, authorizationService, httpContext))
            {
                return Results.Json(new
                {
                    message = "Forbidden: user is not in the AD group allowed to operate the kill switch."
                }, statusCode: StatusCodes.Status403Forbidden);
            }

            return Results.Ok(current.DenyUsers);
        }).RequireAuthorization().RequireRateLimiting("OpsSensitivePolicy");

        builder.MapPost("/ops/killswitch/denylist", async (
            DenylistAddRequest request,
            KillSwitchState state,
            IAuthorizationService authorizationService,
            HttpContext httpContext) =>
        {
            var current = state.Current;

            if (!await CanOperateAsync(current, authorizationService, httpContext))
            {
                return Results.Json(new
                {
                    message = "Forbidden: user is not in the AD group allowed to operate the kill switch."
                }, statusCode: StatusCodes.Status403Forbidden);
            }

            if (string.IsNullOrWhiteSpace(request.Username))
            {
                return Results.BadRequest(new { message = "Username is required." });
            }

            if (request.DurationMinutes <= 0 || request.DurationMinutes > 7 * 24 * 60)
            {
                return Results.BadRequest(new { message = "DurationMinutes must be between 1 and 10080." });
            }

            var expiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(request.DurationMinutes);
            state.AddOrUpdateDeniedUser(request.Username, expiresAtUtc, request.Reason);

            return Results.Ok(new
            {
                username = request.Username,
                expiresAtUtc,
                request.Reason
            });
        }).RequireAuthorization().RequireRateLimiting("OpsSensitivePolicy");

        builder.MapDelete("/ops/killswitch/denylist/{username}", async (
            string username,
            KillSwitchState state,
            IAuthorizationService authorizationService,
            HttpContext httpContext) =>
        {
            var current = state.Current;

            if (!await CanOperateAsync(current, authorizationService, httpContext))
            {
                return Results.Json(new
                {
                    message = "Forbidden: user is not in the AD group allowed to operate the kill switch."
                }, statusCode: StatusCodes.Status403Forbidden);
            }

            var removed = state.RemoveDeniedUser(username);
            return Results.Ok(new { username, removed });
        }).RequireAuthorization().RequireRateLimiting("OpsSensitivePolicy");
    }

    private static async Task<bool> CanOperateAsync(
        KillSwitchSnapshot snapshot,
        IAuthorizationService authorizationService,
        HttpContext httpContext)
    {
        if (string.IsNullOrWhiteSpace(snapshot.AllowedGroup))
        {
            return false;
        }

        var policyName = $"AdGroup:{snapshot.AllowedGroup}";
        var authorization = await authorizationService.AuthorizeAsync(httpContext.User, policyName);
        return authorization.Succeeded;
    }
}

//@Todo melhorar logs Retornando result corretamente.
//retornar 
