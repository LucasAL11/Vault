using System.Security.Claims;
using Api.Endpoints;
using Microsoft.AspNetCore.Routing;

namespace Api.Endpoints.Diagnostics;

public sealed class AuthDebug : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/debug/auth", (HttpContext context) =>
        {
            ClaimsPrincipal user = context.User;
            var identity = user.Identity;

            return Results.Ok(new
            {
                IsAuthenticated = identity?.IsAuthenticated ?? false,
                Name = identity?.Name,
                AuthenticationType = identity?.AuthenticationType,
                Claims = user.Claims.Select(c => new { c.Type, c.Value })
            });
        }).RequireAuthorization();
    }
}
