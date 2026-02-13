using Api.Endpoints;
using Application.Authentication;

namespace Api.Endpoints.Users;

public sealed class UserGroups : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/users/groups", (IUserContext userContext) =>
        {
            var groups = userContext.Groups
                .Select(group => group.Name)
                .OrderBy(name => name)
                .ToArray();

            return Results.Ok(new
            {
                User = userContext.Identity.ToString(),
                Groups = groups
            });
        }).RequireAuthorization();
    }
}
