using Application.Abstractions.Data;
using Microsoft.EntityFrameworkCore;

namespace Api.Endpoints.Users;

public sealed class ListUsers : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/users/list", async (
            IApplicationDbContext dbContext,
            CancellationToken ct) =>
        {
            var users = await dbContext.Users
                .Select(u => new
                {
                    u.Id,
                    UserName = u.UserName.UserName,
                    u.FirstName,
                    u.LastName
                })
                .OrderBy(u => u.UserName)
                .ToListAsync(ct);

            return Results.Ok(users);
        }).RequireAuthorization();
    }
}
