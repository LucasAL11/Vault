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
            // Materializa primeiro (tabela pequena), depois projeta no client
            var users = await dbContext.Users.ToListAsync(ct);

            var result = users
                .OrderBy(u => u.UserName.UserName)
                .Select(u => new
                {
                    u.Id,
                    UserName = u.UserName.UserName,
                    u.FirstName,
                    u.LastName
                })
                .ToList();

            return Results.Ok(result);
        }).RequireAuthorization();
    }
}
