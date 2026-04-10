using Api.Infrastructure;
using Application.Abstractions.Data;
using Microsoft.EntityFrameworkCore;

namespace Api.Endpoints.Vault;

public class VaultListEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/vaults", async (IApplicationDbContext db) =>
        {
            var vaults = await db.Vaults
                .Where(v => v.Status == Domain.vault.Status.Active)
                .OrderBy(v => v.Name)
                .Select(v => new
                {
                    v.Id,
                    v.Name,
                    v.Slug,
                    v.Description,
                    v.TenantId,
                    v.Group,
                    Environment = v.Environment.ToString(),
                    Status = v.Status.ToString()
                })
                .ToListAsync();

            return Results.Ok(vaults);
        }).RequireAuthorization("AdminPolicy");
    }
}
