using Api.Infrastructure;
using Api.Security;
using Application.Abstractions.Data;
using Infrastructure.Authentication.ActiveDirectory;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace Api.Endpoints.Vault;

public class VaultListEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/vaults", async (
                IApplicationDbContext db,
                IAuthorizationService authorizationService,
                HttpContext httpContext) =>
            {
                var user = httpContext.User;

                // Admin Geral vê todos os cofres; Admin de Cofre vê apenas os do(s) seu(s) tenant(s);
                // demais usuários recebem 403 (listagem é operação administrativa).
                var isGlobalAdmin = (await authorizationService
                    .AuthorizeAsync(user, AdGroupPolicyProvider.AdminPolicyName)).Succeeded;
                var adminTenants = user.GetAdminTenants();

                if (!isGlobalAdmin && adminTenants.Count == 0)
                {
                    return Results.Forbid();
                }

                var query = db.Vaults.Where(v => v.Status == Domain.vault.Status.Active);

                if (!isGlobalAdmin)
                {
                    // Npgsql traduz string.ToLower() para LOWER() no SQL — match case-insensitive
                    // com os tenants extraídos de admin-vault-{tenant}.
                    query = query.Where(v => adminTenants.Contains(v.TenantId.ToLower()));
                }

                var vaults = await query
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
            }).RequireAuthorization();
    }
}
