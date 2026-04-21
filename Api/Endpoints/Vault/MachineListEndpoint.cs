using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Vault.Machines;
using Domain.vault;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class MachineListEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/vaults/{vaultId:guid}/machines", async (
            Guid vaultId,
            VaultMachineStatus? status,
            IMessageDispatcher sender,
            IAuthorizationService authorizationService,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var authResult = await VaultAuthorization.AuthorizeVaultAdminAsync(
                vaultId,
                sender,
                authorizationService,
                httpContext.User,
                cancellationToken);
            if (authResult.IsFailure)
            {
                return CustomResults.Problem(authResult);
            }

            var result = await sender.Send(new ListMachinesQuery(vaultId, status), cancellationToken);
            if (result.IsFailure)
            {
                return CustomResults.Problem(result);
            }

            return Results.Ok(new
            {
                VaultId = vaultId,
                Count = result.Value.Count,
                Items = result.Value
            });
        }).RequireAuthorization();
    }
}
