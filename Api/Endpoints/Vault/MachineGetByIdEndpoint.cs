using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Vault.Machines;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class MachineGetByIdEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/vaults/{vaultId:guid}/machines/{machineId:guid}", async (
            Guid vaultId,
            Guid machineId,
            IMessageDispatcher sender,
            IAuthorizationService authorizationService,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            var authResult = await VaultAuthorization.AuthorizeVaultAsync(
                vaultId,
                sender,
                authorizationService,
                httpContext.User,
                cancellationToken);
            if (authResult.IsFailure)
            {
                return CustomResults.Problem(authResult);
            }

            var result = await sender.Send(new GetMachineByIdQuery(vaultId, machineId), cancellationToken);
            return result.IsFailure ? CustomResults.Problem(result) : Results.Ok(result.Value);
        }).RequireAuthorization("AdminPolicy");
    }
}
