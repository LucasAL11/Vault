using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.Machines;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class MachineDeleteEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapDelete("/vaults/{vaultId:guid}/machines/{machineId:guid}", async (
            Guid vaultId,
            Guid machineId,
            IMessageDispatcher sender,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<MachineDeleteEndpoint> logger,
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

            var result = await sender.Send(new DeleteMachineCommand(vaultId, machineId), cancellationToken);
            if (result.IsFailure)
            {
                return CustomResults.Problem(result);
            }

            logger.LogInformation(
                "Machine removed from vault. VaultId={VaultId}, MachineId={MachineId}, User={User}",
                vaultId,
                machineId,
                userContext.Identity.ToString());

            return Results.NoContent();
        }).RequireAuthorization();
    }
}
