using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.Machines;
using Domain.vault;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class MachineUpdateEndpoint : IEndpoint
{
    private sealed record UpdateMachineRequest(VaultMachineStatus Status);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPut("/vaults/{vaultId:guid}/machines/{machineId:guid}", async (
            Guid vaultId,
            Guid machineId,
            UpdateMachineRequest request,
            IMessageDispatcher sender,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<MachineUpdateEndpoint> logger,
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

            var result = await sender.Send(new UpdateMachineCommand(vaultId, machineId, request.Status), cancellationToken);
            if (result.IsFailure)
            {
                return CustomResults.Problem(result);
            }

            logger.LogInformation(
                "Machine status updated. VaultId={VaultId}, MachineId={MachineId}, Status={Status}, User={User}",
                vaultId,
                machineId,
                result.Value.Status,
                userContext.Identity.ToString());

            return Results.Ok(result.Value);
        }).RequireAuthorization();
    }
}
