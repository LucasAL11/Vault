using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.Machines;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class MachineCreateEndpoint : IEndpoint
{
    private sealed record CreateMachineRequest(int ComputerId);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/vaults/{vaultId:guid}/machines", async (
            Guid vaultId,
            CreateMachineRequest request,
            IMessageDispatcher sender,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<MachineCreateEndpoint> logger,
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

            var result = await sender.Send(new CreateMachineCommand(vaultId, request.ComputerId), cancellationToken);
            if (result.IsFailure)
            {
                return CustomResults.Problem(result);
            }

            var machine = result.Value;
            logger.LogInformation(
                "Machine linked to vault. VaultId={VaultId}, MachineId={MachineId}, ComputerId={ComputerId}, User={User}",
                vaultId,
                machine.Id,
                machine.ComputerId,
                userContext.Identity.ToString());

            return Results.Created($"/vaults/{vaultId}/machines/{machine.Id}", machine);
        }).RequireAuthorization();
    }
}
