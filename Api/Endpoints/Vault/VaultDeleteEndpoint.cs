using Api.Extensions;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault;
using Shared;

namespace Api.Endpoints.Vault;

public class VaultDeleteEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapDelete("/vaults/{vaultId:guid}", async (
            Guid vaultId,
            IMessageDispatcher sender,
            IUserContext user) =>
        {
            var command = new DeleteVaultCommand(vaultId, Actor: user.Identity.Username);

            Result<DeleteVaultResultDto> result = await sender.Send(command);

            return result.Match(
                dto => Results.Ok(dto),
                CustomResults.Problem);
        }).RequireAuthorization("AdminPolicy");
    }
}
