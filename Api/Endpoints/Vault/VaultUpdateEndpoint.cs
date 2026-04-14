using Api.Extensions;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault;
using Shared;

namespace Api.Endpoints.Vault;

public class VaultUpdateEndpoint : IEndpoint
{
    private record Request(string Name, string? Description);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPut("/vaults/{vaultId:guid}", async (
            Guid vaultId,
            Request request,
            IMessageDispatcher sender,
            IUserContext user) =>
        {
            var command = new UpdateVaultCommand(
                vaultId,
                request.Name,
                request.Description ?? string.Empty,
                Actor: user.Identity.Username);

            Result<UpdateVaultResultDto> result = await sender.Send(command);

            return result.Match(
                dto => Results.Ok(dto),
                CustomResults.Problem);
        }).RequireAuthorization("AdminPolicy");
    }
}
