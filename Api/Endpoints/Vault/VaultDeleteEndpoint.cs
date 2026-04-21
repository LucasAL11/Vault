using Api.Extensions;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault;
using Microsoft.AspNetCore.Authorization;
using Shared;

namespace Api.Endpoints.Vault;

public class VaultDeleteEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapDelete("/vaults/{vaultId:guid}", async (
            Guid vaultId,
            IMessageDispatcher sender,
            IAuthorizationService authorizationService,
            IUserContext user,
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

            var command = new DeleteVaultCommand(vaultId, Actor: user.Identity.Username);

            Result<DeleteVaultResultDto> result = await sender.Send(command, cancellationToken);

            return result.Match(
                dto => Results.Ok(dto),
                CustomResults.Problem);
        }).RequireAuthorization();
    }
}
