using Api.Extensions;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault;
using Microsoft.AspNetCore.Authorization;
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

            var command = new UpdateVaultCommand(
                vaultId,
                request.Name,
                request.Description ?? string.Empty,
                Actor: user.Identity.Username);

            Result<UpdateVaultResultDto> result = await sender.Send(command, cancellationToken);

            return result.Match(
                dto => Results.Ok(dto),
                CustomResults.Problem);
        }).RequireAuthorization();
    }
}
