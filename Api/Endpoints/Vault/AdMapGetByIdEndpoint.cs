using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Vault.AdMaps;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class AdMapGetByIdEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/vaults/{vaultId:guid}/ad-maps/{adMapId:guid}", async (
            Guid vaultId,
            Guid adMapId,
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

            var result = await sender.Send(new GetAdMapByIdQuery(vaultId, adMapId), cancellationToken);
            return result.IsFailure ? CustomResults.Problem(result) : Results.Ok(result.Value);
        }).RequireAuthorization("AdminPolicy");
    }
}
