using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Vault.AdMaps;
using Domain.vault;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class AdMapListEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/vaults/{vaultId:guid}/ad-maps", async (
            Guid vaultId,
            bool? includeInactive,
            VaultPermission? permission,
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

            var result = await sender.Send(
                new ListAdMapsQuery(vaultId, includeInactive ?? false, permission),
                cancellationToken);
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
        }).RequireAuthorization("AdminPolicy");
    }
}
