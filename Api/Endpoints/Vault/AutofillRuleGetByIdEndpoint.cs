using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Vault.AutofillRules;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class AutofillRuleGetByIdEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/vaults/{vaultId:guid}/autofill-rules/{ruleId:guid}", async (
            Guid vaultId,
            Guid ruleId,
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
                new GetAutofillRuleByIdQuery(vaultId, ruleId),
                cancellationToken);
            if (result.IsFailure)
            {
                return CustomResults.Problem(result);
            }

            return Results.Ok(result.Value);
        }).RequireAuthorization("AdminPolicy")
            .WithTags("autofill");
    }
}
