using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.AutofillRules;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class AutofillRuleDeleteEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapDelete("/vaults/{vaultId:guid}/autofill-rules/{ruleId:guid}", async (
            Guid vaultId,
            Guid ruleId,
            IMessageDispatcher sender,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<AutofillRuleDeleteEndpoint> logger,
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

            var result = await sender.Send(new DeleteAutofillRuleCommand(vaultId, ruleId), cancellationToken);
            if (result.IsFailure)
            {
                return CustomResults.Problem(result);
            }

            logger.LogInformation(
                "Autofill rule removed. VaultId={VaultId}, RuleId={RuleId}, User={User}",
                vaultId,
                ruleId,
                userContext.Identity.ToString());

            return Results.NoContent();
        }).RequireAuthorization("AdminPolicy")
            .WithTags("autofill");
    }
}
