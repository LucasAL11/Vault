using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.AutofillRules;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class AutofillRuleUpdateEndpoint : IEndpoint
{
    private sealed record UpdateAutofillRuleRequest(string UrlPattern, string Login, string SecretName, bool IsActive);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPut("/vaults/{vaultId:guid}/autofill-rules/{ruleId:guid}", async (
            Guid vaultId,
            Guid ruleId,
            UpdateAutofillRuleRequest request,
            IMessageDispatcher sender,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<AutofillRuleUpdateEndpoint> logger,
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
                new UpdateAutofillRuleCommand(vaultId, ruleId, request.UrlPattern, request.Login, request.SecretName, request.IsActive),
                cancellationToken);
            if (result.IsFailure)
            {
                return CustomResults.Problem(result);
            }

            logger.LogInformation(
                "Autofill rule updated. VaultId={VaultId}, RuleId={RuleId}, UrlPattern={UrlPattern}, User={User}",
                vaultId,
                ruleId,
                result.Value.UrlPattern,
                userContext.Identity.ToString());

            return Results.Ok(result.Value);
        }).RequireAuthorization("AdminPolicy")
            .WithTags("autofill");
    }
}
