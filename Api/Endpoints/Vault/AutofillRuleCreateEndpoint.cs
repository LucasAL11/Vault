using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.AutofillRules.Create;
using Microsoft.AspNetCore.Authorization;

namespace Api.Endpoints.Vault;

public sealed class AutofillRuleCreateEndpoint : IEndpoint
{
    private sealed record CreateAutofillRuleRequest(string UrlPattern, string Login, string SecretName, bool IsActive = true);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPost("/vaults/{vaultId:guid}/autofill-rules", async (
                Guid vaultId,
                CreateAutofillRuleRequest request,
                IMessageDispatcher sender,
                IAuthorizationService authorizationService,
                IUserContext userContext,
                HttpContext httpContext,
                ILogger<AutofillRuleCreateEndpoint> logger,
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
                    new CreateAutofillRuleCommand(vaultId, request.UrlPattern, request.Login, request.SecretName, request.IsActive),
                    cancellationToken);
                if (result.IsFailure)
                {
                    return CustomResults.Problem(result);
                }

                logger.LogInformation(
                    "Autofill rule created. VaultId={VaultId}, RuleId={RuleId}, UrlPattern={UrlPattern}, User={User}",
                    vaultId,
                    result.Value.Id,
                    result.Value.UrlPattern,
                    userContext.Identity.ToString());

                return Results.Created($"/vaults/{vaultId}/autofill-rules/{result.Value.Id}", result.Value);
            }).RequireAuthorization()
            .WithTags("autofill");
    }
}
