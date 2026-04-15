using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Vault.AutofillRules;

namespace Api.Endpoints.Vault;

/// <summary>
/// Endpoint usado pela extensão Chrome para encontrar regras de autofill
/// que correspondam à URL atual da página.
/// </summary>
public sealed class AutofillRuleMatchEndpoint : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/autofill-rules/match", async (
            string url,
            IMessageDispatcher sender,
            CancellationToken cancellationToken) =>
        {
            var result = await sender.Send(new MatchAutofillRulesQuery(url), cancellationToken);
            if (result.IsFailure)
            {
                return CustomResults.Problem(result);
            }

            return Results.Ok(new
            {
                url,
                count = result.Value.Count,
                items = result.Value,
            });
        }).RequireAuthorization()
            .WithTags("autofill");
    }
}
