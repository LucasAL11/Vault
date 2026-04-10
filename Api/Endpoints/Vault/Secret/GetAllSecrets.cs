using Api.Endpoints;
using Api.Infrastructure;
using Application.Abstractions.Messaging.Handlers;
using Application.Authentication;
using Application.Vault.Secrets;
using Domain.vault;
using Shared;

namespace Api.Endpoints.Vault.Secret;

public sealed class GetAllSecrets : IEndpoint
{
    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/vaults/{vaultId:guid}/secrets", async (
            Guid vaultId,
            string? name,
            string? status,
            int? page,
            int? pageSize,
            string? orderBy,
            string? orderDirection,
            IMessageDispatcher sender,
            ISecretAccessAuthorizer secretAccessAuthorizer,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<GetAllSecrets> logger,
            CancellationToken cancellationToken) =>
        {
            httpContext.Response.ApplyNoStoreHeaders();

            var normalizedPage = page ?? 1;
            var normalizedPageSize = pageSize ?? 20;

            if (!SecretQueryHelpers.TryParseStatusFilter(status, out var parsedStatus))
            {
                return Results.BadRequest(new
                {
                    message = $"status is invalid. Allowed values: {string.Join(", ", Enum.GetNames<Status>())}."
                });
            }

            if (!SecretQueryHelpers.TryNormalizeSecretSortBy(orderBy, out var normalizedSortBy))
            {
                return Results.BadRequest(new
                {
                    message = "orderBy is invalid. Allowed values: name, status, currentVersion."
                });
            }

            if (!SecretQueryHelpers.TryNormalizeSortDirection(orderDirection, out var normalizedSortDirection))
            {
                return Results.BadRequest(new
                {
                    message = "orderDirection is invalid. Allowed values: asc, desc."
                });
            }

            var nameFilter = string.IsNullOrWhiteSpace(name) ? null : name.Trim();

            var actor = userContext.Identity.ToString();
            var authorization = await secretAccessAuthorizer.AuthorizeAsync(
                vaultId: vaultId,
                secretName: "*",
                requiredPermission: VaultPermission.Read,
                operation: "list-metadata",
                user: httpContext.User,
                actor: actor,
                cancellationToken: cancellationToken);

            if (authorization.IsNotFound)
            {
                return SecretHttpHelpers.SecureNotFound();
            }

            if (!authorization.IsGranted)
            {
                return SecretHttpHelpers.SecureForbidden();
            }

            var result = await sender.Send(
                new ListSecretsQuery(
                    VaultId: vaultId,
                    Name: nameFilter,
                    Status: parsedStatus,
                    Page: normalizedPage,
                    PageSize: normalizedPageSize,
                    OrderBy: normalizedSortBy,
                    OrderDirection: normalizedSortDirection),
                cancellationToken);

            if (result.IsFailure)
            {
                if (result.Error.Type == ErrorType.NotFound)
                {
                    return SecretHttpHelpers.SecureNotFound();
                }

                return CustomResults.Problem(result);
            }

            var list = result.Value;
            var auditResult = await sender.Send(
                new AppendSecretAuditCommand(
                    VaultId: vaultId,
                    SecretName: null,
                    Action: "SECRET_LIST_METADATA",
                    Actor: actor,
                    Details:
                    $"page={list.Page};pageSize={list.PageSize};returned={list.Items.Count};total={list.TotalCount};name={list.FilterName ?? "-"};status={list.FilterStatus ?? "-"};orderBy={list.OrderBy};orderDirection={list.OrderDirection}"),
                cancellationToken);

            if (auditResult.IsFailure)
            {
                return CustomResults.Problem(auditResult);
            }

            logger.LogInformation(
                "Secret list metadata success. VaultId={VaultId}, Page={Page}, PageSize={PageSize}, Returned={Returned}, Total={Total}, User={User}",
                vaultId,
                list.Page,
                list.PageSize,
                list.Items.Count,
                list.TotalCount,
                actor);

            return Results.Ok(new
            {
                list.VaultId,
                list.Page,
                list.PageSize,
                list.TotalCount,
                list.TotalPages,
                list.OrderBy,
                list.OrderDirection,
                Filters = new
                {
                    Name = list.FilterName,
                    Status = list.FilterStatus
                },
                Items = list.Items
            });
        }).RequireAuthorization().RequireRateLimiting("SecretReadPolicy");
    }
}
