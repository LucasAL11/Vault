using Application.Abstractions.Data;
using Application.Abstractions.Security;
using Application.Authentication;
using Microsoft.EntityFrameworkCore;
using Infrastructure.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Api.Endpoints.Operations;

public sealed class KeyProviderOperations : IEndpoint
{
    private sealed record RotateRequest(string KeyId);
    private sealed record ReEncryptRequest(Guid VaultId, string SecretName, bool IncludeRevoked = false, bool IncludeExpired = false);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapGet("/ops/key-provider", async (
            IKeyProvider keyProvider,
            IAuthorizationService authorizationService,
            IOptionsMonitor<KeyProviderOptions> optionsMonitor,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (!await CanOperateAsync(authorizationService, optionsMonitor.CurrentValue.OperatorsGroup, httpContext))
            {
                return Results.Forbid();
            }

            var current = await keyProvider.GetCurrentKeyAsync(cancellationToken);
            var knownIds = await keyProvider.GetKnownKeyIdsAsync(cancellationToken);

            return Results.Ok(new
            {
                Mode = optionsMonitor.CurrentValue.Mode,
                CurrentKeyId = current.KeyId,
                KnownKeyIds = knownIds
            });
        }).RequireAuthorization();

        builder.MapPost("/ops/key-provider/rotate", async (
            RotateRequest request,
            IKeyProvider keyProvider,
            IApplicationDbContext dbContext,
            IAuthorizationService authorizationService,
            IOptionsMonitor<KeyProviderOptions> optionsMonitor,
            IUserContext userContext,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (!await CanOperateAsync(authorizationService, optionsMonitor.CurrentValue.OperatorsGroup, httpContext))
            {
                return Results.Forbid();
            }

            if (string.IsNullOrWhiteSpace(request.KeyId))
            {
                return Results.BadRequest(new { message = "keyId is required." });
            }

            var rotated = await keyProvider.RotateCurrentKeyAsync(request.KeyId, cancellationToken);
            var knownIds = await keyProvider.GetKnownKeyIdsAsync(cancellationToken);
            
            await dbContext.SecretAuditEntries.AddAsync(
                new Domain.vault.SecretAuditEntry(
                    vaultId: null,
                    secretName: null,
                    action: "KEY_ROTATE",
                    actor: userContext.Identity.ToString(),
                    occurredAtUtc: DateTimeOffset.UtcNow,
                    details: $"currentKeyId={rotated.KeyId}"),
                cancellationToken);
            await dbContext.SaveChangesAsync(cancellationToken);

            return Results.Ok(new
            {
                CurrentKeyId = rotated.KeyId,
                KnownKeyIds = knownIds
            });
        }).RequireAuthorization();

        builder.MapPost("/ops/key-provider/re-encrypt", async (
            ReEncryptRequest request,
            IKeyProvider keyProvider,
            ISecretProtector secretProtector,
            IApplicationDbContext dbContext,
            IAuthorizationService authorizationService,
            IOptionsMonitor<KeyProviderOptions> optionsMonitor,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<KeyProviderOperations> logger,
            CancellationToken cancellationToken) =>
        {
            if (!await CanOperateAsync(authorizationService, optionsMonitor.CurrentValue.OperatorsGroup, httpContext))
            {
                return Results.Forbid();
            }

            if (string.IsNullOrWhiteSpace(request.SecretName))
            {
                return Results.BadRequest(new { message = "secretName is required." });
            }

            var secret = await dbContext.Secrets
                .SingleOrDefaultAsync(x => x.VaultId == request.VaultId && x.Name == request.SecretName, cancellationToken);

            if (secret is null)
            {
                return Results.NotFound(new { message = "Secret was not found." });
            }

            var versions = await dbContext.SecretVersions
                .Where(x => x.SecretId == secret.Id)
                .OrderBy(x => x.Version)
                .ToListAsync(cancellationToken);

            if (versions.Count == 0)
            {
                return Results.NotFound(new { message = "Secret has no versions." });
            }

            var currentKey = await keyProvider.GetCurrentKeyAsync(cancellationToken);
            var rotatedCount = 0;

            foreach (var version in versions)
            {
                if (!request.IncludeRevoked && version.IsRevoked)
                {
                    continue;
                }

                if (!request.IncludeExpired && version.Expires.HasValue && version.Expires.Value <= DateTimeOffset.UtcNow)
                {
                    continue;
                }

                if (string.Equals(version.KeyReference, currentKey.KeyId, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var context = new SecretProtectionContext(request.VaultId, secret.Id, version.Version);

                var plaintext = await secretProtector.UnprotectAsync(
                    new ProtectedSecret(version.CipherText, version.Nonce, version.KeyReference),
                    context,
                    cancellationToken);

                var reProtected = await secretProtector.ProtectAsync(plaintext, context, cancellationToken);
                version.ReEncrypt(reProtected.CipherText, reProtected.Nonce, reProtected.KeyId);
                rotatedCount++;
            }

            if (rotatedCount > 0)
            {
                await dbContext.SaveChangesAsync(cancellationToken);
            }

            await dbContext.SecretAuditEntries.AddAsync(
                new Domain.vault.SecretAuditEntry(
                    vaultId: request.VaultId,
                    secretName: request.SecretName,
                    action: "SECRET_REENCRYPT",
                    actor: userContext.Identity.ToString(),
                    occurredAtUtc: DateTimeOffset.UtcNow,
                    details: $"rotatedCount={rotatedCount};currentKeyId={currentKey.KeyId}"),
                cancellationToken);
            await dbContext.SaveChangesAsync(cancellationToken);

            logger.LogInformation(
                "Secret re-encrypt completed. VaultId={VaultId}, SecretName={SecretName}, RotatedCount={RotatedCount}, CurrentKeyId={CurrentKeyId}, User={User}",
                request.VaultId,
                request.SecretName,
                rotatedCount,
                currentKey.KeyId,
                httpContext.User.Identity?.Name);

            return Results.Ok(new
            {
                request.VaultId,
                request.SecretName,
                RotatedCount = rotatedCount,
                CurrentKeyId = currentKey.KeyId
            });
        }).RequireAuthorization();
    }

    private static async Task<bool> CanOperateAsync(
        IAuthorizationService authorizationService,
        string? operatorsGroup,
        HttpContext httpContext)
    {
        if (string.IsNullOrWhiteSpace(operatorsGroup))
        {
            return false;
        }

        var policy = $"AdGroup:{operatorsGroup}";
        var result = await authorizationService.AuthorizeAsync(httpContext.User, policy);
        return result.Succeeded;
    }
}
