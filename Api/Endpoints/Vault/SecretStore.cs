using Application.Abstractions.Data;
using Application.Abstractions.Security;
using Application.Authentication;
using Domain.vault;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace Api.Endpoints.Vault;

public sealed class SecretStore : IEndpoint
{
    private sealed record UpsertRequest(string Value, string? ContentType, DateTimeOffset? ExpiresUtc);
    private sealed record AuditEntryResponse(string Action, string Actor, DateTimeOffset OccurredAtUtc, string? Details);

    public void MapEndpoint(IEndpointRouteBuilder builder)
    {
        builder.MapPut("/vaults/{vaultId:guid}/secrets/{name}", async (
            Guid vaultId,
            string name,
            UpsertRequest request,
            IApplicationDbContext dbContext,
            ISecretProtector secretProtector,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<SecretStore> logger,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            if (string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { message = "Secret name is required." });
            }

            if (string.IsNullOrWhiteSpace(request.Value))
            {
                return Results.BadRequest(new { message = "Secret value is required." });
            }
            
            var vault = await dbContext.Vaults
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.Id == vaultId, cancellationToken);

            if (vault is null)
            {
                logger.LogWarning("Secret write denied: vault not found. VaultId={VaultId}, User={User}", vaultId, userContext.Identity.ToString());
                return Results.NotFound(new { message = "Vault was not found." });
            }

            if (!await AuthorizeVaultPolicyAsync(vault.Group, authorizationService, httpContext.User, userContext, logger, vaultId, "write"))
            {
                return Results.Forbid();
            }

            var secret = await dbContext.Secrets
                .Include(x => x.Versions)
                .SingleOrDefaultAsync(x => x.VaultId == vaultId && x.Name == name, cancellationToken);

            if (secret is null)
            {
                secret = new Secret(vaultId, name);
                await dbContext.Secrets.AddAsync(secret, cancellationToken);
            }

            var nextVersion = secret.CurrentVersion + 1;
            var protectionContext = new SecretProtectionContext(vaultId, secret.Id, nextVersion);

            var protectedSecret = await secretProtector.ProtectAsync(request.Value, protectionContext, cancellationToken);
            var version = secret.AddVersion(
                protectedSecret.CipherText,
                protectedSecret.Nonce,
                protectedSecret.KeyId,
                string.IsNullOrWhiteSpace(request.ContentType) ? "text/plain" : request.ContentType.Trim(),
                request.ExpiresUtc);

            await dbContext.SaveChangesAsync(cancellationToken);

            logger.LogInformation(
                "Secret write success. VaultId={VaultId}, SecretName={SecretName}, Version={Version}, KeyReference={KeyReference}, User={User}",
                vaultId,
                secret.Name,
                version.Version,
                version.KeyReference,
                userContext.Identity.ToString());

            await AppendAuditAsync(
                dbContext,
                action: "SECRET_WRITE",
                actor: userContext.Identity.ToString(),
                vaultId: vaultId,
                secretName: secret.Name,
                details: $"version={version.Version};keyId={version.KeyReference}",
                cancellationToken);

            return Results.Ok(new
            {
                secret.Id,
                secret.Name,
                Version = version.Version,
                version.KeyReference,
                version.Expires
            });
        }).RequireAuthorization().RequireRateLimiting("SecretReadPolicy");

        builder.MapGet("/vaults/{vaultId:guid}/secrets/{name}", async (
            Guid vaultId,
            string name,
            IApplicationDbContext dbContext,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<SecretStore> logger,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            if (string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { message = "Secret name is required." });
            }
            
            var vault = await dbContext.Vaults
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.Id == vaultId, cancellationToken);

            if (vault is null)
            {
                logger.LogWarning("Secret metadata read denied: vault not found. VaultId={VaultId}, User={User}", vaultId, userContext.Identity.ToString());
                return Results.NotFound(new { message = "Vault was not found." });
            }

            if (!await AuthorizeVaultPolicyAsync(vault.Group, authorizationService, httpContext.User, userContext, logger, vaultId, "read-metadata"))
            {
                return Results.Forbid();
            }

            var secret = await dbContext.Secrets
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.VaultId == vaultId && x.Name == name, cancellationToken);

            if (secret is null)
            {
                return Results.NotFound(new { message = "Secret was not found." });
            }

            var latestVersion = await dbContext.SecretVersions
                .AsNoTracking()
                .Where(x => x.SecretId == secret.Id)
                .OrderByDescending(x => x.Version)
                .FirstOrDefaultAsync(cancellationToken);

            if (latestVersion is null)
            {
                return Results.NotFound(new { message = "Secret has no versions." });
            }

            logger.LogInformation(
                "Secret metadata read success. VaultId={VaultId}, SecretName={SecretName}, Version={Version}, User={User}",
                vaultId,
                secret.Name,
                latestVersion.Version,
                userContext.Identity.ToString());

            await AppendAuditAsync(
                dbContext,
                action: "SECRET_READ_METADATA",
                actor: userContext.Identity.ToString(),
                vaultId: vaultId,
                secretName: secret.Name,
                details: $"version={latestVersion.Version};keyId={latestVersion.KeyReference};revoked={latestVersion.IsRevoked}",
                cancellationToken);

            return Results.Ok(new
            {
                secret.Name,
                latestVersion.Version,
                latestVersion.ContentType,
                latestVersion.KeyReference,
                latestVersion.IsRevoked,
                latestVersion.Expires
            });
        }).RequireAuthorization().RequireRateLimiting("SecretReadPolicy");

        builder.MapGet("/vaults/{vaultId:guid}/secrets/{name}/versions", async (
            Guid vaultId,
            string name,
            bool includeRevoked,
            int? fromVersion,
            int? toVersion,
            IApplicationDbContext dbContext,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<SecretStore> logger,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            if (string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { message = "Secret name is required." });
            }

            if (fromVersion.HasValue && fromVersion.Value <= 0)
            {
                return Results.BadRequest(new { message = "fromVersion must be greater than zero." });
            }

            if (toVersion.HasValue && toVersion.Value <= 0)
            {
                return Results.BadRequest(new { message = "toVersion must be greater than zero." });
            }

            if (fromVersion.HasValue && toVersion.HasValue && fromVersion.Value > toVersion.Value)
            {
                return Results.BadRequest(new { message = "fromVersion cannot be greater than toVersion." });
            }

            var vault = await dbContext.Vaults
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.Id == vaultId, cancellationToken);

            if (vault is null)
            {
                logger.LogWarning("Secret versions metadata read denied: vault not found. VaultId={VaultId}, User={User}", vaultId, userContext.Identity.ToString());
                return Results.NotFound(new { message = "Vault was not found." });
            }

            if (!await AuthorizeVaultPolicyAsync(vault.Group, authorizationService, httpContext.User, userContext, logger, vaultId, "read-versions-metadata"))
            {
                return Results.Forbid();
            }

            var secret = await dbContext.Secrets
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.VaultId == vaultId && x.Name == name, cancellationToken);

            if (secret is null)
            {
                return Results.NotFound(new { message = "Secret was not found." });
            }

            var versionsQuery = dbContext.SecretVersions
                .AsNoTracking()
                .Where(x => x.SecretId == secret.Id);

            if (!includeRevoked)
            {
                versionsQuery = versionsQuery.Where(x => !x.IsRevoked);
            }

            if (fromVersion.HasValue)
            {
                versionsQuery = versionsQuery.Where(x => x.Version >= fromVersion.Value);
            }

            if (toVersion.HasValue)
            {
                versionsQuery = versionsQuery.Where(x => x.Version <= toVersion.Value);
            }

            var versions = await versionsQuery
                .OrderByDescending(x => x.Version)
                .Select(x => new
                {
                    x.Version,
                    KeyId = x.KeyReference,
                    x.ContentType,
                    x.IsRevoked,
                    x.Expires
                })
                .ToListAsync(cancellationToken);

            logger.LogInformation(
                "Secret versions metadata read success. VaultId={VaultId}, SecretName={SecretName}, VersionsCount={VersionsCount}, User={User}",
                vaultId,
                secret.Name,
                versions.Count,
                userContext.Identity.ToString());

            await AppendAuditAsync(
                dbContext,
                action: "SECRET_READ_VERSIONS_METADATA",
                actor: userContext.Identity.ToString(),
                vaultId: vaultId,
                secretName: secret.Name,
                details: $"versionsCount={versions.Count};includeRevoked={includeRevoked};fromVersion={fromVersion?.ToString() ?? "-"};toVersion={toVersion?.ToString() ?? "-"}",
                cancellationToken);

            return Results.Ok(new
            {
                secret.Name,
                secret.CurrentVersion,
                Versions = versions
            });
        }).RequireAuthorization();

        builder.MapGet("/vaults/{vaultId:guid}/secrets/{name}/audit", async (
            Guid vaultId,
            string name,
            int? take,
            IApplicationDbContext dbContext,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<SecretStore> logger,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            if (string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { message = "Secret name is required." });
            }

            var limitedTake = Math.Clamp(take ?? 50, 1, 200);

            var vault = await dbContext.Vaults
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.Id == vaultId, cancellationToken);

            if (vault is null)
            {
                logger.LogWarning("Secret audit read denied: vault not found. VaultId={VaultId}, User={User}", vaultId, userContext.Identity.ToString());
                return Results.NotFound(new { message = "Vault was not found." });
            }

            if (!await AuthorizeVaultPolicyAsync(vault.Group, authorizationService, httpContext.User, userContext, logger, vaultId, "read-audit"))
            {
                return Results.Forbid();
            }

            var auditQuery = dbContext.SecretAuditEntries
                .AsNoTracking()
                .Where(x => x.VaultId == vaultId && x.SecretName == name)
                .Select(x => new AuditEntryResponse(
                    x.Action,
                    x.Actor,
                    x.OccurredAtUtc,
                    x.Details));

            List<AuditEntryResponse> audit;
            if (dbContext is DbContext efDb &&
                string.Equals(efDb.Database.ProviderName, "Microsoft.EntityFrameworkCore.Sqlite", StringComparison.Ordinal))
            {
                // SQLite provider doesn't support DateTimeOffset in ORDER BY translation.
                audit = (await auditQuery.ToListAsync(cancellationToken))
                    .OrderByDescending(x => x.OccurredAtUtc)
                    .Take(limitedTake)
                    .ToList();
            }
            else
            {
                audit = await auditQuery
                    .OrderByDescending(x => x.OccurredAtUtc)
                    .Take(limitedTake)
                    .ToListAsync(cancellationToken);
            }

            return Results.Ok(new
            {
                VaultId = vaultId,
                SecretName = name,
                Take = limitedTake,
                Entries = audit
            });
        }).RequireAuthorization().RequireRateLimiting("SecretAuditReadPolicy");
    }

    private static async Task<bool> AuthorizeVaultPolicyAsync(
        string? vaultGroup,
        IAuthorizationService authorizationService,
        System.Security.Claims.ClaimsPrincipal user,
        IUserContext userContext,
        ILogger<SecretStore> logger,
        Guid vaultId,
        string operation)
    {
        if (string.IsNullOrWhiteSpace(vaultGroup))
        {
            logger.LogWarning(
                "Secret {Operation} denied: vault without group policy. VaultId={VaultId}, User={User}",
                operation,
                vaultId,
                userContext.Identity.ToString());
            return false;
        }

        var policy = $"AdGroup:{vaultGroup}";
        var result = await authorizationService.AuthorizeAsync(user, policy);
        return result.Succeeded;
    }

    private static async Task AppendAuditAsync(
        IApplicationDbContext dbContext,
        string action,
        string actor,
        Guid? vaultId,
        string? secretName,
        string? details,
        CancellationToken cancellationToken)
    {
        await dbContext.SecretAuditEntries.AddAsync(
            new SecretAuditEntry(
                vaultId: vaultId,
                secretName: secretName,
                action: action,
                actor: actor,
                occurredAtUtc: DateTimeOffset.UtcNow,
                details: details),
            cancellationToken);

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    private static void ApplyNoStoreHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, no-cache, max-age=0";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "0";
    }
}
