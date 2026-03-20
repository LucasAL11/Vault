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
    private sealed record SecretRequestPayload(string Reason, string? TicketId);
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
                return SecureNotFound();
            }

            if (!await AuthorizeSecretAccessAsync(
                    vault: vault,
                    secretName: name,
                    requiredPermission: VaultPermission.Write,
                    operation: "write",
                    dbContext: dbContext,
                    authorizationService: authorizationService,
                    user: httpContext.User,
                    userContext: userContext,
                    logger: logger,
                    cancellationToken: cancellationToken))
            {
                return SecureForbidden();
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
        }).RequireAuthorization().RequireRateLimiting("SecretWritePolicy");

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
                return SecureNotFound();
            }

            if (!await AuthorizeSecretAccessAsync(
                    vault: vault,
                    secretName: name,
                    requiredPermission: VaultPermission.Read,
                    operation: "read-metadata",
                    dbContext: dbContext,
                    authorizationService: authorizationService,
                    user: httpContext.User,
                    userContext: userContext,
                    logger: logger,
                    cancellationToken: cancellationToken))
            {
                return SecureForbidden();
            }

            var secret = await dbContext.Secrets
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.VaultId == vaultId && x.Name == name, cancellationToken);

            if (secret is null)
            {
                return SecureNotFound();
            }

            var latestVersion = await dbContext.SecretVersions
                .AsNoTracking()
                .Where(x => x.SecretId == secret.Id)
                .OrderByDescending(x => x.Version)
                .FirstOrDefaultAsync(cancellationToken);

            if (latestVersion is null)
            {
                return SecureNotFound();
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
                return SecureNotFound();
            }

            if (!await AuthorizeSecretAccessAsync(
                    vault: vault,
                    secretName: name,
                    requiredPermission: VaultPermission.Read,
                    operation: "read-versions-metadata",
                    dbContext: dbContext,
                    authorizationService: authorizationService,
                    user: httpContext.User,
                    userContext: userContext,
                    logger: logger,
                    cancellationToken: cancellationToken))
            {
                return SecureForbidden();
            }

            var secret = await dbContext.Secrets
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.VaultId == vaultId && x.Name == name, cancellationToken);

            if (secret is null)
            {
                return SecureNotFound();
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
        }).RequireAuthorization().RequireRateLimiting("SecretReadPolicy");

        builder.MapPost("/vaults/{vaultId:guid}/secrets/{name}/request", async (
            Guid vaultId,
            string name,
            SecretRequestPayload request,
            IApplicationDbContext dbContext,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            ISecretProtector secretProtector,
            HttpContext httpContext,
            ILogger<SecretStore> logger,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            if (string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { message = "Secret name is required." });
            }

            if (string.IsNullOrWhiteSpace(request.Reason))
            {
                return Results.BadRequest(new { message = "Reason is required to request secret value." });
            }

            var vault = await dbContext.Vaults
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.Id == vaultId, cancellationToken);

            if (vault is null)
            {
                logger.LogWarning("Secret request denied: vault not found. VaultId={VaultId}, User={User}", vaultId, userContext.Identity.ToString());
                return SecureNotFound();
            }

            if (!await AuthorizeSecretAccessAsync(
                    vault: vault,
                    secretName: name,
                    requiredPermission: VaultPermission.Read,
                    operation: "request-value",
                    dbContext: dbContext,
                    authorizationService: authorizationService,
                    user: httpContext.User,
                    userContext: userContext,
                    logger: logger,
                    cancellationToken: cancellationToken))
            {
                return SecureForbidden();
            }

            var secret = await dbContext.Secrets
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.VaultId == vaultId && x.Name == name, cancellationToken);

            if (secret is null)
            {
                return SecureNotFound();
            }

            var now = DateTimeOffset.UtcNow;
            var activeVersionsQuery = dbContext.SecretVersions
                .AsNoTracking()
                .Where(x => x.SecretId == secret.Id && !x.IsRevoked);

            SecretVersion? activeVersion;
            if (dbContext is DbContext efDb &&
                string.Equals(efDb.Database.ProviderName, "Microsoft.EntityFrameworkCore.Sqlite", StringComparison.Ordinal))
            {
                activeVersion = (await activeVersionsQuery.ToListAsync(cancellationToken))
                    .Where(x => x.Expires == null || x.Expires > now)
                    .OrderByDescending(x => x.Version)
                    .FirstOrDefault();
            }
            else
            {
                activeVersion = await activeVersionsQuery
                    .Where(x => x.Expires == null || x.Expires > now)
                    .OrderByDescending(x => x.Version)
                    .FirstOrDefaultAsync(cancellationToken);
            }

            if (activeVersion is null)
            {
                return SecureNotFound();
            }

            var plaintext = await secretProtector.UnprotectAsync(
                new ProtectedSecret(activeVersion.CipherText, activeVersion.Nonce, activeVersion.KeyReference),
                new SecretProtectionContext(vaultId, secret.Id, activeVersion.Version),
                cancellationToken);

            await AppendAuditAsync(
                dbContext,
                action: "SECRET_REQUEST_VALUE",
                actor: userContext.Identity.ToString(),
                vaultId: vaultId,
                secretName: secret.Name,
                details: $"version={activeVersion.Version};ticket={request.TicketId ?? "-"};reason={request.Reason.Trim()}",
                cancellationToken);

            logger.LogInformation(
                "Secret request success. VaultId={VaultId}, SecretName={SecretName}, Version={Version}, User={User}",
                vaultId,
                secret.Name,
                activeVersion.Version,
                userContext.Identity.ToString());

            return Results.Ok(new
            {
                secret.Name,
                activeVersion.Version,
                activeVersion.ContentType,
                Value = plaintext,
                activeVersion.Expires
            });
        }).RequireAuthorization().RequireRateLimiting("SecretReadPolicy");

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
                return SecureNotFound();
            }

            if (!await AuthorizeSecretAccessAsync(
                    vault: vault,
                    secretName: name,
                    requiredPermission: VaultPermission.Admin,
                    operation: "read-audit",
                    dbContext: dbContext,
                    authorizationService: authorizationService,
                    user: httpContext.User,
                    userContext: userContext,
                    logger: logger,
                    cancellationToken: cancellationToken))
            {
                return SecureForbidden();
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

    private static async Task<bool> AuthorizeSecretAccessAsync(
        Domain.vault.Vault vault,
        string secretName,
        VaultPermission requiredPermission,
        string operation,
        IApplicationDbContext dbContext,
        IAuthorizationService authorizationService,
        System.Security.Claims.ClaimsPrincipal user,
        IUserContext userContext,
        ILogger<SecretStore> logger,
        CancellationToken cancellationToken)
    {
        var vaultId = vault.Id;
        if (vault.Status != Status.Active)
        {
            await AppendAuditAsync(
                dbContext,
                action: "SECRET_ACCESS_DENIED",
                actor: userContext.Identity.ToString(),
                vaultId: vaultId,
                secretName: secretName,
                details: $"operation={operation};reason=vault-status-not-active;vaultStatus={vault.Status}",
                cancellationToken);

            logger.LogWarning(
                "Secret {Operation} denied: vault status is not active. VaultId={VaultId}, VaultStatus={VaultStatus}, User={User}",
                operation,
                vaultId,
                vault.Status,
                userContext.Identity.ToString());
            return false;
        }

        var vaultGroup = vault.Group;
        if (string.IsNullOrWhiteSpace(vaultGroup))
        {
            await AppendAuditAsync(
                dbContext,
                action: "SECRET_ACCESS_DENIED",
                actor: userContext.Identity.ToString(),
                vaultId: vaultId,
                secretName: secretName,
                details: $"operation={operation};reason=vault-without-group-policy",
                cancellationToken);

            logger.LogWarning(
                "Secret {Operation} denied: vault without group policy. VaultId={VaultId}, User={User}",
                operation,
                vaultId,
                userContext.Identity.ToString());
            return false;
        }

        var vaultPolicy = $"AdGroup:{vaultGroup}";
        var vaultResult = await authorizationService.AuthorizeAsync(user, vaultPolicy);
        if (!vaultResult.Succeeded)
        {
            await AppendAuditAsync(
                dbContext,
                action: "SECRET_ACCESS_DENIED",
                actor: userContext.Identity.ToString(),
                vaultId: vaultId,
                secretName: secretName,
                details: $"operation={operation};reason=vault-group-policy-failed;vaultGroup={vaultGroup}",
                cancellationToken);

            logger.LogWarning(
                "Secret {Operation} denied: vault group authorization failed. VaultId={VaultId}, VaultGroup={VaultGroup}, User={User}",
                operation,
                vaultId,
                vaultGroup,
                userContext.Identity.ToString());
            return false;
        }

        var adMapGroups = await dbContext.ADMaps
            .AsNoTracking()
            .Where(x => x.VaultId == vaultId && x.IsActive && (int)x.Permission >= (int)requiredPermission)
            .Select(x => x.GroupId)
            .Distinct()
            .ToListAsync(cancellationToken);

        if (adMapGroups.Count == 0)
        {
            await AppendAuditAsync(
                dbContext,
                action: "SECRET_ACCESS_DENIED",
                actor: userContext.Identity.ToString(),
                vaultId: vaultId,
                secretName: secretName,
                details: $"operation={operation};reason=no-active-admap;requiredPermission={requiredPermission}",
                cancellationToken);

            logger.LogWarning(
                "Secret {Operation} denied: no active ADMap with required permission. VaultId={VaultId}, RequiredPermission={RequiredPermission}, User={User}",
                operation,
                vaultId,
                requiredPermission,
                userContext.Identity.ToString());
            return false;
        }

        foreach (var groupId in adMapGroups)
        {
            var adMapPolicy = $"AdGroup:{groupId}";
            var adMapResult = await authorizationService.AuthorizeAsync(user, adMapPolicy);
            if (adMapResult.Succeeded)
            {
                await AppendAuditAsync(
                    dbContext,
                    action: "SECRET_ACCESS_GRANTED",
                    actor: userContext.Identity.ToString(),
                    vaultId: vaultId,
                    secretName: secretName,
                    details: $"operation={operation};requiredPermission={requiredPermission};group={groupId}",
                    cancellationToken);

                return true;
            }
        }

        await AppendAuditAsync(
            dbContext,
            action: "SECRET_ACCESS_DENIED",
            actor: userContext.Identity.ToString(),
            vaultId: vaultId,
            secretName: secretName,
            details: $"operation={operation};reason=admap-policy-failed;requiredPermission={requiredPermission};candidateGroups={string.Join(",", adMapGroups)}",
            cancellationToken);

        logger.LogWarning(
            "Secret {Operation} denied: user is not authorized by ADMap. VaultId={VaultId}, RequiredPermission={RequiredPermission}, CandidateGroups={CandidateGroups}, User={User}",
            operation,
            vaultId,
            requiredPermission,
            adMapGroups,
            userContext.Identity.ToString());

        return false;
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

    private static IResult SecureForbidden()
        => Results.Json(new { message = "Access denied." }, statusCode: StatusCodes.Status403Forbidden);

    private static IResult SecureNotFound()
        => Results.NotFound(new { message = "Resource not available." });
}
