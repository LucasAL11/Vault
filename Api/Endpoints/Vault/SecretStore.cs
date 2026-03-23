using System.Security.Cryptography;
using System.Text;
using Api.Endpoints.Users;
using Api.Security;
using Application.Abstractions.Data;
using Application.Abstractions.Security;
using Application.Authentication;
using Domain.vault;
using Infrastructure.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Api.Endpoints.Vault;

public sealed class SecretStore : IEndpoint
{
    private const string DummyClientId = "__vault-proof-invalid-client__";
    private const string DummySubject = "__vault-proof-invalid-subject__";
    private const string SecretRequestContractVersion = "v1";
    private static readonly byte[] DummyNonceBytes = new byte[32];

    private sealed record UpsertRequest(string Value, string? ContentType, DateTimeOffset? ExpiresUtc);
    private sealed class SecretRequestPayload
    {
        public string? ContractVersion { get; init; }
        public string? Reason { get; init; }
        public string? Ticket { get; init; }
        public string? TicketId { get; init; }
        public string? ClientId { get; init; }
        public string? Nonce { get; init; }
        public DateTimeOffset? IssuedAt { get; init; }
        public DateTimeOffset? IssuedAtUtc { get; init; }
        public string? Proof { get; init; }
    }
    private sealed record RevokeSecretVersionRequest(string? Reason);
    private sealed record SecretListItemResponse(
        string Name,
        string Status,
        int CurrentVersion,
        int? LatestVersion,
        string? ContentType,
        string? KeyReference,
        bool? IsRevoked,
        DateTimeOffset? Expires);
    private sealed record SecretLatestVersionSnapshot(
        Guid SecretId,
        int Version,
        string ContentType,
        string KeyReference,
        bool IsRevoked,
        DateTimeOffset? Expires);
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

        builder.MapGet("/vaults/{vaultId:guid}/secrets", async (
            Guid vaultId,
            string? name,
            string? status,
            int? page,
            int? pageSize,
            string? orderBy,
            string? orderDirection,
            IApplicationDbContext dbContext,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            HttpContext httpContext,
            ILogger<SecretStore> logger,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            var normalizedPage = page ?? 1;
            if (normalizedPage <= 0)
            {
                return Results.BadRequest(new { message = "page must be greater than zero." });
            }

            var normalizedPageSize = pageSize ?? 20;
            if (normalizedPageSize is < 1 or > 100)
            {
                return Results.BadRequest(new { message = "pageSize must be between 1 and 100." });
            }

            if (!TryParseStatusFilter(status, out var parsedStatus))
            {
                return Results.BadRequest(new
                {
                    message = $"status is invalid. Allowed values: {string.Join(", ", Enum.GetNames<Status>())}."
                });
            }

            if (!TryNormalizeSecretSortBy(orderBy, out var normalizedSortBy))
            {
                return Results.BadRequest(new
                {
                    message = "orderBy is invalid. Allowed values: name, status, currentVersion."
                });
            }

            if (!TryNormalizeSortDirection(orderDirection, out var normalizedSortDirection))
            {
                return Results.BadRequest(new
                {
                    message = "orderDirection is invalid. Allowed values: asc, desc."
                });
            }

            var nameFilter = string.IsNullOrWhiteSpace(name) ? null : name.Trim();
            if (nameFilter is { Length: > 120 })
            {
                return Results.BadRequest(new { message = "name filter cannot exceed 120 characters." });
            }

            var vault = await dbContext.Vaults
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.Id == vaultId, cancellationToken);

            if (vault is null)
            {
                logger.LogWarning(
                    "Secret list metadata denied: vault not found. VaultId={VaultId}, User={User}",
                    vaultId,
                    userContext.Identity.ToString());
                return SecureNotFound();
            }

            if (!await AuthorizeSecretAccessAsync(
                    vault: vault,
                    secretName: "*",
                    requiredPermission: VaultPermission.Read,
                    operation: "list-metadata",
                    dbContext: dbContext,
                    authorizationService: authorizationService,
                    user: httpContext.User,
                    userContext: userContext,
                    logger: logger,
                    cancellationToken: cancellationToken))
            {
                return SecureForbidden();
            }

            var secretsQuery = dbContext.Secrets
                .AsNoTracking()
                .Where(x => x.VaultId == vaultId);

            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                var normalizedNameFilter = nameFilter.ToLowerInvariant();
                secretsQuery = secretsQuery.Where(x => x.Name.ToLower().Contains(normalizedNameFilter));
            }

            if (parsedStatus.HasValue)
            {
                secretsQuery = secretsQuery.Where(x => x.Status == parsedStatus.Value);
            }

            var sortedSecretsQuery = ApplySecretSorting(secretsQuery, normalizedSortBy, normalizedSortDirection);
            var totalCount = await sortedSecretsQuery.CountAsync(cancellationToken);
            var skip = (normalizedPage - 1) * normalizedPageSize;

            var pagedSecrets = await sortedSecretsQuery
                .Skip(skip)
                .Take(normalizedPageSize)
                .Select(x => new
                {
                    x.Id,
                    x.Name,
                    x.Status,
                    x.CurrentVersion
                })
                .ToListAsync(cancellationToken);

            var secretIds = pagedSecrets
                .Select(x => x.Id)
                .ToArray();

            var latestVersionsBySecretId = new Dictionary<Guid, SecretLatestVersionSnapshot>();
            if (secretIds.Length > 0)
            {
                var latestCandidates = await dbContext.SecretVersions
                    .AsNoTracking()
                    .Where(x => secretIds.Contains(x.SecretId))
                    .OrderByDescending(x => x.Version)
                    .Select(x => new SecretLatestVersionSnapshot(
                        x.SecretId,
                        x.Version,
                        x.ContentType,
                        x.KeyReference,
                        x.IsRevoked,
                        x.Expires))
                    .ToListAsync(cancellationToken);

                foreach (var candidate in latestCandidates)
                {
                    if (!latestVersionsBySecretId.ContainsKey(candidate.SecretId))
                    {
                        latestVersionsBySecretId[candidate.SecretId] = candidate;
                    }
                }
            }

            var items = pagedSecrets
                .Select(secret =>
                {
                    latestVersionsBySecretId.TryGetValue(secret.Id, out var latestVersion);
                    return new SecretListItemResponse(
                        Name: secret.Name,
                        Status: secret.Status.ToString(),
                        CurrentVersion: secret.CurrentVersion,
                        LatestVersion: latestVersion?.Version,
                        ContentType: latestVersion?.ContentType,
                        KeyReference: latestVersion?.KeyReference,
                        IsRevoked: latestVersion?.IsRevoked,
                        Expires: latestVersion?.Expires);
                })
                .ToList();

            var totalPages = totalCount == 0
                ? 0
                : (int)Math.Ceiling(totalCount / (double)normalizedPageSize);

            await AppendAuditAsync(
                dbContext,
                action: "SECRET_LIST_METADATA",
                actor: userContext.Identity.ToString(),
                vaultId: vaultId,
                secretName: null,
                details:
                $"page={normalizedPage};pageSize={normalizedPageSize};returned={items.Count};total={totalCount};name={nameFilter ?? "-"};status={parsedStatus?.ToString() ?? "-"};orderBy={normalizedSortBy};orderDirection={normalizedSortDirection}",
                cancellationToken);

            logger.LogInformation(
                "Secret list metadata success. VaultId={VaultId}, Page={Page}, PageSize={PageSize}, Returned={Returned}, Total={Total}, User={User}",
                vaultId,
                normalizedPage,
                normalizedPageSize,
                items.Count,
                totalCount,
                userContext.Identity.ToString());

            return Results.Ok(new
            {
                VaultId = vaultId,
                Page = normalizedPage,
                PageSize = normalizedPageSize,
                TotalCount = totalCount,
                TotalPages = totalPages,
                OrderBy = normalizedSortBy,
                OrderDirection = normalizedSortDirection,
                Filters = new
                {
                    Name = nameFilter,
                    Status = parsedStatus?.ToString()
                },
                Items = items
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

        builder.MapPost("/vaults/{vaultId:guid}/secrets/{name}/versions/{version:int}/revoke", async (
            Guid vaultId,
            string name,
            int version,
            RevokeSecretVersionRequest request,
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

            if (version <= 0)
            {
                return Results.BadRequest(new { message = "version must be greater than zero." });
            }

            var reason = request.Reason?.Trim();
            if (string.IsNullOrWhiteSpace(reason))
            {
                return Results.BadRequest(new { message = "reason is required." });
            }

            if (reason.Length > 500)
            {
                return Results.BadRequest(new { message = "reason cannot exceed 500 characters." });
            }

            var vault = await dbContext.Vaults
                .AsNoTracking()
                .SingleOrDefaultAsync(x => x.Id == vaultId, cancellationToken);

            if (vault is null)
            {
                logger.LogWarning(
                    "Secret version revoke denied: vault not found. VaultId={VaultId}, User={User}",
                    vaultId,
                    userContext.Identity.ToString());
                return SecureNotFound();
            }

            if (!await AuthorizeSecretAccessAsync(
                    vault: vault,
                    secretName: name,
                    requiredPermission: VaultPermission.Admin,
                    operation: "revoke-version",
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

            var secretVersion = await dbContext.SecretVersions
                .SingleOrDefaultAsync(x => x.SecretId == secret.Id && x.Version == version, cancellationToken);

            if (secretVersion is null)
            {
                return SecureNotFound();
            }

            var wasAlreadyRevoked = secretVersion.IsRevoked;
            if (!wasAlreadyRevoked)
            {
                secretVersion.Revoke();
                await dbContext.SaveChangesAsync(cancellationToken);
            }

            var actor = userContext.Identity.ToString();
            await AppendAuditAsync(
                dbContext,
                action: "SECRET_VERSION_REVOKE",
                actor: actor,
                vaultId: vaultId,
                secretName: secret.Name,
                details: $"version={secretVersion.Version};reason={reason};alreadyRevoked={wasAlreadyRevoked}",
                cancellationToken);

            logger.LogInformation(
                "Secret version revoke success. VaultId={VaultId}, SecretName={SecretName}, Version={Version}, AlreadyRevoked={AlreadyRevoked}, User={User}",
                vaultId,
                secret.Name,
                secretVersion.Version,
                wasAlreadyRevoked,
                actor);

            return Results.Ok(new
            {
                secret.Name,
                Version = secretVersion.Version,
                secretVersion.IsRevoked,
                Reason = reason,
                Actor = actor,
                AlreadyRevoked = wasAlreadyRevoked
            });
        }).RequireAuthorization().RequireRateLimiting("SecretWritePolicy");

        builder.MapPost("/vaults/{vaultId:guid}/secrets/{name}/request", async (
            Guid vaultId,
            string name,
            SecretRequestPayload request,
            IApplicationDbContext dbContext,
            IAuthorizationService authorizationService,
            IUserContext userContext,
            ISecretProtector secretProtector,
            INonceStore nonceStore,
            IOptions<AuthChallengeOptions> challengeOptions,
            IOptions<NonceStoreOptions> nonceStoreOptions,
            HttpContext httpContext,
            ILogger<SecretStore> logger,
            CancellationToken cancellationToken) =>
        {
            ApplyNoStoreHeaders(httpContext.Response);

            if (string.IsNullOrWhiteSpace(name))
            {
                return Results.BadRequest(new { message = "Secret name is required." });
            }

            var contractVersion = request.ContractVersion?.Trim();
            if (!string.Equals(contractVersion, SecretRequestContractVersion, StringComparison.OrdinalIgnoreCase))
            {
                return Results.BadRequest(new
                {
                    message = $"contractVersion is invalid. Supported value: {SecretRequestContractVersion}."
                });
            }

            var reason = request.Reason?.Trim();
            var ticket = ResolveTicket(request);
            var clientId = request.ClientId?.Trim();
            var nonce = request.Nonce?.Trim();
            var proof = request.Proof?.Trim();
            var issuedAt = request.IssuedAt ?? request.IssuedAtUtc;

            if (string.IsNullOrWhiteSpace(reason) ||
                string.IsNullOrWhiteSpace(ticket) ||
                string.IsNullOrWhiteSpace(clientId) ||
                string.IsNullOrWhiteSpace(nonce) ||
                string.IsNullOrWhiteSpace(proof) ||
                !issuedAt.HasValue)
            {
                return Results.BadRequest(new
                {
                    message = "Required contract fields: reason, ticket, clientId, nonce, issuedAt, proof."
                });
            }

            var normalizedReason = reason!;
            var normalizedTicket = ticket!;
            var normalizedClientId = clientId!;
            var normalizedNonce = nonce!;
            var normalizedProof = proof!;
            var normalizedIssuedAt = issuedAt.Value;

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

            if (!NonceChallengeScope.TryResolveSubject(httpContext, requestedSubject: null, out var subject))
            {
                logger.LogWarning(
                    "Secret request denied: unable to resolve subject. VaultId={VaultId}, SecretName={SecretName}, User={User}",
                    vaultId,
                    name,
                    userContext.Identity.ToString());
                return Results.Unauthorized();
            }

            var authChallengeOptions = challengeOptions.Value;
            var nonceOptions = nonceStoreOptions.Value;
            var hasClientSecret = TryGetClientSecret(normalizedClientId, authChallengeOptions, out var configuredClientSecret);
            var effectiveClientSecret = hasClientSecret
                ? configuredClientSecret
                : ResolveFallbackSecret(authChallengeOptions);
            var nonceParsed = TryFromBase64Url(normalizedNonce, out var nonceBytes);
            var effectiveNonceBytes = nonceParsed ? nonceBytes : DummyNonceBytes;
            var proofPayload = BuildSecretRequestProofPayload(
                vaultId,
                name,
                normalizedClientId,
                subject,
                normalizedReason,
                normalizedTicket,
                normalizedNonce,
                normalizedIssuedAt);
            var signatureValid = IsSignatureValid(proofPayload, normalizedProof, effectiveClientSecret);
            var withinSkewWindow = IsWithinSkewWindow(normalizedIssuedAt, authChallengeOptions, nonceOptions);

            var shouldConsumeIssuedNonce = hasClientSecret && nonceParsed && signatureValid && withinSkewWindow;
            var consumeScope = shouldConsumeIssuedNonce
                ? NonceChallengeScope.Build(
                    httpContext,
                    normalizedClientId,
                    subject,
                    NonceChallengeAudiences.VaultSecretRequest)
                : NonceChallengeScope.Build(
                    httpContext,
                    DummyClientId,
                    DummySubject,
                    NonceChallengeAudiences.VaultSecretRequest);
            var consumeNonceBytes = shouldConsumeIssuedNonce ? effectiveNonceBytes : DummyNonceBytes;
            var nonceConsumed = await nonceStore.TryConsumeAsync(consumeScope, consumeNonceBytes, cancellationToken);

            var proofValid = hasClientSecret && nonceParsed && signatureValid && withinSkewWindow && nonceConsumed;
            if (!proofValid)
            {
                await AppendAuditAsync(
                    dbContext,
                    action: "SECRET_REQUEST_VALUE_DENIED",
                    actor: userContext.Identity.ToString(),
                    vaultId: vaultId,
                    secretName: name,
                    details: $"reason=invalid-proof;clientId={normalizedClientId}",
                    cancellationToken);

                logger.LogWarning(
                    "Secret request denied: proof validation failed. VaultId={VaultId}, SecretName={SecretName}, User={User}",
                    vaultId,
                    name,
                    userContext.Identity.ToString());
                return Results.Unauthorized();
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
                details: $"version={activeVersion.Version};ticket={NormalizeTicketId(normalizedTicket)};reason={normalizedReason};clientId={normalizedClientId};contractVersion={SecretRequestContractVersion}",
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

    private static bool TryParseStatusFilter(string? status, out Status? parsedStatus)
    {
        parsedStatus = null;
        if (string.IsNullOrWhiteSpace(status))
        {
            return true;
        }

        if (Enum.TryParse<Status>(status.Trim(), ignoreCase: true, out var value))
        {
            parsedStatus = value;
            return true;
        }

        return false;
    }

    private static bool TryNormalizeSecretSortBy(string? orderBy, out string normalizedSortBy)
    {
        if (string.IsNullOrWhiteSpace(orderBy))
        {
            normalizedSortBy = "name";
            return true;
        }

        var normalized = orderBy.Trim();
        if (normalized.Equals("name", StringComparison.OrdinalIgnoreCase))
        {
            normalizedSortBy = "name";
            return true;
        }

        if (normalized.Equals("status", StringComparison.OrdinalIgnoreCase))
        {
            normalizedSortBy = "status";
            return true;
        }

        if (normalized.Equals("currentVersion", StringComparison.OrdinalIgnoreCase))
        {
            normalizedSortBy = "currentVersion";
            return true;
        }

        normalizedSortBy = string.Empty;
        return false;
    }

    private static bool TryNormalizeSortDirection(string? orderDirection, out string normalizedSortDirection)
    {
        if (string.IsNullOrWhiteSpace(orderDirection))
        {
            normalizedSortDirection = "asc";
            return true;
        }

        var normalized = orderDirection.Trim();
        if (normalized.Equals("asc", StringComparison.OrdinalIgnoreCase))
        {
            normalizedSortDirection = "asc";
            return true;
        }

        if (normalized.Equals("desc", StringComparison.OrdinalIgnoreCase))
        {
            normalizedSortDirection = "desc";
            return true;
        }

        normalizedSortDirection = string.Empty;
        return false;
    }

    private static IQueryable<Secret> ApplySecretSorting(
        IQueryable<Secret> query,
        string sortBy,
        string sortDirection)
    {
        var descending = string.Equals(sortDirection, "desc", StringComparison.OrdinalIgnoreCase);

        return sortBy switch
        {
            "status" when descending => query
                .OrderByDescending(x => x.Status)
                .ThenBy(x => x.Name)
                .ThenBy(x => x.Id),

            "status" => query
                .OrderBy(x => x.Status)
                .ThenBy(x => x.Name)
                .ThenBy(x => x.Id),

            "currentVersion" when descending => query
                .OrderByDescending(x => x.CurrentVersion)
                .ThenBy(x => x.Name)
                .ThenBy(x => x.Id),

            "currentVersion" => query
                .OrderBy(x => x.CurrentVersion)
                .ThenBy(x => x.Name)
                .ThenBy(x => x.Id),

            "name" when descending => query
                .OrderByDescending(x => x.Name)
                .ThenBy(x => x.Id),

            _ => query
                .OrderBy(x => x.Name)
                .ThenBy(x => x.Id)
        };
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

    private static bool TryGetClientSecret(string clientId, AuthChallengeOptions options, out string secret)
    {
        secret = string.Empty;
        if (!options.ClientSecrets.TryGetValue(clientId, out var configuredSecret) ||
            string.IsNullOrWhiteSpace(configuredSecret))
        {
            return false;
        }

        secret = configuredSecret;
        return true;
    }

    private static string ResolveFallbackSecret(AuthChallengeOptions options)
    {
        foreach (var entry in options.ClientSecrets)
        {
            if (!string.IsNullOrWhiteSpace(entry.Value))
            {
                return entry.Value;
            }
        }

        return "vault-secret-request-fallback-secret";
    }

    private static string BuildSecretRequestProofPayload(
        Guid vaultId,
        string secretName,
        string clientId,
        string subject,
        string reason,
        string ticket,
        string nonce,
        DateTimeOffset issuedAtUtc)
    {
        return $"{vaultId:D}|{secretName.Trim()}|{clientId.Trim()}|{subject.Trim().ToUpperInvariant()}|{reason.Trim()}|{NormalizeTicketId(ticket)}|{nonce.Trim()}|{issuedAtUtc:O}";
    }

    private static string? ResolveTicket(SecretRequestPayload request)
    {
        if (!string.IsNullOrWhiteSpace(request.Ticket))
        {
            return request.Ticket.Trim();
        }

        if (!string.IsNullOrWhiteSpace(request.TicketId))
        {
            return request.TicketId.Trim();
        }

        return null;
    }

    private static string NormalizeTicketId(string? ticket)
    {
        return string.IsNullOrWhiteSpace(ticket) ? "-" : ticket.Trim();
    }

    private static bool IsSignatureValid(string payload, string signatureBase64Url, string clientSecret)
    {
        var secretBytes = Encoding.UTF8.GetBytes(clientSecret);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        using var hmac = new HMACSHA256(secretBytes);
        var expectedSignature = hmac.ComputeHash(payloadBytes);

        var signatureParsed = TryFromBase64Url(signatureBase64Url, out var providedSignature);
        var signaturesMatch = FixedTimeEqualsWithExpectedLength(providedSignature, expectedSignature, expectedSignature.Length);
        return signatureParsed & signaturesMatch;
    }

    private static bool FixedTimeEqualsWithExpectedLength(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, int expectedLength)
    {
        Span<byte> leftBuffer = stackalloc byte[expectedLength];
        Span<byte> rightBuffer = stackalloc byte[expectedLength];
        leftBuffer.Clear();
        rightBuffer.Clear();

        var leftCopy = Math.Min(left.Length, expectedLength);
        var rightCopy = Math.Min(right.Length, expectedLength);
        left[..leftCopy].CopyTo(leftBuffer);
        right[..rightCopy].CopyTo(rightBuffer);

        var bytesEqual = CryptographicOperations.FixedTimeEquals(leftBuffer, rightBuffer);
        var lengthsEqual = left.Length == expectedLength && right.Length == expectedLength;
        return bytesEqual & lengthsEqual;
    }

    private static bool IsWithinSkewWindow(
        DateTimeOffset issuedAtUtc,
        AuthChallengeOptions challengeOptions,
        NonceStoreOptions nonceStoreOptions)
    {
        var skewSeconds = Math.Max(0, challengeOptions.ClockSkewSeconds);
        var nonceTtlSeconds = Math.Max(1, nonceStoreOptions.TtlSeconds);
        var now = DateTimeOffset.UtcNow;
        var earliestAccepted = issuedAtUtc.AddSeconds(-skewSeconds);
        var latestAccepted = issuedAtUtc.AddSeconds(nonceTtlSeconds + skewSeconds);

        return now >= earliestAccepted && now <= latestAccepted;
    }

    private static bool TryFromBase64Url(string input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var normalized = input.Replace('-', '+').Replace('_', '/');
        switch (normalized.Length % 4)
        {
            case 2:
                normalized += "==";
                break;
            case 3:
                normalized += "=";
                break;
            case 1:
                return false;
        }

        try
        {
            bytes = Convert.FromBase64String(normalized);
            return bytes.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
