using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Secrets;

public sealed record ListSecretsQuery(
    Guid VaultId,
    string? Name,
    Status? Status,
    int Page,
    int PageSize,
    string OrderBy,
    string OrderDirection) : IQuery<SecretListMetadataDto>;

public sealed class ListSecretsQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<ListSecretsQuery, SecretListMetadataDto>
{
    private sealed record SecretLatestVersionSnapshot(
        Guid SecretId,
        int Version,
        string ContentType,
        string KeyReference,
        bool IsRevoked,
        DateTimeOffset? Expires);

    public async Task<Result<SecretListMetadataDto>> Handle(
        ListSecretsQuery query,
        CancellationToken cancellationToken = default)
    {
        var secretsQuery = dbContext.Secrets
            .AsNoTracking()
            .Where(x => x.VaultId == query.VaultId);

        if (!string.IsNullOrWhiteSpace(query.Name))
        {
            var normalizedNameFilter = query.Name.Trim().ToLowerInvariant();
            secretsQuery = secretsQuery.Where(x => x.Name.ToLower().Contains(normalizedNameFilter));
        }

        if (query.Status.HasValue)
        {
            secretsQuery = secretsQuery.Where(x => x.Status == query.Status.Value);
        }

        var sortedSecretsQuery = ApplySecretSorting(secretsQuery, query.OrderBy, query.OrderDirection);
        var totalCount = await sortedSecretsQuery.CountAsync(cancellationToken);
        var skip = (query.Page - 1) * query.PageSize;

        var pagedSecrets = await sortedSecretsQuery
            .Skip(skip)
            .Take(query.PageSize)
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
            var latestVersionPerSecretQuery = dbContext.SecretVersions
                .AsNoTracking()
                .Where(x => secretIds.Contains(x.SecretId))
                .GroupBy(x => x.SecretId)
                .Select(group => new
                {
                    SecretId = group.Key,
                    Version = group.Max(x => x.Version)
                });

            var latestCandidates = await (
                from version in dbContext.SecretVersions.AsNoTracking()
                join latest in latestVersionPerSecretQuery
                    on new { version.SecretId, version.Version }
                    equals new { latest.SecretId, latest.Version }
                select new SecretLatestVersionSnapshot(
                    version.SecretId,
                    version.Version,
                    version.ContentType,
                    version.KeyReference,
                    version.IsRevoked,
                    version.Expires))
                .ToListAsync(cancellationToken);

            foreach (var candidate in latestCandidates)
            {
                latestVersionsBySecretId[candidate.SecretId] = candidate;
            }
        }

        var items = pagedSecrets
            .Select(secret =>
            {
                latestVersionsBySecretId.TryGetValue(secret.Id, out var latestVersion);
                return new SecretListItemDto(
                    Name: secret.Name,
                    Status: secret.Status.ToString(),
                    CurrentVersion: secret.CurrentVersion,
                    LatestVersion: latestVersion?.Version,
                    ContentType: latestVersion?.ContentType,
                    KeyReference: latestVersion?.KeyReference,
                    IsRevoked: latestVersion?.IsRevoked,
                    Expires: latestVersion?.Expires);
            })
            .ToArray();

        var totalPages = totalCount == 0
            ? 0
            : (int)Math.Ceiling(totalCount / (double)query.PageSize);

        return new SecretListMetadataDto(
            query.VaultId,
            query.Page,
            query.PageSize,
            totalCount,
            totalPages,
            query.OrderBy,
            query.OrderDirection,
            query.Name,
            query.Status?.ToString(),
            items);
    }

    private static IQueryable<Domain.vault.Secret> ApplySecretSorting(
        IQueryable<Domain.vault.Secret> query,
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
}
