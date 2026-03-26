using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Secrets;

public sealed record ListSecretVersionsQuery(
    Guid VaultId,
    string Name,
    bool IncludeRevoked,
    int? FromVersion,
    int? ToVersion) : IQuery<SecretVersionsDto>;

public sealed class ListSecretVersionsQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<ListSecretVersionsQuery, SecretVersionsDto>
{
    public async Task<Result<SecretVersionsDto>> Handle(
        ListSecretVersionsQuery query,
        CancellationToken cancellationToken = default)
    {
        var secret = await dbContext.Secrets
            .AsNoTracking()
            .Where(x => x.VaultId == query.VaultId && x.Name == query.Name)
            .Select(x => new
            {
                x.Id,
                x.Name,
                x.CurrentVersion
            })
            .SingleOrDefaultAsync(cancellationToken);

        if (secret is null)
        {
            return Result.Failure<SecretVersionsDto>(SecretErrors.SecretNotFound(query.VaultId, query.Name));
        }

        var versionsQuery = dbContext.SecretVersions
            .AsNoTracking()
            .Where(x => x.SecretId == secret.Id);

        if (!query.IncludeRevoked)
        {
            versionsQuery = versionsQuery.Where(x => !x.IsRevoked);
        }

        if (query.FromVersion.HasValue)
        {
            versionsQuery = versionsQuery.Where(x => x.Version >= query.FromVersion.Value);
        }

        if (query.ToVersion.HasValue)
        {
            versionsQuery = versionsQuery.Where(x => x.Version <= query.ToVersion.Value);
        }

        var versions = await versionsQuery
            .OrderByDescending(x => x.Version)
            .Select(x => new SecretVersionItemDto(
                x.Version,
                x.KeyReference,
                x.ContentType,
                x.IsRevoked,
                x.Expires))
            .ToArrayAsync(cancellationToken);

        return new SecretVersionsDto(
            secret.Name,
            secret.CurrentVersion,
            versions);
    }
}
