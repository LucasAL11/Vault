using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Secrets;

public sealed record GetSecretMetadataQuery(Guid VaultId, string Name)
    : IQuery<SecretMetadataDto>;

public sealed class GetSecretMetadataQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<GetSecretMetadataQuery, SecretMetadataDto>
{
    public async Task<Result<SecretMetadataDto>> Handle(
        GetSecretMetadataQuery query,
        CancellationToken cancellationToken = default)
    {
        var secret = await dbContext.Secrets
            .AsNoTracking()
            .Where(x => x.VaultId == query.VaultId && x.Name == query.Name)
            .Select(x => new
            {
                x.Id,
                x.Name
            })
            .SingleOrDefaultAsync(cancellationToken);

        if (secret is null)
        {
            return Result.Failure<SecretMetadataDto>(SecretErrors.SecretNotFound(query.VaultId, query.Name));
        }

        var latestVersion = await dbContext.SecretVersions
            .AsNoTracking()
            .Where(x => x.SecretId == secret.Id)
            .OrderByDescending(x => x.Version)
            .Select(x => new
            {
                x.Version,
                x.ContentType,
                x.KeyReference,
                x.IsRevoked,
                x.Expires
            })
            .FirstOrDefaultAsync(cancellationToken);

        if (latestVersion is null)
        {
            return Result.Failure<SecretMetadataDto>(SecretErrors.SecretNotFound(query.VaultId, query.Name));
        }

        return new SecretMetadataDto(
            secret.Name,
            latestVersion.Version,
            latestVersion.ContentType,
            latestVersion.KeyReference,
            latestVersion.IsRevoked,
            latestVersion.Expires);
    }
}
