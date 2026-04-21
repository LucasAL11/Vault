using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Application.Abstractions.Security;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Secrets;

public sealed record RequestSecretValueQuery(Guid VaultId, string Name)
    : IQuery<RequestedSecretValueDto>;

public sealed class RequestSecretValueQueryHandler(
    IApplicationDbContext dbContext,
    ISecretProtector secretProtector)
    : IQueryHandler<RequestSecretValueQuery, RequestedSecretValueDto>
{
    public async Task<Result<RequestedSecretValueDto>> Handle(
        RequestSecretValueQuery query,
        CancellationToken cancellationToken = default)
    {
        var secret = await dbContext.Secrets
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.VaultId == query.VaultId 
                                       && x.Name == query.Name, cancellationToken);

        if (secret is null)
        {
            return Result.Failure<RequestedSecretValueDto>(SecretErrors.SecretNotFound(query.VaultId, query.Name));
        }

        var now = DateTimeOffset.UtcNow;
        
        var activeVersionsQuery = dbContext.SecretVersions
            .AsNoTracking()
            .Where(x => x.SecretId == secret.Id && !x.IsRevoked);

        Domain.vault.SecretVersion? activeVersion;
        
        
        
        
        if (DbProviderCompatibility.IsSqliteProvider(dbContext))
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
            return Result.Failure<RequestedSecretValueDto>(SecretErrors.SecretNotFound(query.VaultId, query.Name));
        }

        var plaintext = await secretProtector.UnprotectAsync(
            new ProtectedSecret(activeVersion.CipherText, activeVersion.Nonce, activeVersion.KeyReference),
            new SecretProtectionContext(query.VaultId, secret.Id, activeVersion.Version),
            cancellationToken);

        return new RequestedSecretValueDto(
            secret.Name,
            activeVersion.Version,
            activeVersion.ContentType,
            plaintext,
            activeVersion.Expires);
    }
}
