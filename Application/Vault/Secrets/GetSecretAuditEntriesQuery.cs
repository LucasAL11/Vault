using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Secrets;

public sealed record GetSecretAuditEntriesQuery(Guid VaultId, string SecretName, int Take)
    : IQuery<SecretAuditDto>;

public sealed class GetSecretAuditEntriesQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<GetSecretAuditEntriesQuery, SecretAuditDto>
{
    public async Task<Result<SecretAuditDto>> Handle(
        GetSecretAuditEntriesQuery query,
        CancellationToken cancellationToken = default)
    {
        var auditQuery = dbContext.SecretAuditEntries
            .AsNoTracking()
            .Where(x => x.VaultId == query.VaultId && x.SecretName == query.SecretName)
            .Select(x => new SecretAuditEntryDto(
                x.Action,
                x.Actor,
                x.OccurredAtUtc,
                x.Details));

        IReadOnlyCollection<SecretAuditEntryDto> entries;
        if (DbProviderCompatibility.IsSqliteProvider(dbContext))
        {
            entries = (await auditQuery.ToListAsync(cancellationToken))
                .OrderByDescending(x => x.OccurredAtUtc)
                .Take(query.Take)
                .ToArray();
        }
        else
        {
            entries = await auditQuery
                .OrderByDescending(x => x.OccurredAtUtc)
                .Take(query.Take)
                .ToArrayAsync(cancellationToken);
        }

        return new SecretAuditDto(
            query.VaultId,
            query.SecretName,
            query.Take,
            entries);
    }
}
