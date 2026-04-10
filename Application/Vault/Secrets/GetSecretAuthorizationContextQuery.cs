using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Application.Vault;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Secrets;

public sealed record GetSecretAuthorizationContextQuery(Guid VaultId, VaultPermission RequiredPermission)
    : IQuery<SecretAuthorizationContextDto>;

public sealed class GetSecretAuthorizationContextQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<GetSecretAuthorizationContextQuery, SecretAuthorizationContextDto>
{
    public async Task<Result<SecretAuthorizationContextDto>> Handle(
        GetSecretAuthorizationContextQuery query,
        CancellationToken cancellationToken = default)
    {
        var vault = await dbContext.Vaults
            .AsNoTracking()
            .Where(x => x.Id == query.VaultId)
            .Select(x => new { x.Id, x.Status, x.Group })
            .SingleOrDefaultAsync(cancellationToken);

        if (vault is null)
        {
            return Result.Failure<SecretAuthorizationContextDto>(VaultErrors.VaultNotFound(query.VaultId));
        }

        var candidateGroups = await dbContext.ADMaps
            .AsNoTracking()
            .Where(x => x.VaultId == query.VaultId && x.IsActive && (int)x.Permission >= (int)query.RequiredPermission)
            .Select(x => x.GroupId)
            .Distinct()
            .ToListAsync(cancellationToken);

        return new SecretAuthorizationContextDto(
            vault.Id,
            vault.Status,
            vault.Group,
            candidateGroups);
    }
}
