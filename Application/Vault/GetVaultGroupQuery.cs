using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault;

public sealed record GetVaultGroupQuery(Guid VaultId) : IQuery<string>;

internal sealed class GetVaultGroupQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<GetVaultGroupQuery, string>
{
    public async Task<Result<string>> Handle(GetVaultGroupQuery query, CancellationToken cancellationToken = default)
    {
        var vault = await dbContext.Vaults
            .AsNoTracking()
            .Where(x => x.Id == query.VaultId)
            .Select(x => new { x.Id, x.Group })
            .SingleOrDefaultAsync(cancellationToken);

        if (vault is null)
        {
            return Result.Failure<string>(VaultErrors.VaultNotFound(query.VaultId));
        }

        if (string.IsNullOrWhiteSpace(vault.Group))
        {
            return Result.Failure<string>(VaultErrors.VaultMissingGroup(query.VaultId));
        }

        return vault.Group;
    }
}
