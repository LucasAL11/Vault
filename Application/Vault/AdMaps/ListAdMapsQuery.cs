using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.AdMaps;

public sealed record ListAdMapsQuery(Guid VaultId, bool IncludeInactive, VaultPermission? Permission)
    : IQuery<IReadOnlyCollection<AdMapDto>>;

internal sealed class ListAdMapsQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<ListAdMapsQuery, IReadOnlyCollection<AdMapDto>>
{
    public async Task<Result<IReadOnlyCollection<AdMapDto>>> Handle(ListAdMapsQuery query, CancellationToken cancellationToken = default)
    {
        var baseQuery = dbContext.ADMaps
            .AsNoTracking()
            .Where(x => x.VaultId == query.VaultId);

        if (!query.IncludeInactive)
        {
            baseQuery = baseQuery.Where(x => x.IsActive);
        }

        if (query.Permission.HasValue)
        {
            baseQuery = baseQuery.Where(x => x.Permission == query.Permission.Value);
        }

        var items = await baseQuery
            .Select(x => new AdMapDto(
                x.Id,
                x.VaultId,
                x.GroupId,
                x.Permission,
                x.IsActive,
                x.CreatedAt))
            .ToListAsync(cancellationToken);

        return items
            .OrderByDescending(x => x.CreatedAt)
            .ToArray();
    }
}
