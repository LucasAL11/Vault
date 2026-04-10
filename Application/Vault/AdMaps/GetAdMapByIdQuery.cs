using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.AdMaps;

public sealed record GetAdMapByIdQuery(Guid VaultId, Guid AdMapId) : IQuery<AdMapDto>;

internal sealed class GetAdMapByIdQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<GetAdMapByIdQuery, AdMapDto>
{
    public async Task<Result<AdMapDto>> Handle(GetAdMapByIdQuery query, CancellationToken cancellationToken = default)
    {
        var item = await dbContext.ADMaps
            .AsNoTracking()
            .Where(x => x.VaultId == query.VaultId && x.Id == query.AdMapId)
            .Select(x => new AdMapDto(
                x.Id,
                x.VaultId,
                x.GroupId,
                x.Permission,
                x.IsActive,
                x.CreatedAt))
            .SingleOrDefaultAsync(cancellationToken);

        return item is null
            ? Result.Failure<AdMapDto>(VaultErrors.AdMapNotFound(query.VaultId, query.AdMapId))
            : item;
    }
}
