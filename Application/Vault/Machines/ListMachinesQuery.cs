using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Machines;

public sealed record ListMachinesQuery(Guid VaultId, VaultMachineStatus? Status) : IQuery<IReadOnlyCollection<MachineDto>>;

public sealed class ListMachinesQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<ListMachinesQuery, IReadOnlyCollection<MachineDto>>
{
    public async Task<Result<IReadOnlyCollection<MachineDto>>> Handle(ListMachinesQuery query, CancellationToken cancellationToken = default)
    {
        var baseQuery = dbContext.VaultMachines
            .AsNoTracking()
            .Where(x => x.VaultId == query.VaultId);

        if (query.Status.HasValue)
        {
            baseQuery = baseQuery.Where(x => x.Status == query.Status.Value);
        }

        var items = await (
            from machine in baseQuery
            join computer in dbContext.Computers.AsNoTracking()
                on machine.ComputerId equals computer.Id
            select new MachineDto(
                machine.Id,
                machine.VaultId,
                machine.ComputerId,
                computer.Name,
                machine.Status,
                machine.CreatedAt,
                machine.LastSeenAt))
            .ToListAsync(cancellationToken);

        return items
            .OrderByDescending(x => x.CreatedAt)
            .ToArray();
    }
}
