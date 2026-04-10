using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Machines;

public sealed record GetMachineByIdQuery(Guid VaultId, Guid MachineId) : IQuery<MachineDto>;

internal sealed class GetMachineByIdQueryHandler(IApplicationDbContext dbContext)
    : IQueryHandler<GetMachineByIdQuery, MachineDto>
{
    public async Task<Result<MachineDto>> Handle(GetMachineByIdQuery query, CancellationToken cancellationToken = default)
    {
        var machine = await (
            from vm in dbContext.VaultMachines.AsNoTracking()
            join computer in dbContext.Computers.AsNoTracking()
                on vm.ComputerId equals computer.Id
            where vm.VaultId == query.VaultId && vm.Id == query.MachineId
            select new MachineDto(
                vm.Id,
                vm.VaultId,
                vm.ComputerId,
                computer.Name,
                vm.Status,
                vm.CreatedAt,
                vm.LastSeenAt))
            .SingleOrDefaultAsync(cancellationToken);

        return machine is null
            ? Result.Failure<MachineDto>(VaultErrors.MachineNotFound(query.VaultId, query.MachineId))
            : machine;
    }
}
