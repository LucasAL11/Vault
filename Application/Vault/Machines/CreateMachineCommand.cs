using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Machines;

public sealed record CreateMachineCommand(Guid VaultId, int ComputerId) : ICommand<MachineDto>;

internal sealed class CreateMachineCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<CreateMachineCommand, MachineDto>
{
    public async Task<Result<MachineDto>> Handle(CreateMachineCommand command, CancellationToken cancellationToken = default)
    {
        if (command.ComputerId <= 0)
        {
            return Result.Failure<MachineDto>(VaultErrors.InvalidComputerId());
        }

        var computer = await dbContext.Computers
            .AsNoTracking()
            .Where(x => x.Id == command.ComputerId)
            .Select(x => new { x.Id, x.Name })
            .SingleOrDefaultAsync(cancellationToken);

        if (computer is null)
        {
            return Result.Failure<MachineDto>(VaultErrors.ComputerNotFound(command.ComputerId));
        }

        var existing = await dbContext.VaultMachines
            .AsNoTracking()
            .AnyAsync(x => x.VaultId == command.VaultId && x.ComputerId == command.ComputerId, cancellationToken);

        if (existing)
        {
            return Result.Failure<MachineDto>(VaultErrors.MachineAlreadyLinked(command.VaultId, command.ComputerId));
        }

        var machine = new VaultMachine(command.VaultId, command.ComputerId);
        await dbContext.VaultMachines.AddAsync(machine, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        return new MachineDto(
            machine.Id,
            machine.VaultId,
            machine.ComputerId,
            computer.Name,
            machine.Status,
            machine.CreatedAt,
            machine.LastSeenAt);
    }
}
