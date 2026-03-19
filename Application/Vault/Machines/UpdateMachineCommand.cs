using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Machines;

public sealed record UpdateMachineCommand(Guid VaultId, Guid MachineId, VaultMachineStatus Status)
    : ICommand<MachineDto>;

public sealed class UpdateMachineCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<UpdateMachineCommand, MachineDto>
{
    public async Task<Result<MachineDto>> Handle(UpdateMachineCommand command, CancellationToken cancellationToken = default)
    {
        var machine = await dbContext.VaultMachines
            .SingleOrDefaultAsync(x => x.VaultId == command.VaultId && x.Id == command.MachineId, cancellationToken);

        if (machine is null)
        {
            return Result.Failure<MachineDto>(VaultErrors.MachineNotFound(command.VaultId, command.MachineId));
        }

        if (command.Status == VaultMachineStatus.Disabled)
        {
            machine.Disable();
        }
        else
        {
            machine.Enable();
            machine.MarkSeen();
        }

        await dbContext.SaveChangesAsync(cancellationToken);

        var computerName = await dbContext.Computers
            .AsNoTracking()
            .Where(x => x.Id == machine.ComputerId)
            .Select(x => x.Name)
            .SingleOrDefaultAsync(cancellationToken);

        return new MachineDto(
            machine.Id,
            machine.VaultId,
            machine.ComputerId,
            computerName,
            machine.Status,
            machine.CreatedAt,
            machine.LastSeenAt);
    }
}
