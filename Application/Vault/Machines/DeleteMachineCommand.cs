using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Machines;

public sealed record DeleteMachineCommand(Guid VaultId, Guid MachineId) : ICommand<bool>;

internal sealed class DeleteMachineCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<DeleteMachineCommand, bool>
{
    public async Task<Result<bool>> Handle(DeleteMachineCommand command, CancellationToken cancellationToken = default)
    {
        var machine = await dbContext.VaultMachines
            .SingleOrDefaultAsync(x => x.VaultId == command.VaultId && x.Id == command.MachineId, cancellationToken);

        if (machine is null)
        {
            return Result.Failure<bool>(VaultErrors.MachineNotFound(command.VaultId, command.MachineId));
        }

        dbContext.VaultMachines.Remove(machine);
        await dbContext.SaveChangesAsync(cancellationToken);
        return true;
    }
}
