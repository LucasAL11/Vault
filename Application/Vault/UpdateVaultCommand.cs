using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault;

public sealed record UpdateVaultCommand(
    Guid VaultId,
    string Name,
    string Description,
    string Actor) : ICommand<UpdateVaultResultDto>;

public sealed record UpdateVaultResultDto(Guid Id, string Name, string Description);

public sealed class UpdateVaultCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<UpdateVaultCommand, UpdateVaultResultDto>
{
    public async Task<Result<UpdateVaultResultDto>> Handle(
        UpdateVaultCommand command, CancellationToken cancellationToken = default)
    {
        var vault = await dbContext.Vaults
            .FirstOrDefaultAsync(v => v.Id == command.VaultId, cancellationToken);

        if (vault is null)
            return Result.Failure<UpdateVaultResultDto>(
                VaultErrors.VaultNotFound(command.VaultId));

        vault.Update(command.Name, command.Description);

        await dbContext.SaveChangesAsync(cancellationToken);

        return new UpdateVaultResultDto(vault.Id, vault.Name, vault.Description);
    }
}
