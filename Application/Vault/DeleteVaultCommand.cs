using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault;

public sealed record DeleteVaultCommand(Guid VaultId, string Actor) : ICommand<DeleteVaultResultDto>;

public sealed record DeleteVaultResultDto(Guid Id, bool HardDeleted);

public sealed class DeleteVaultCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<DeleteVaultCommand, DeleteVaultResultDto>
{
    public async Task<Result<DeleteVaultResultDto>> Handle(
        DeleteVaultCommand command, CancellationToken cancellationToken = default)
    {
        var vault = await dbContext.Vaults
            .FirstOrDefaultAsync(v => v.Id == command.VaultId, cancellationToken);

        if (vault is null)
            return Result.Failure<DeleteVaultResultDto>(
                VaultErrors.VaultNotFound(command.VaultId));

        var hasActiveSecrets = await dbContext.Secrets
            .AnyAsync(s => s.VaultId == command.VaultId && s.Status == Status.Active,
                cancellationToken);

        if (hasActiveSecrets)
        {
            // Soft delete — vault has active secrets
            vault.Disable();
            await dbContext.SaveChangesAsync(cancellationToken);
            return new DeleteVaultResultDto(vault.Id, HardDeleted: false);
        }
        else
        {
            // Hard delete — vault is empty
            dbContext.Vaults.Remove(vault);
            await dbContext.SaveChangesAsync(cancellationToken);
            return new DeleteVaultResultDto(vault.Id, HardDeleted: true);
        }
    }
}
