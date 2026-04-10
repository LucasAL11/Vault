using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.AdMaps;

public sealed record UpdateAdMapCommand(Guid VaultId, Guid AdMapId, VaultPermission Permission, bool IsActive)
    : ICommand<AdMapDto>;

internal sealed class UpdateAdMapCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<UpdateAdMapCommand, AdMapDto>
{
    public async Task<Result<AdMapDto>> Handle(UpdateAdMapCommand command, CancellationToken cancellationToken = default)
    {
        var adMap = await dbContext.ADMaps
            .SingleOrDefaultAsync(x => x.VaultId == command.VaultId && x.Id == command.AdMapId, cancellationToken);

        if (adMap is null)
        {
            return Result.Failure<AdMapDto>(VaultErrors.AdMapNotFound(command.VaultId, command.AdMapId));
        }

        adMap.UpdatePermission(command.Permission);
        if (command.IsActive)
        {
            adMap.Enable();
        }
        else
        {
            adMap.Disable();
        }

        await dbContext.SaveChangesAsync(cancellationToken);

        return new AdMapDto(
            adMap.Id,
            adMap.VaultId,
            adMap.GroupId,
            adMap.Permission,
            adMap.IsActive,
            adMap.CreatedAt);
    }
}
