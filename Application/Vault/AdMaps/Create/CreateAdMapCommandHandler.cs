using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.AdMaps.create;

public sealed class CreateAdMapCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<CreateAdMapCommand, AdMapDto>
{
    public async Task<Result<AdMapDto>> Handle(CreateAdMapCommand commandHandler, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(commandHandler.GroupId))
        {
            return Result.Failure<AdMapDto>(VaultErrors.InvalidGroupId());
        }

        var normalizedGroupId = commandHandler.GroupId.Trim();
        var exists = await dbContext.ADMaps
            .AsNoTracking()
            .AnyAsync(x => x.VaultId == commandHandler.VaultId && x.GroupId == normalizedGroupId, cancellationToken);

        if (exists)
        {
            return Result.Failure<AdMapDto>(VaultErrors.AdMapAlreadyExists(commandHandler.VaultId, normalizedGroupId));
        }

        var adMap = new ADMap(commandHandler.VaultId, normalizedGroupId, commandHandler.Permission);
        if (!commandHandler.IsActive)
        {
            adMap.Disable();
        }

        await dbContext.ADMaps.AddAsync(adMap, cancellationToken);
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
