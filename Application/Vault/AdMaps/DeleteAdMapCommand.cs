using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.AdMaps;

public sealed record DeleteAdMapCommand(Guid VaultId, Guid AdMapId) : ICommand<bool>;

internal sealed class DeleteAdMapCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<DeleteAdMapCommand, bool>
{
    public async Task<Result<bool>> Handle(DeleteAdMapCommand command, CancellationToken cancellationToken = default)
    {
        var adMap = await dbContext.ADMaps
            .SingleOrDefaultAsync(x => x.VaultId == command.VaultId && x.Id == command.AdMapId, cancellationToken);

        if (adMap is null)
        {
            return Result.Failure<bool>(VaultErrors.AdMapNotFound(command.VaultId, command.AdMapId));
        }

        dbContext.ADMaps.Remove(adMap);
        await dbContext.SaveChangesAsync(cancellationToken);
        return true;
    }
}
