using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Shared;

namespace Application.Vault.Secrets;

public sealed record AppendSecretAuditCommand(
    Guid? VaultId,
    string? SecretName,
    string Action,
    string Actor,
    string? Details,
    bool SaveChanges = true) : ICommand;

public sealed class AppendSecretAuditCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<AppendSecretAuditCommand>
{
    public async Task<Result> Handle(AppendSecretAuditCommand command, CancellationToken cancellationToken = default)
    {
        await dbContext.SecretAuditEntries.AddAsync(
            new SecretAuditEntry(
                vaultId: command.VaultId,
                secretName: command.SecretName,
                action: command.Action,
                actor: command.Actor,
                occurredAtUtc: DateTimeOffset.UtcNow,
                details: command.Details),
            cancellationToken);

        if (command.SaveChanges)
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }

        return Result.Success();
    }
}
