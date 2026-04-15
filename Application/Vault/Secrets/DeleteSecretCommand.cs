using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Secrets;

public sealed record DeleteSecretCommand(
    Guid VaultId,
    string Name,
    string Actor) : ICommand<DeleteSecretResultDto>;

public sealed record DeleteSecretResultDto(Guid VaultId, string Name);

public sealed class DeleteSecretCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<DeleteSecretCommand, DeleteSecretResultDto>
{
    public async Task<Result<DeleteSecretResultDto>> Handle(
        DeleteSecretCommand command,
        CancellationToken cancellationToken = default)
    {
        var secret = await dbContext.Secrets
            .Include(s => s.Versions)
            .SingleOrDefaultAsync(
                s => s.VaultId == command.VaultId && s.Name == command.Name,
                cancellationToken);

        if (secret is null)
        {
            return Result.Failure<DeleteSecretResultDto>(
                SecretErrors.SecretNotFound(command.VaultId, command.Name));
        }

        // Remove all versions first (FK constraint)
        dbContext.SecretVersions.RemoveRange(secret.Versions);
        dbContext.Secrets.Remove(secret);

        await dbContext.SecretAuditEntries.AddAsync(
            new SecretAuditEntry(
                vaultId: command.VaultId,
                secretName: secret.Name,
                action: "SECRET_DELETED",
                actor: command.Actor,
                occurredAtUtc: DateTimeOffset.UtcNow,
                details: $"versions={secret.Versions.Count}"),
            cancellationToken);

        await dbContext.SaveChangesAsync(cancellationToken);

        return new DeleteSecretResultDto(command.VaultId, secret.Name);
    }
}
