using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Shared;

namespace Application.Vault.Secrets;

public sealed record RevokeSecretVersionCommand(
    Guid VaultId,
    string Name,
    int Version,
    string Reason,
    string Actor) : ICommand<RevokeSecretVersionResultDto>;

public sealed class RevokeSecretVersionCommandHandler(IApplicationDbContext dbContext)
    : ICommandHandler<RevokeSecretVersionCommand, RevokeSecretVersionResultDto>
{
    public async Task<Result<RevokeSecretVersionResultDto>> Handle(
        RevokeSecretVersionCommand command,
        CancellationToken cancellationToken = default)
    {
        var secret = await dbContext.Secrets
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.VaultId == command.VaultId && x.Name == command.Name, cancellationToken);

        if (secret is null)
        {
            return Result.Failure<RevokeSecretVersionResultDto>(SecretErrors.SecretNotFound(command.VaultId, command.Name));
        }

        var secretVersion = await dbContext.SecretVersions
            .SingleOrDefaultAsync(x => x.SecretId == secret.Id && x.Version == command.Version, cancellationToken);

        if (secretVersion is null)
        {
            return Result.Failure<RevokeSecretVersionResultDto>(
                SecretErrors.SecretVersionNotFound(command.VaultId, command.Name, command.Version));
        }

        var wasAlreadyRevoked = secretVersion.IsRevoked;
        if (!wasAlreadyRevoked)
        {
            secretVersion.Revoke();
        }

        await dbContext.SecretAuditEntries.AddAsync(
            new SecretAuditEntry(
                vaultId: command.VaultId,
                secretName: secret.Name,
                action: "SECRET_VERSION_REVOKE",
                actor: command.Actor,
                occurredAtUtc: DateTimeOffset.UtcNow,
                details: $"version={secretVersion.Version};reason={command.Reason};alreadyRevoked={wasAlreadyRevoked}"),
            cancellationToken);

        await dbContext.SaveChangesAsync(cancellationToken);

        return new RevokeSecretVersionResultDto(
            secret.Name,
            secretVersion.Version,
            secretVersion.IsRevoked,
            command.Reason,
            command.Actor,
            wasAlreadyRevoked);
    }
}
