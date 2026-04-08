using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Application.Abstractions.Security;
using Application.Vault;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Shared;

namespace Application.Vault.Secrets;

public sealed record UpsertSecretCommand(
    Guid VaultId,
    string Name,
    string Value,
    string ContentType,
    DateTimeOffset? ExpiresUtc,
    string Actor) : ICommand<UpsertSecretResultDto>;

public sealed class UpsertSecretCommandHandler(
    IApplicationDbContext dbContext,
    ISecretProtector secretProtector,
    IOptions<SecretVersionRetentionOptions> retentionOptions)
    : ICommandHandler<UpsertSecretCommand, UpsertSecretResultDto>
{
    public async Task<Result<UpsertSecretResultDto>> Handle(
        UpsertSecretCommand command,
        CancellationToken cancellationToken = default)
    {
        var vault = await dbContext.Vaults
            .AsNoTracking()
            .Where(x => x.Id == command.VaultId)
            .Select(x => new
            {
                x.Id,
                x.Environment
            })
            .SingleOrDefaultAsync(cancellationToken);

        if (vault is null)
        {
            return Result.Failure<UpsertSecretResultDto>(VaultErrors.VaultNotFound(command.VaultId));
        }

        var retentionPolicy = retentionOptions.Value.ResolvePolicy(vault.Environment, command.Name, command.ContentType);
        if (!retentionPolicy.TryResolveExpiration(
                command.ExpiresUtc,
                DateTimeOffset.UtcNow,
                out var effectiveExpiresUtc,
                out var expirationPolicyError))
        {
            return Result.Failure<UpsertSecretResultDto>(SecretErrors.InvalidExpiration(expirationPolicyError));
        }

        var secret = await dbContext.Secrets
            .Include(x => x.Versions)
            .SingleOrDefaultAsync(x => x.VaultId == command.VaultId && x.Name == command.Name, cancellationToken);

        if (secret is null)
        {
            secret = new Secret(command.VaultId, command.Name);
            await dbContext.Secrets.AddAsync(secret, cancellationToken);
        }

        var nextVersion = secret.CurrentVersion + 1;
        var protectionContext = new SecretProtectionContext(command.VaultId, secret.Id, nextVersion);
        var protectedSecret = await secretProtector.ProtectAsync(command.Value, protectionContext, cancellationToken);

        var version = secret.AddVersion(
            protectedSecret.CipherText,
            protectedSecret.Nonce,
            protectedSecret.KeyId,
            command.ContentType,
            effectiveExpiresUtc);
        dbContext.SecretVersions.Add(version);

        var prunedVersionsCount = PruneOldVersions(secret, retentionPolicy.MaxVersionsToRetain, dbContext);

        await AppendAuditAsync(
            dbContext,
            action: "SECRET_WRITE",
            actor: command.Actor,
            vaultId: command.VaultId,
            secretName: secret.Name,
            details: $"version={version.Version};" +
                     $"keyId={version.KeyReference};" +
                     $"expires={version.Expires?.ToString("O") ?? "-"}" +
                     $";retentionRule={retentionPolicy.RuleName};" +
                     $"secretType={retentionPolicy.SecretType};" +
                     $"maxVersions={retentionPolicy.MaxVersionsToRetain};" +
                     $"pruned={prunedVersionsCount}",
            cancellationToken,
            saveChanges: false);

        await dbContext.SaveChangesAsync(cancellationToken);

        return new UpsertSecretResultDto(
            secret.Id,
            secret.Name,
            version.Version,
            version.KeyReference,
            version.Expires);
    }

    private static async Task AppendAuditAsync(
        IApplicationDbContext dbContext,
        string action,
        string actor,
        Guid? vaultId,
        string? secretName,
        string? details,
        CancellationToken cancellationToken,
        bool saveChanges = true)
    {
        await dbContext.SecretAuditEntries.AddAsync(
            new SecretAuditEntry(
                vaultId: vaultId,
                secretName: secretName,
                action: action,
                actor: actor,
                occurredAtUtc: DateTimeOffset.UtcNow,
                details: details),
            cancellationToken);

        if (saveChanges)
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    private static int PruneOldVersions(Secret secret, int maxVersionsToRetain, IApplicationDbContext dbContext)
    {
        if (maxVersionsToRetain < 1)
        {
            return 0;
        }

        var versionsToPrune = secret.Versions
            .OrderByDescending(x => x.Version)
            .Skip(maxVersionsToRetain)
            .ToArray();

        if (versionsToPrune.Length == 0)
        {
            return 0;
        }

        dbContext.SecretVersions.RemoveRange(versionsToPrune);
        return versionsToPrune.Length;
    }
}
