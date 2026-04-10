using Application.Abstractions.Data;
using Microsoft.EntityFrameworkCore;
using Application.Abstractions.Security;
using Domain.vault;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shared;

namespace Infrastructure.BackgroundJobs;

/// <summary>
/// Background service that automatically renews expiring (but not revoked) secret versions.
/// Decrypts the current value and creates a new version with extended expiration.
/// Revoked versions are never renewed — they require manual password change.
/// </summary>
public sealed class SecretVersionRenewalService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ISecretProtector _secretProtector;
    private readonly SecretRenewalOptions _options;
    private readonly ILogger<SecretVersionRenewalService> _logger;

    public SecretVersionRenewalService(
        IServiceScopeFactory scopeFactory,
        ISecretProtector secretProtector,
        IOptions<SecretRenewalOptions> options,
        ILogger<SecretVersionRenewalService> logger)
    {
        _scopeFactory = scopeFactory;
        _secretProtector = secretProtector;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "SecretVersionRenewalService started. Interval={IntervalMin}m, RenewWindow={WindowMin}m, NewLifetime={LifetimeDays}d",
            _options.IntervalMinutes,
            _options.RenewBeforeExpirationMinutes,
            _options.NewVersionLifetimeDays);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RenewExpiringVersionsAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SecretVersionRenewalService encountered an error during renewal cycle");
            }

            await Task.Delay(TimeSpan.FromMinutes(_options.IntervalMinutes), stoppingToken);
        }
    }

    private async Task RenewExpiringVersionsAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var expirationThreshold = now.AddMinutes(_options.RenewBeforeExpirationMinutes);

        // Phase 1: collect IDs only — short-lived scope, no entity tracking beyond IDs
        List<Guid> secretIds;
        using (var scope = _scopeFactory.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IApplicationDbContext>();
            secretIds = await db.Secrets
                .Where(s => s.Status == Status.Active)
                .Where(s => s.Versions.Any(v =>
                    !v.IsRevoked &&
                    v.Expires != null &&
                    v.Expires <= expirationThreshold &&
                    v.Version == s.CurrentVersion))
                .Select(s => s.Id)
                .ToListAsync(ct);
        }

        if (secretIds.Count == 0) return;

        _logger.LogInformation("SecretVersionRenewal: found {Count} secret(s) with expiring versions", secretIds.Count);

        var renewed = 0;
        var skipped = 0;

        // Phase 2: each secret gets its own scope so a failed save never contaminates the next iteration
        foreach (var secretId in secretIds)
        {
            var result = await RenewSecretAsync(secretId, now, ct);

            if (result.IsSuccess)
                renewed++;
            else
            {
                skipped++;
                if (result.Error.Type == ErrorType.Conflict)
                    _logger.LogWarning(
                        "SecretVersionRenewal: concurrency conflict for Secret={SecretId} — will retry next cycle",
                        secretId);
                else
                    _logger.LogWarning(
                        "SecretVersionRenewal: skipped Secret={SecretId} — {Reason}",
                        secretId,
                        result.Error.Description);
            }
        }

        _logger.LogInformation("SecretVersionRenewal: cycle complete. Renewed={Renewed}, Skipped={Skipped}", renewed, skipped);
    }

    private async Task<Result> RenewSecretAsync(Guid secretId, DateTimeOffset now, CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IApplicationDbContext>();

        var secret = await dbContext.Secrets
            .Include(s => s.Versions)
            .FirstOrDefaultAsync(s => s.Id == secretId, ct);

        if (secret is null)
            return Result.Failure(Error.NotFound(
                "Secret.NotFound",
                $"Secret {secretId} no longer exists"));

        var currentVersion = secret.Versions
            .FirstOrDefault(v => v.Version == secret.CurrentVersion && !v.IsRevoked);

        if (currentVersion is null)
            return Result.Failure(Error.NotFound(
                "Secret.CurrentVersion.NotFound",
                "No active current version found"));

        var plaintext = await _secretProtector.UnprotectAsync(
            new ProtectedSecret(currentVersion.CipherText, currentVersion.Nonce, currentVersion.KeyReference),
            new SecretProtectionContext(secret.VaultId, secret.Id, currentVersion.Version),
            ct);

        var nextVersion = secret.CurrentVersion + 1;
        var newExpires = _options.NewVersionLifetimeDays.HasValue
            ? now.AddDays(_options.NewVersionLifetimeDays.Value)
            : (DateTimeOffset?)null;

        var protectedSecret = await _secretProtector.ProtectAsync(
            plaintext,
            new SecretProtectionContext(secret.VaultId, secret.Id, nextVersion),
            ct);

        secret.AddVersion(
            protectedSecret.CipherText,
            protectedSecret.Nonce,
            protectedSecret.KeyId,
            currentVersion.ContentType,
            newExpires);

        try
        {
            await dbContext.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            return Result.Failure(Error.Conflict(
                "Secret.ConcurrencyConflict",
                "Secret was modified concurrently"));
        }

        _logger.LogInformation(
            "SecretVersionRenewal: renewed VaultId={VaultId}, Secret={SecretName}, v{OldVersion} -> v{NewVersion}, Expires={Expires}",
            secret.VaultId,
            secret.Name,
            currentVersion.Version,
            nextVersion,
            newExpires?.ToString("O") ?? "never");

        return Result.Success();
    }
}
