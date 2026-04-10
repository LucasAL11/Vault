using Application.Abstractions.Data;
using Application.Abstractions.Security;
using Domain.vault;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

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
        using var scope = _scopeFactory.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IApplicationDbContext>();

        var now = DateTimeOffset.UtcNow;
        var expirationThreshold = now.AddMinutes(_options.RenewBeforeExpirationMinutes);

        // Find all secrets that have a latest non-revoked version expiring within the window
        var secrets = await dbContext.Secrets
            .Include(s => s.Versions)
            .Where(s => s.Status == Status.Active)
            .Where(s => s.Versions.Any(v =>
                !v.IsRevoked &&
                v.Expires != null &&
                v.Expires <= expirationThreshold &&
                v.Version == s.CurrentVersion))
            .ToListAsync(ct);

        if (secrets.Count == 0) return;

        _logger.LogInformation("SecretVersionRenewal: found {Count} secret(s) with expiring versions", secrets.Count);

        var renewed = 0;
        var skipped = 0;

        foreach (var secret in secrets)
        {
            try
            {
                var currentVersion = secret.Versions
                    .Where(v => v.Version == secret.CurrentVersion && !v.IsRevoked)
                    .FirstOrDefault();

                if (currentVersion is null)
                {
                    skipped++;
                    continue;
                }

                // Decrypt current value
                var plaintext = await _secretProtector.UnprotectAsync(
                    new ProtectedSecret(currentVersion.CipherText, currentVersion.Nonce, currentVersion.KeyReference),
                    new SecretProtectionContext(secret.VaultId, secret.Id, currentVersion.Version),
                    ct);

                // Re-encrypt into a new version
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
                    renewed++;

                    _logger.LogInformation(
                        "SecretVersionRenewal: renewed VaultId={VaultId}, Secret={SecretName}, v{OldVersion} -> v{NewVersion}, Expires={Expires}",
                        secret.VaultId,
                        secret.Name,
                        currentVersion.Version,
                        nextVersion,
                        newExpires?.ToString("O") ?? "never");
                }
                catch (DbUpdateConcurrencyException ex)
                {
                    skipped++;
                    _logger.LogWarning(ex,
                        "SecretVersionRenewal: concurrency conflict skipped VaultId={VaultId}, Secret={SecretName} — will retry next cycle",
                        secret.VaultId,
                        secret.Name);

                    // Detach stale entries so the next iteration starts clean
                    foreach (var entry in ex.Entries)
                        entry.State = EntityState.Detached;
                }
            }
            catch (Exception ex)
            {
                skipped++;
                _logger.LogWarning(ex,
                    "SecretVersionRenewal: failed to renew VaultId={VaultId}, Secret={SecretName}",
                    secret.VaultId,
                    secret.Name);
            }
        }

        _logger.LogInformation("SecretVersionRenewal: cycle complete. Renewed={Renewed}, Skipped={Skipped}", renewed, skipped);
    }
}
