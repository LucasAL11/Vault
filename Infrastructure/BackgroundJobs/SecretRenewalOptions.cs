namespace Infrastructure.BackgroundJobs;

public sealed class SecretRenewalOptions
{
    /// <summary>How often the renewal job runs (default: 1 hour).</summary>
    public int IntervalMinutes { get; init; } = 60;

    /// <summary>Renew versions expiring within this window (default: 24 hours).</summary>
    public int RenewBeforeExpirationMinutes { get; init; } = 1440;

    /// <summary>New version lifetime after renewal (default: 7 days). Null = no expiration.</summary>
    public int? NewVersionLifetimeDays { get; init; } = 7;
}
