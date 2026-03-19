namespace Domain.KillSwitch;

public sealed class KillSwitchOptions
{
    public bool Enabled { get; init; }
    public string? AllowedGroup { get; init; }
    public int RetryAfterSeconds { get; init; } = 120;
    public string Message { get; init; } = "Service temporarily unavailable.";
    public List<KillSwitchDenyUserOption> DenyUsers { get; init; } = new();
}

public sealed class KillSwitchDenyUserOption
{
    public string Username { get; init; } = string.Empty;
    public DateTimeOffset ExpiresAtUtc { get; init; }
    public string? Reason { get; init; }
}
