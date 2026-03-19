namespace Api.Security;

public sealed class RateLimitingOptions
{
    public int RetryAfterSeconds { get; set; } = 60;

    public FixedWindowPolicyOptions SecretRead { get; set; } = new() { PermitLimit = 20 };
    public FixedWindowPolicyOptions SecretWrite { get; set; } = new() { PermitLimit = 10 };
    public FixedWindowPolicyOptions SecretAuditRead { get; set; } = new() { PermitLimit = 10 };

    public FixedWindowPolicyOptions AuthChallenge { get; set; } = new() { PermitLimit = 30 };
    public FixedWindowPolicyOptions AuthChallengeVerify { get; set; } = new() { PermitLimit = 60 };
    public FixedWindowPolicyOptions AuthChallengeRespond { get; set; } = new() { PermitLimit = 20 };

    public FixedWindowPolicyOptions ZkSensitive { get; set; } = new() { PermitLimit = 30 };
    public FixedWindowPolicyOptions OpsSensitive { get; set; } = new() { PermitLimit = 20 };
}

public sealed class FixedWindowPolicyOptions
{
    public int PermitLimit { get; set; } = 20;
    public int WindowSeconds { get; set; } = 60;
    public int QueueLimit { get; set; } = 0;
}
