namespace Api.Security;

public sealed class AuthChallengeOptions
{
    public Dictionary<string, string> ClientSecrets { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public int ClockSkewSeconds { get; init; } = 60;
}
