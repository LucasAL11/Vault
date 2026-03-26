using VaultEnvironment = Domain.vault.Environment;

namespace Application.Vault.Secrets;

public sealed class SecretVersionRetentionOptions
{
    public SecretVersionRetentionRule[] Rules { get; set; } = [];

    public ResolvedSecretVersionRetentionPolicy ResolvePolicy(VaultEnvironment environment, string secretName, string contentType)
    {
        var secretType = SecretTypeClassifier.Classify(secretName, contentType);
        var environmentName = environment.ToString();

        var normalizedRules = Rules
            .Select(static x => x.GetNormalized())
            .ToArray();

        var matched = normalizedRules
            .Select(rule => new { Rule = rule, Score = rule.GetMatchScore(environmentName, secretType) })
            .Where(x => x.Score >= 0)
            .OrderByDescending(x => x.Score)
            .ThenBy(x => x.Rule.Name, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();

        var selected = matched?.Rule ?? SecretVersionRetentionRule.CreateFallback();
        return new ResolvedSecretVersionRetentionPolicy(selected, secretType);
    }
}

public sealed class SecretVersionRetentionRule
{
    public string Name { get; set; } = "fallback";
    public string Environment { get; set; } = "*";
    public string SecretType { get; set; } = "*";
    public int MaxVersionsToRetain { get; set; } = 20;
    public bool RequireExpiration { get; set; }
    public int DefaultExpirationDays { get; set; } = 30;
    public int MinExpirationMinutes { get; set; } = 15;
    public int MaxExpirationDays { get; set; } = 180;

    public SecretVersionRetentionRule GetNormalized()
    {
        return new SecretVersionRetentionRule
        {
            Name = string.IsNullOrWhiteSpace(Name) ? "fallback" : Name.Trim(),
            Environment = NormalizeSelector(Environment),
            SecretType = NormalizeSelector(SecretType),
            MaxVersionsToRetain = Math.Clamp(MaxVersionsToRetain, 1, 500),
            RequireExpiration = RequireExpiration,
            DefaultExpirationDays = Math.Clamp(DefaultExpirationDays, 0, 3650),
            MinExpirationMinutes = Math.Clamp(MinExpirationMinutes, 0, 525_600),
            MaxExpirationDays = Math.Clamp(MaxExpirationDays, 0, 3650)
        };
    }

    public static SecretVersionRetentionRule CreateFallback()
    {
        return new SecretVersionRetentionRule
        {
            Name = "fallback",
            Environment = "*",
            SecretType = "*",
            MaxVersionsToRetain = 20,
            RequireExpiration = false,
            DefaultExpirationDays = 30,
            MinExpirationMinutes = 15,
            MaxExpirationDays = 180
        };
    }

    public int GetMatchScore(string environmentName, string secretType)
    {
        var normalizedEnvironment = NormalizeSelector(environmentName);
        var normalizedSecretType = NormalizeSelector(secretType);

        var environmentMatches = Environment == "*" || string.Equals(Environment, normalizedEnvironment, StringComparison.OrdinalIgnoreCase);
        var typeMatches = SecretType == "*" || string.Equals(SecretType, normalizedSecretType, StringComparison.OrdinalIgnoreCase);
        if (!environmentMatches || !typeMatches)
        {
            return -1;
        }

        var score = 0;
        if (Environment != "*")
        {
            score += 2;
        }

        if (SecretType != "*")
        {
            score += 1;
        }

        return score;
    }

    private static string NormalizeSelector(string? selector)
    {
        if (string.IsNullOrWhiteSpace(selector))
        {
            return "*";
        }

        var normalized = selector.Trim();
        return string.Equals(normalized, "*", StringComparison.Ordinal) ? "*" : normalized;
    }
}

public sealed class ResolvedSecretVersionRetentionPolicy
{
    public ResolvedSecretVersionRetentionPolicy(SecretVersionRetentionRule rule, string secretType)
    {
        RuleName = rule.Name;
        SecretType = secretType;
        MaxVersionsToRetain = rule.MaxVersionsToRetain;
        RequireExpiration = rule.RequireExpiration;
        DefaultExpirationDays = rule.DefaultExpirationDays;
        MinExpirationMinutes = rule.MinExpirationMinutes;
        MaxExpirationDays = rule.MaxExpirationDays;
    }

    public string RuleName { get; }
    public string SecretType { get; }
    public int MaxVersionsToRetain { get; }
    public bool RequireExpiration { get; }
    public int DefaultExpirationDays { get; }
    public int MinExpirationMinutes { get; }
    public int MaxExpirationDays { get; }

    public bool TryResolveExpiration(
        DateTimeOffset? requestedExpiresUtc,
        DateTimeOffset nowUtc,
        out DateTimeOffset? effectiveExpiresUtc,
        out string errorMessage)
    {
        if (requestedExpiresUtc.HasValue)
        {
            var requested = requestedExpiresUtc.Value;
            if (requested <= nowUtc)
            {
                effectiveExpiresUtc = null;
                errorMessage = "expiresUtc must be in the future.";
                return false;
            }

            if (MinExpirationMinutes > 0)
            {
                var minimum = nowUtc.AddMinutes(MinExpirationMinutes);
                if (requested < minimum)
                {
                    effectiveExpiresUtc = null;
                    errorMessage = $"expiresUtc is below the minimum window for policy '{RuleName}'.";
                    return false;
                }
            }

            if (MaxExpirationDays > 0)
            {
                var maximum = nowUtc.AddDays(MaxExpirationDays);
                if (requested > maximum)
                {
                    effectiveExpiresUtc = null;
                    errorMessage = $"expiresUtc exceeds the maximum window for policy '{RuleName}'.";
                    return false;
                }
            }

            effectiveExpiresUtc = requested;
            errorMessage = string.Empty;
            return true;
        }

        if (DefaultExpirationDays > 0)
        {
            effectiveExpiresUtc = nowUtc.AddDays(DefaultExpirationDays);
            errorMessage = string.Empty;
            return true;
        }

        if (RequireExpiration)
        {
            effectiveExpiresUtc = null;
            errorMessage = $"expiresUtc is required for policy '{RuleName}'.";
            return false;
        }

        effectiveExpiresUtc = null;
        errorMessage = string.Empty;
        return true;
    }
}

internal static class SecretTypeClassifier
{
    public static string Classify(string secretName, string contentType)
    {
        var normalizedName = secretName.Trim().ToUpperInvariant();
        var normalizedContentType = contentType.Trim().ToLowerInvariant();

        if (ContainsAny(normalizedName, ["CERT", "CERTIFICATE", "PFX", "PEM"]) ||
            normalizedContentType.Contains("pkcs12", StringComparison.OrdinalIgnoreCase) ||
            normalizedContentType.Contains("pem", StringComparison.OrdinalIgnoreCase))
        {
            return "Certificate";
        }

        if (ContainsAny(normalizedName, ["TOKEN", "JWT", "BEARER", "SESSION"]))
        {
            return "Token";
        }

        if (ContainsAny(normalizedName, ["PASSWORD", "PASS", "PWD", "SECRET", "API_KEY", "CONNECTION", "KEY"]))
        {
            return "Credential";
        }

        return "Generic";
    }

    private static bool ContainsAny(string input, string[] terms)
    {
        return terms.Any(input.Contains);
    }
}
