using Api.Security;

namespace Api.Endpoints.Users;

public static class NonceChallengeAudiences
{
    public const string AuthChallengeVerify = "auth.challenge.verify";
    public const string AuthChallengeRespond = "auth.challenge.respond";
    public const string VaultSecretRequest = "vault.secret.request";
    public const string WebApp1 = "webapplication1";

    public static bool TryNormalize(string? audience, out string normalizedAudience)
    {
        normalizedAudience = string.Empty;
        if (!InputValidation.TryNormalizeAsciiToken(audience, minLength: 1, maxLength: 64, allowedSymbols: "._-", out var candidate))
        {
            return false;
        }

        var normalized = candidate.ToLowerInvariant();
        switch (normalized)
        {
            case AuthChallengeVerify:
            case AuthChallengeRespond:
            case VaultSecretRequest:
            case WebApp1:    
                normalizedAudience = normalized;
                return true;
            default:
                return false;
        }
    }
}
