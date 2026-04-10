using System.Text;
using System.Security.Claims;

namespace Api.Endpoints.Users;

internal static class NonceChallengeScope
{
    public static string Build(
        HttpContext httpContext,
        string? clientId,
        string subject,
        string audience)
    {
        var normalizedClientId = string.IsNullOrWhiteSpace(clientId)
            ? "anonymous"
            : clientId.Trim();
        var normalizedSubject = NormalizeSubject(subject);
        var normalizedAudience = NormalizeAudience(audience);
        var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown-ip";
        return $"auth-challenge:{normalizedAudience}:{normalizedClientId}:{normalizedSubject}:{ip}";
    }

    public static bool TryResolveSubject(HttpContext httpContext, string? requestedSubject, out string subject)
    {
        if (!string.IsNullOrWhiteSpace(requestedSubject))
        {
            subject = NormalizeSubject(requestedSubject);
            return true;
        }

        var principal = httpContext.User;
        var identityName = principal?.Identity?.Name;
        if (!string.IsNullOrWhiteSpace(identityName))
        {
            subject = NormalizeSubject(identityName);
            return true;
        }

        var nameIdentifier = principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.IsNullOrWhiteSpace(nameIdentifier))
        {
            subject = NormalizeSubject(nameIdentifier);
            return true;
        }

        subject = string.Empty;
        return false;
    }

    public static string BuildCredentialSubject(string domain, string username)
    {
        return NormalizeSubject($"{domain.Trim()}\\{username.Trim()}");
    }

    private static string NormalizeSubject(string subject)
    {
        return subject
            .Trim()
            .Normalize(NormalizationForm.FormKC)
            .ToUpperInvariant();
    }

    private static string NormalizeAudience(string audience)
    {
        return audience
            .Trim()
            .Normalize(NormalizationForm.FormKC)
            .ToLowerInvariant();
    }
}
