
namespace Api.Logging;

internal static class SensitiveDataMasker
{
    private static readonly string[] SensitiveKeyMarkers =
    [
        "authorization",
        "token",
        "secret",
        "password",
        "cookie",
        "api-key",
        "apikey",
        "client-secret",
        "refresh_token"
    ];

    public static Dictionary<string, string> MaskHeaders(IHeaderDictionary headers)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var header in headers)
        {
            result[header.Key] = IsSensitiveKey(header.Key)
                ? MaskValue(header.Value.ToString())
                : NormalizeNonSensitiveValue(header.Value.ToString());
        }

        return result;
    }

    public static Dictionary<string, string> MaskQuery(IQueryCollection query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in query)
        {
            result[item.Key] = IsSensitiveKey(item.Key)
                ? MaskValue(item.Value.ToString())
                : NormalizeNonSensitiveValue(item.Value.ToString());
        }

        return result;
    }

    private static bool IsSensitiveKey(string key)
        => SensitiveKeyMarkers.Any(marker =>
            key.Contains(marker, StringComparison.OrdinalIgnoreCase));

    private static string MaskValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "***";
        }

        if (value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return "Bearer ***";
        }

        return "***";
    }

    private static string NormalizeNonSensitiveValue(string value)
    {
        const int maxLen = 256;
        return value.Length <= maxLen ? value : $"{value[..maxLen]}...";
    }
}
