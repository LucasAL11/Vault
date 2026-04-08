using System.Text;

namespace Api.Security;

internal static class InputValidation
{
    public static bool TryNormalizeText(string? input, int minLength, int maxLength, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var candidate = input.Trim().Normalize(NormalizationForm.FormKC);
        if (candidate.Length < minLength || candidate.Length > maxLength)
        {
            return false;
        }

        if (candidate.Any(char.IsControl))
        {
            return false;
        }

        normalized = candidate;
        return true;
    }

    public static bool TryNormalizeAsciiToken(
        string? input,
        int minLength,
        int maxLength,
        string allowedSymbols,
        out string normalized)
    {
        normalized = string.Empty;
        if (!TryNormalizeText(input, minLength, maxLength, out var candidate))
        {
            return false;
        }

        foreach (var ch in candidate)
        {
            if (ch > 0x7F)
            {
                return false;
            }

            if (char.IsLetterOrDigit(ch))
            {
                continue;
            }

            if (allowedSymbols.IndexOf(ch) >= 0)
            {
                continue;
            }

            return false;
        }

        normalized = candidate;
        return true;
    }

    public static bool TryDecodeBase64Url(
        string? input,
        int minByteLength,
        int maxByteLength,
        int maxEncodedLength,
        out string normalizedInput,
        out byte[] bytes)
    {
        normalizedInput = string.Empty;
        bytes = Array.Empty<byte>();

        if (!TryNormalizeText(input, minLength: 1, maxLength: maxEncodedLength, out var candidate))
        {
            return false;
        }

        if (candidate.Any(ch => !IsBase64UrlChar(ch)))
        {
            return false;
        }

        normalizedInput = candidate;

        var normalizedBase64 = candidate.Replace('-', '+').Replace('_', '/');
        switch (normalizedBase64.Length % 4)
        {
            case 2:
                normalizedBase64 += "==";
                break;
            case 3:
                normalizedBase64 += "=";
                break;
            case 1:
                return false;
        }

        try
        {
            bytes = Convert.FromBase64String(normalizedBase64);
        }
        catch (FormatException)
        {
            bytes = Array.Empty<byte>();
            return false;
        }

        if (bytes.Length < minByteLength || bytes.Length > maxByteLength)
        {
            bytes = Array.Empty<byte>();
            return false;
        }

        return true;
    }

    private static bool IsBase64UrlChar(char ch)
    {
        return ch is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9'
            or '-'
            or '_';
    }
}
