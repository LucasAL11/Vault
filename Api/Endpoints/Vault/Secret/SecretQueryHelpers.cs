using Domain.vault;

namespace Api.Endpoints.Vault.Secret;

internal static class SecretQueryHelpers
{
    internal static bool TryParseStatusFilter(string? status, out Status? parsedStatus)
    {
        parsedStatus = null;
        if (string.IsNullOrWhiteSpace(status))
            return true;

        if (Enum.TryParse<Status>(status.Trim(), ignoreCase: true, out var value))
        {
            parsedStatus = value;
            return true;
        }

        return false;
    }

    internal static bool TryNormalizeSecretSortBy(string? orderBy, out string normalizedSortBy)
    {
        if (string.IsNullOrWhiteSpace(orderBy)) { normalizedSortBy = "name"; return true; }

        var normalized = orderBy.Trim();
        if (normalized.Equals("name", StringComparison.OrdinalIgnoreCase)) { normalizedSortBy = "name"; return true; }
        if (normalized.Equals("status", StringComparison.OrdinalIgnoreCase)) { normalizedSortBy = "status"; return true; }
        if (normalized.Equals("currentVersion", StringComparison.OrdinalIgnoreCase)) { normalizedSortBy = "currentVersion"; return true; }

        normalizedSortBy = string.Empty;
        return false;
    }

    internal static bool TryNormalizeSortDirection(string? orderDirection, out string normalizedSortDirection)
    {
        if (string.IsNullOrWhiteSpace(orderDirection)) { normalizedSortDirection = "asc"; return true; }

        var normalized = orderDirection.Trim();
        if (normalized.Equals("asc", StringComparison.OrdinalIgnoreCase)) { normalizedSortDirection = "asc"; return true; }
        if (normalized.Equals("desc", StringComparison.OrdinalIgnoreCase)) { normalizedSortDirection = "desc"; return true; }

        normalizedSortDirection = string.Empty;
        return false;
    }

    internal static IQueryable<Domain.vault.Secret> ApplySecretSorting(
        this IQueryable<Domain.vault.Secret> query,
        string sortBy,
        string sortDirection)
    {
        var descending = string.Equals(sortDirection, "desc", StringComparison.OrdinalIgnoreCase);

        return sortBy switch
        {
            "status" when descending => query.OrderByDescending(x => x.Status).ThenBy(x => x.Name).ThenBy(x => x.Id),
            "status"                 => query.OrderBy(x => x.Status).ThenBy(x => x.Name).ThenBy(x => x.Id),
            "currentVersion" when descending => query.OrderByDescending(x => x.CurrentVersion).ThenBy(x => x.Name).ThenBy(x => x.Id),
            "currentVersion"         => query.OrderBy(x => x.CurrentVersion).ThenBy(x => x.Name).ThenBy(x => x.Id),
            "name" when descending   => query.OrderByDescending(x => x.Name).ThenBy(x => x.Id),
            _                        => query.OrderBy(x => x.Name).ThenBy(x => x.Id),
        };
    }
}
