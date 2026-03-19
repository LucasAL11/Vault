using Microsoft.Extensions.Options;

namespace Domain.KillSwitch;

public sealed class KillSwitchState
{
    private readonly object _gate = new();
    private bool _enabled;
    private string? _allowedGroup;
    private int _retryAfterSeconds;
    private string _message;
    private readonly Dictionary<string, KillSwitchDenyUserEntry> _denyUsers = new(StringComparer.OrdinalIgnoreCase);

    public KillSwitchState(IOptionsMonitor<KillSwitchOptions> optionsMonitor)
    {
        Apply(optionsMonitor.CurrentValue);
        optionsMonitor.OnChange(Apply);
    }

    public KillSwitchSnapshot Current
    {
        get
        {
            lock (_gate)
            {
                PruneExpiredDenyUsers();

                return new KillSwitchSnapshot(
                    _enabled,
                    _allowedGroup,
                    _retryAfterSeconds,
                    _message,
                    _denyUsers.Values.OrderBy(x => x.Username).ToArray());
            }
        }
    }

    public void Set(bool enabled, string? allowedGroup = null, int? retryAfterSeconds = null, string? message = null)
    {
        lock (_gate)
        {
            _enabled = enabled;

            if (allowedGroup is not null)
            {
                _allowedGroup = string.IsNullOrWhiteSpace(allowedGroup) ? null : allowedGroup.Trim();
            }

            if (retryAfterSeconds.HasValue && retryAfterSeconds.Value > 0)
            {
                _retryAfterSeconds = retryAfterSeconds.Value;
            }

            if (!string.IsNullOrWhiteSpace(message))
            {
                _message = message;
            }
        }
    }

    public void AddOrUpdateDeniedUser(string username, DateTimeOffset expiresAtUtc, string? reason)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return;
        }

        lock (_gate)
        {
            if (expiresAtUtc <= DateTimeOffset.UtcNow)
            {
                _denyUsers.Remove(NormalizeUsername(username));
                return;
            }

            var normalized = NormalizeUsername(username);
            _denyUsers[normalized] = new KillSwitchDenyUserEntry(normalized, expiresAtUtc, reason?.Trim());
        }
    }

    public bool RemoveDeniedUser(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return false;
        }

        lock (_gate)
        {
            return _denyUsers.Remove(NormalizeUsername(username));
        }
    }

    public bool TryGetDeniedUser(string username, out KillSwitchDenyUserEntry? denyUser)
    {
        denyUser = null;

        if (string.IsNullOrWhiteSpace(username))
        {
            return false;
        }

        lock (_gate)
        {
            PruneExpiredDenyUsers();
            if (_denyUsers.TryGetValue(NormalizeUsername(username), out var value))
            {
                denyUser = value;
                return true;
            }

            return false;
        }
    }

    private void Apply(KillSwitchOptions options)
    {
        lock (_gate)
        {
            _enabled = options.Enabled;
            _allowedGroup = string.IsNullOrWhiteSpace(options.AllowedGroup) ? null : options.AllowedGroup.Trim();
            _retryAfterSeconds = options.RetryAfterSeconds > 0 ? options.RetryAfterSeconds : 120;
            _message = string.IsNullOrWhiteSpace(options.Message) ? "Service temporarily unavailable." : options.Message;

            _denyUsers.Clear();
            foreach (var denyUser in options.DenyUsers)
            {
                AddOrUpdateDeniedUser(denyUser.Username, denyUser.ExpiresAtUtc, denyUser.Reason);
            }
        }
    }

    private void PruneExpiredDenyUsers()
    {
        if (_denyUsers.Count == 0)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var expired = _denyUsers
            .Where(x => x.Value.ExpiresAtUtc <= now)
            .Select(x => x.Key)
            .ToArray();

        foreach (var key in expired)
        {
            _denyUsers.Remove(key);
        }
    }

    private static string NormalizeUsername(string username)
    {
        var trimmed = username.Trim();
        var lastPart = trimmed.Contains('\\') ? trimmed.Split('\\').Last() : trimmed;
        return lastPart.ToLowerInvariant();
    }
}

public sealed record KillSwitchSnapshot(
    bool Enabled,
    string? AllowedGroup,
    int RetryAfterSeconds,
    string Message,
    IReadOnlyList<KillSwitchDenyUserEntry> DenyUsers);

public sealed record KillSwitchDenyUserEntry(
    string Username,
    DateTimeOffset ExpiresAtUtc,
    string? Reason);
