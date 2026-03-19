using System.Collections.Concurrent;
using Application.Abstractions.Security;
using Microsoft.Extensions.Options;
using Shared;

namespace Infrastructure.Security;

public sealed class InMemoryNonceStore : INonceStore
{
    private readonly ConcurrentDictionary<string, DateTime> _entries = new();
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly NonceStoreOptions _options;

    public InMemoryNonceStore(
        IDateTimeProvider dateTimeProvider,
        IOptions<NonceStoreOptions> options)
    {
        _dateTimeProvider = dateTimeProvider;
        _options = options.Value;

        if (_options.TtlSeconds <= 0)
        {
            throw new InvalidOperationException("NonceStore:TtlSeconds must be greater than zero.");
        }

        if (_options.MaxEntries <= 0)
        {
            throw new InvalidOperationException("NonceStore:MaxEntries must be greater than zero.");
        }
    }

    public ValueTask<bool> TryAddAsync(
        string scope,
        ReadOnlyMemory<byte> nonce,
        CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return ValueTask.FromResult(true);
        }

        if (string.IsNullOrWhiteSpace(scope))
        {
            throw new InvalidOperationException("Nonce scope is required.");
        }

        if (nonce.IsEmpty)
        {
            throw new InvalidOperationException("Nonce is required.");
        }

        var now = _dateTimeProvider.UtcNow;
        PruneExpired(now);
        EnsureCapacity(now);

        var entryKey = BuildEntryKey(scope, nonce.Span);
        var expiresAt = now.AddSeconds(_options.TtlSeconds);

        while (true)
        {
            if (!_entries.TryGetValue(entryKey, out var currentExpiresAt))
            {
                if (_entries.TryAdd(entryKey, expiresAt))
                {
                    return ValueTask.FromResult(true);
                }

                continue;
            }

            if (currentExpiresAt > now)
            {
                return ValueTask.FromResult(false);
            }

            if (_entries.TryUpdate(entryKey, expiresAt, currentExpiresAt))
            {
                return ValueTask.FromResult(true);
            }
        }
    }

    public ValueTask<bool> TryConsumeAsync(
        string scope,
        ReadOnlyMemory<byte> nonce,
        CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return ValueTask.FromResult(true);
        }

        if (string.IsNullOrWhiteSpace(scope))
        {
            throw new InvalidOperationException("Nonce scope is required.");
        }

        if (nonce.IsEmpty)
        {
            throw new InvalidOperationException("Nonce is required.");
        }

        var now = _dateTimeProvider.UtcNow;
        PruneExpired(now);

        var entryKey = BuildEntryKey(scope, nonce.Span);
        if (!_entries.TryGetValue(entryKey, out var expiresAt))
        {
            return ValueTask.FromResult(false);
        }

        if (expiresAt <= now)
        {
            _entries.TryRemove(entryKey, out _);
            return ValueTask.FromResult(false);
        }

        var consumed = _entries.TryRemove(entryKey, out _);
        return ValueTask.FromResult(consumed);
    }

    private void EnsureCapacity(DateTime now)
    {
        if (_entries.Count < _options.MaxEntries)
        {
            return;
        }

        PruneExpired(now);
        if (_entries.Count < _options.MaxEntries)
        {
            return;
        }

        var overflow = _entries.Count - _options.MaxEntries + 1;
        foreach (var oldest in _entries.OrderBy(x => x.Value).Take(overflow))
        {
            _entries.TryRemove(oldest.Key, out _);
        }
    }

    private void PruneExpired(DateTime now)
    {
        foreach (var item in _entries)
        {
            if (item.Value <= now)
            {
                _entries.TryRemove(item.Key, out _);
            }
        }
    }

    private static string BuildEntryKey(string scope, ReadOnlySpan<byte> nonce)
    {
        return $"{scope}:{Convert.ToBase64String(nonce)}";
    }
}
