using System.Security.Cryptography;
using Application.Abstractions.Security;
using Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Npgsql;
using Shared;

namespace Infrastructure.Security;

public sealed class PostgresNonceStore : INonceStore
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly NonceStoreOptions _options;

    public PostgresNonceStore(
        IServiceScopeFactory scopeFactory,
        IDateTimeProvider dateTimeProvider,
        IOptions<NonceStoreOptions> options)
    {
        _scopeFactory = scopeFactory;
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

    public async ValueTask<bool> TryAddAsync(
        string scope,
        ReadOnlyMemory<byte> nonce,
        CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return true;
        }

        ValidateInput(scope, nonce);

        var now = _dateTimeProvider.UtcNow;
        var expiresAt = now.AddSeconds(_options.TtlSeconds);
        var nonceHash = ComputeNonceHash(nonce.Span);

        using var serviceScope = _scopeFactory.CreateScope();
        var db = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        await PruneExpiredAsync(db, now, cancellationToken);
        await EnsureCapacityAsync(db, now, cancellationToken);

        db.NonceStoreEntries.Add(new NonceStoreEntry
        {
            Scope = scope,
            NonceHash = nonceHash,
            CreatedAtUtc = now,
            ExpiresAtUtc = expiresAt
        });

        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            return false;
        }
    }

    public async ValueTask<bool> TryConsumeAsync(
        string scope,
        ReadOnlyMemory<byte> nonce,
        CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return true;
        }

        ValidateInput(scope, nonce);

        var now = _dateTimeProvider.UtcNow;
        var nonceHash = ComputeNonceHash(nonce.Span);

        using var serviceScope = _scopeFactory.CreateScope();
        var db = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        await PruneExpiredAsync(db, now, cancellationToken);

        var affectedRows = await db.NonceStoreEntries
            .Where(x =>
                x.Scope == scope &&
                x.NonceHash == nonceHash &&
                x.ExpiresAtUtc > now)
            .ExecuteDeleteAsync(cancellationToken);

        return affectedRows > 0;
    }

    private async Task EnsureCapacityAsync(
        ApplicationDbContext db,
        DateTime now,
        CancellationToken cancellationToken)
    {
        var activeEntries = await db.NonceStoreEntries
            .CountAsync(x => x.ExpiresAtUtc > now, cancellationToken);

        if (activeEntries < _options.MaxEntries)
        {
            return;
        }

        var overflow = activeEntries - _options.MaxEntries + 1;
        var oldestIds = await db.NonceStoreEntries
            .Where(x => x.ExpiresAtUtc > now)
            .OrderBy(x => x.ExpiresAtUtc)
            .ThenBy(x => x.Id)
            .Select(x => x.Id)
            .Take(overflow)
            .ToArrayAsync(cancellationToken);

        if (oldestIds.Length == 0)
        {
            return;
        }

        await db.NonceStoreEntries
            .Where(x => oldestIds.Contains(x.Id))
            .ExecuteDeleteAsync(cancellationToken);
    }

    private static Task PruneExpiredAsync(
        ApplicationDbContext db,
        DateTime now,
        CancellationToken cancellationToken)
    {
        return db.NonceStoreEntries
            .Where(x => x.ExpiresAtUtc <= now)
            .ExecuteDeleteAsync(cancellationToken);
    }

    private static void ValidateInput(string scope, ReadOnlyMemory<byte> nonce)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            throw new InvalidOperationException("Nonce scope is required.");
        }

        if (nonce.IsEmpty)
        {
            throw new InvalidOperationException("Nonce is required.");
        }
    }

    private static string ComputeNonceHash(ReadOnlySpan<byte> nonce)
    {
        return Convert.ToHexString(SHA256.HashData(nonce));
    }

    private static bool IsUniqueViolation(DbUpdateException exception)
    {
        if (exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            return true;
        }

        var message = exception.InnerException?.Message;
        return !string.IsNullOrWhiteSpace(message) &&
               message.Contains("UNIQUE constraint failed", StringComparison.OrdinalIgnoreCase);
    }
}
