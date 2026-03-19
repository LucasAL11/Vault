using Application.Abstractions.Security;
using Infrastructure.Security;
using Microsoft.Extensions.Options;
using Shared;
using Xunit;

namespace Infrastructure.Tests;

public sealed class NonceStoreTests
{
    [Fact]
    public async Task TryAddAsync_ShouldRejectDuplicateWithinTtl_AndAcceptAfterExpiry()
    {
        var clock = new FakeDateTimeProvider(DateTime.UtcNow);
        INonceStore store = CreateStore(clock, new NonceStoreOptions
        {
            Enabled = true,
            TtlSeconds = 60,
            MaxEntries = 100
        });

        var nonce = new byte[] { 1, 2, 3, 4, 5, 6 };

        var first = await store.TryAddAsync("scope-a", nonce);
        var duplicate = await store.TryAddAsync("scope-a", nonce);
        clock.Advance(TimeSpan.FromSeconds(61));
        var afterExpiry = await store.TryAddAsync("scope-a", nonce);

        Assert.True(first);
        Assert.False(duplicate);
        Assert.True(afterExpiry);
    }

    [Fact]
    public async Task TryAddAsync_ShouldAllowSameNonceOnDifferentScopes()
    {
        var clock = new FakeDateTimeProvider(DateTime.UtcNow);
        INonceStore store = CreateStore(clock, new NonceStoreOptions
        {
            Enabled = true,
            TtlSeconds = 60,
            MaxEntries = 100
        });

        var nonce = new byte[] { 9, 9, 9, 9 };
        var firstScope = await store.TryAddAsync("scope-1", nonce);
        var secondScope = await store.TryAddAsync("scope-2", nonce);

        Assert.True(firstScope);
        Assert.True(secondScope);
    }

    [Fact]
    public async Task TryAddAsync_WhenDisabled_ShouldAlwaysReturnTrue()
    {
        var clock = new FakeDateTimeProvider(DateTime.UtcNow);
        INonceStore store = CreateStore(clock, new NonceStoreOptions
        {
            Enabled = false,
            TtlSeconds = 60,
            MaxEntries = 10
        });

        var nonce = new byte[] { 7, 7, 7 };

        var first = await store.TryAddAsync("scope-a", nonce);
        var second = await store.TryAddAsync("scope-a", nonce);

        Assert.True(first);
        Assert.True(second);
    }

    [Fact]
    public async Task TryConsumeAsync_ShouldConsumeOnce_AndRejectReplay()
    {
        var clock = new FakeDateTimeProvider(DateTime.UtcNow);
        INonceStore store = CreateStore(clock, new NonceStoreOptions
        {
            Enabled = true,
            TtlSeconds = 60,
            MaxEntries = 100
        });

        var nonce = new byte[] { 3, 1, 4, 1, 5 };
        await store.TryAddAsync("scope-a", nonce);

        var firstConsume = await store.TryConsumeAsync("scope-a", nonce);
        var replayConsume = await store.TryConsumeAsync("scope-a", nonce);

        Assert.True(firstConsume);
        Assert.False(replayConsume);
    }

    [Fact]
    public async Task TryConsumeAsync_ShouldFailAfterExpiry()
    {
        var clock = new FakeDateTimeProvider(DateTime.UtcNow);
        INonceStore store = CreateStore(clock, new NonceStoreOptions
        {
            Enabled = true,
            TtlSeconds = 2,
            MaxEntries = 100
        });

        var nonce = new byte[] { 8, 6, 7, 5, 3, 0, 9 };
        await store.TryAddAsync("scope-a", nonce);
        clock.Advance(TimeSpan.FromSeconds(3));

        var consumed = await store.TryConsumeAsync("scope-a", nonce);

        Assert.False(consumed);
    }

    private static INonceStore CreateStore(FakeDateTimeProvider clock, NonceStoreOptions options)
    {
        return new InMemoryNonceStore(clock, Options.Create(options));
    }

    private sealed class FakeDateTimeProvider(DateTime utcNow) : IDateTimeProvider
    {
        public DateTime UtcNow { get; private set; } = utcNow;

        public void Advance(TimeSpan value)
        {
            UtcNow = UtcNow.Add(value);
        }
    }
}
