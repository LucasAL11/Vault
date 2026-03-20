using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Application.Abstractions.Security;
using Infrastructure.Data;
using Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shared;
using Xunit;

namespace Infrastructure.Tests;

public sealed class PostgresNonceStoreMultiNodeTests
{
    [Fact]
    public async Task Should_PreventReplay_AcrossMultipleNodes_SharingSameDatabase()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nonce-multinode-{Guid.NewGuid():N}.db");
        var connectionString = $"Data Source={databasePath};Cache=Shared;Mode=ReadWriteCreate;Default Timeout=10";
        ServiceProvider? node1 = null;
        ServiceProvider? node2 = null;

        try
        {
            node1 = BuildNode(connectionString);
            await InitializeDatabaseAsync(node1);

            node2 = BuildNode(connectionString);

            var store1 = node1.GetRequiredService<INonceStore>();
            var store2 = node2.GetRequiredService<INonceStore>();

            var scope = "auth-challenge:cryptography.prove:client-a:PLT\\LUCAS.LUNA:127.0.0.1";
            var nonce = new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 };

            var addedInNode1 = await store1.TryAddAsync(scope, nonce);
            var duplicateInNode2 = await store2.TryAddAsync(scope, nonce);
            var consumedInNode2 = await store2.TryConsumeAsync(scope, nonce);
            var replayInNode1 = await store1.TryConsumeAsync(scope, nonce);

            Assert.True(addedInNode1);
            Assert.False(duplicateInNode2);
            Assert.True(consumedInNode2);
            Assert.False(replayInNode1);
        }
        finally
        {
            node2?.Dispose();
            node1?.Dispose();

            if (File.Exists(databasePath))
            {
                try
                {
                    File.Delete(databasePath);
                }
                catch (IOException)
                {
                    // Best-effort cleanup for SQLite file that can remain briefly locked after provider disposal.
                }
            }
        }
    }

    private static ServiceProvider BuildNode(string connectionString)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddScoped<IMessageDispatcher, NoOpMessageDispatcher>();
        services.AddSingleton<IDateTimeProvider>(new FixedDateTimeProvider(DateTime.UtcNow));
        services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite(connectionString));
        services.AddSingleton<IOptions<NonceStoreOptions>>(Options.Create(new NonceStoreOptions
        {
            Provider = NonceStoreProviders.Postgres,
            Enabled = true,
            TtlSeconds = 300,
            MaxEntries = 10_000
        }));
        services.AddSingleton<INonceStore, PostgresNonceStore>();
        return services.BuildServiceProvider();
    }

    private static async Task InitializeDatabaseAsync(ServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await dbContext.Database.EnsureDeletedAsync();
        await dbContext.Database.EnsureCreatedAsync();
    }

    private sealed class FixedDateTimeProvider(DateTime utcNow) : IDateTimeProvider
    {
        public DateTime UtcNow { get; } = utcNow;
    }

    private sealed class NoOpMessageDispatcher : IMessageDispatcher
    {
        public Task<Result<TResponse>> Send<TResponse>(IMessage<TResponse> message, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("NoOp dispatcher does not support Send.");

        public Task<Result> Send(IMessage message, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("NoOp dispatcher does not support Send.");

        public Task Publish(IDomainEvent domainEvent, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
