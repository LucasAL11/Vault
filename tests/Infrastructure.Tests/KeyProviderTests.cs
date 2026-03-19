using System.Text;
using System.Text.Json;
using Application.Abstractions.Security;
using Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace Infrastructure.Tests;

public class KeyProviderTests
{
    [Fact]
    public async Task DevMode_ShouldResolveConfiguredKey()
    {
        using var serviceProvider = BuildServiceProvider(new Dictionary<string, string?>
        {
            ["KeyProvider:Mode"] = "Dev",
            ["KeyProvider:Dev:KeyId"] = "dev-test-key-v1",
            ["KeyProvider:Dev:Base64Key"] = ToBase64("01234567890123456789012345678901")
        });

        var provider = serviceProvider.GetRequiredService<IKeyProvider>();
        var key = await provider.GetCurrentKeyAsync();

        Assert.Equal("dev-test-key-v1", key.KeyId);
        Assert.Equal(32, key.KeyBytes.Length);
    }

    [Fact]
    public async Task ProdMode_ShouldPreferEnvironmentVariables()
    {
        const string envKeyId = "prod-env-key-v1";
        const string envKey = "abcdefghijklmnopqrstuvwxyz123456";

        var originalKeyId = Environment.GetEnvironmentVariable("APP_KEY_ID");
        var originalKey = Environment.GetEnvironmentVariable("APP_KEY_BASE64");

        try
        {
            Environment.SetEnvironmentVariable("APP_KEY_ID", envKeyId);
            Environment.SetEnvironmentVariable("APP_KEY_BASE64", ToBase64(envKey));

            using var serviceProvider = BuildServiceProvider(new Dictionary<string, string?>
            {
                ["KeyProvider:Mode"] = "Prod",
                ["KeyProvider:Prod:CurrentKeyId"] = "prod-config-key-v1",
                ["KeyProvider:Prod:Keys:0:KeyId"] = "prod-config-key-v1",
                ["KeyProvider:Prod:Keys:0:Base64Key"] = ToBase64("00000000000000000000000000000000")
            });

            var provider = serviceProvider.GetRequiredService<IKeyProvider>();
            var key = await provider.GetCurrentKeyAsync();

            Assert.Equal(envKeyId, key.KeyId);
            Assert.Equal(32, key.KeyBytes.Length);
            Assert.Equal(envKey, Encoding.UTF8.GetString(key.KeyBytes));
        }
        finally
        {
            Environment.SetEnvironmentVariable("APP_KEY_ID", originalKeyId);
            Environment.SetEnvironmentVariable("APP_KEY_BASE64", originalKey);
        }
    }

    [Fact]
    public void ProdMode_ShouldFailWhenNoKeyConfigured()
    {
        var originalKeyId = Environment.GetEnvironmentVariable("APP_KEY_ID");
        var originalKey = Environment.GetEnvironmentVariable("APP_KEY_BASE64");

        try
        {
            Environment.SetEnvironmentVariable("APP_KEY_ID", null);
            Environment.SetEnvironmentVariable("APP_KEY_BASE64", null);

            using var serviceProvider = BuildServiceProvider(new Dictionary<string, string?>
            {
                ["KeyProvider:Mode"] = "Prod",
                ["KeyProvider:Prod:CurrentKeyId"] = "",
                ["KeyProvider:Prod:Keys:0:KeyId"] = "",
                ["KeyProvider:Prod:Keys:0:Base64Key"] = ""
            });

            var exception = Assert.Throws<InvalidOperationException>(() => serviceProvider.GetRequiredService<IKeyProvider>());
            Assert.Contains("Production current key id is missing", exception.Message);
        }
        finally
        {
            Environment.SetEnvironmentVariable("APP_KEY_ID", originalKeyId);
            Environment.SetEnvironmentVariable("APP_KEY_BASE64", originalKey);
        }
    }

    [Fact]
    public async Task ProdMode_ShouldRotateCurrentKeyToAnotherKnownKey()
    {
        var originalKeyId = Environment.GetEnvironmentVariable("APP_KEY_ID");
        var originalKey = Environment.GetEnvironmentVariable("APP_KEY_BASE64");
        var originalCurrent = Environment.GetEnvironmentVariable("APP_KEY_CURRENT_ID");

        try
        {
            Environment.SetEnvironmentVariable("APP_KEY_ID", null);
            Environment.SetEnvironmentVariable("APP_KEY_BASE64", null);
            Environment.SetEnvironmentVariable("APP_KEY_CURRENT_ID", null);

            using var serviceProvider = BuildServiceProvider(new Dictionary<string, string?>
            {
                ["KeyProvider:Mode"] = "Prod",
                ["KeyProvider:Prod:CurrentKeyId"] = "prod-key-v1",
                ["KeyProvider:Prod:Keys:0:KeyId"] = "prod-key-v1",
                ["KeyProvider:Prod:Keys:0:Base64Key"] = ToBase64("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ["KeyProvider:Prod:Keys:1:KeyId"] = "prod-key-v2",
                ["KeyProvider:Prod:Keys:1:Base64Key"] = ToBase64("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            });

            var provider = serviceProvider.GetRequiredService<IKeyProvider>();

            var currentBefore = await provider.GetCurrentKeyAsync();
            Assert.Equal("prod-key-v1", currentBefore.KeyId);

            var rotated = await provider.RotateCurrentKeyAsync("prod-key-v2");
            Assert.Equal("prod-key-v2", rotated.KeyId);

            var currentAfter = await provider.GetCurrentKeyAsync();
            Assert.Equal("prod-key-v2", currentAfter.KeyId);
        }
        finally
        {
            Environment.SetEnvironmentVariable("APP_KEY_ID", originalKeyId);
            Environment.SetEnvironmentVariable("APP_KEY_BASE64", originalKey);
            Environment.SetEnvironmentVariable("APP_KEY_CURRENT_ID", originalCurrent);
        }
    }

    [Fact]
    public async Task ProdKmsMode_ShouldResolveCurrentKeyFromRemoteKeyring()
    {
        var handler = new StubHttpMessageHandler(_ =>
        {
            var payload = JsonSerializer.Serialize(new
            {
                currentKeyId = "kms-key-v2",
                keys = new[]
                {
                    new { keyId = "kms-key-v1", base64Key = ToBase64("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") },
                    new { keyId = "kms-key-v2", base64Key = ToBase64("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") }
                }
            });

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };
        });

        using var serviceProvider = BuildServiceProvider(
            new Dictionary<string, string?>
            {
                ["KeyProvider:Mode"] = "ProdKms",
                ["KeyProvider:ProdKms:Enabled"] = "true",
                ["KeyProvider:ProdKms:BaseUrl"] = "https://kms.test.local",
                ["KeyProvider:ProdKms:KeysEndpointPath"] = "/v1/keyring",
                ["KeyProvider:ProdKms:TimeoutSeconds"] = "5",
                ["KeyProvider:ProdKms:CacheTtlSeconds"] = "30"
            },
            services =>
            {
                services.RemoveAll<IHttpClientFactory>();
                services.AddSingleton<IHttpClientFactory>(new StubHttpClientFactory(new HttpClient(handler)
                {
                    BaseAddress = new Uri("https://kms.test.local")
                }));
            });

        var provider = serviceProvider.GetRequiredService<IKeyProvider>();
        var key = await provider.GetCurrentKeyAsync();

        Assert.Equal("kms-key-v2", key.KeyId);
        Assert.Equal(32, key.KeyBytes.Length);
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task ProdKmsMode_ShouldUseInMemoryCacheUntilTtlExpires()
    {
        var handler = new StubHttpMessageHandler(_ =>
        {
            var payload = JsonSerializer.Serialize(new
            {
                currentKeyId = "kms-key-v1",
                keys = new[]
                {
                    new { keyId = "kms-key-v1", base64Key = ToBase64("cccccccccccccccccccccccccccccccc") }
                }
            });

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };
        });

        using var serviceProvider = BuildServiceProvider(
            new Dictionary<string, string?>
            {
                ["KeyProvider:Mode"] = "ProdKms",
                ["KeyProvider:ProdKms:Enabled"] = "true",
                ["KeyProvider:ProdKms:BaseUrl"] = "https://kms.test.local",
                ["KeyProvider:ProdKms:KeysEndpointPath"] = "/v1/keyring",
                ["KeyProvider:ProdKms:TimeoutSeconds"] = "5",
                ["KeyProvider:ProdKms:CacheTtlSeconds"] = "60"
            },
            services =>
            {
                services.RemoveAll<IHttpClientFactory>();
                services.AddSingleton<IHttpClientFactory>(new StubHttpClientFactory(new HttpClient(handler)
                {
                    BaseAddress = new Uri("https://kms.test.local")
                }));
            });

        var provider = serviceProvider.GetRequiredService<IKeyProvider>();

        var first = await provider.GetCurrentKeyAsync();
        var second = await provider.GetCurrentKeyAsync();
        var known = await provider.GetKnownKeyIdsAsync();

        Assert.Equal("kms-key-v1", first.KeyId);
        Assert.Equal("kms-key-v1", second.KeyId);
        Assert.Single(known);
        Assert.Equal(1, handler.CallCount);
    }

    private static ServiceProvider BuildServiceProvider(
        Dictionary<string, string?> keyProviderOverrides,
        Action<IServiceCollection>? configureServices = null)
    {
        var baseConfig = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Database"] = "Host=localhost;Port=5432;Database=test;Username=test;Password=test",
            ["Jwt:Issuer"] = "test-issuer",
            ["Jwt:Audience"] = "test-audience",
            ["Jwt:Secret"] = "01234567890123456789012345678901",
            ["ZkBackend:LocalHmacKey"] = "test-zk-key"
        };

        foreach (var item in keyProviderOverrides)
        {
            baseConfig[item.Key] = item.Value;
        }

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(baseConfig)
            .Build();

        var services = new ServiceCollection();
        services.AddInfrastructure(configuration);
        configureServices?.Invoke(services);
        return services.BuildServiceProvider();
    }

    private static string ToBase64(string value)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private sealed class StubHttpClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(responseFactory(request));
        }
    }
}
