using Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Infrastructure.Tests;

public sealed class DynamicAuthProviderTests
{
    [Fact]
    public void HybridAuth_WithOidcBearer_ShouldForwardToOidcJwt()
    {
        using var provider = BuildServiceProvider(new Dictionary<string, string?>
        {
            ["Authentication:Oidc:Enabled"] = "true",
            ["Authentication:Oidc:Issuer"] = "https://idp.example.com"
        });

        var selector = GetSelector(provider);
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = $"Bearer {CreateUnsignedJwt("https://idp.example.com")}";

        var forwardedScheme = selector(context);

        Assert.Equal("OidcJwt", forwardedScheme);
    }

    [Fact]
    public void HybridAuth_WithLocalBearer_ShouldForwardToLocalJwt()
    {
        using var provider = BuildServiceProvider(new Dictionary<string, string?>
        {
            ["Authentication:Oidc:Enabled"] = "true",
            ["Authentication:Oidc:Issuer"] = "https://idp.example.com"
        });

        var selector = GetSelector(provider);
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = $"Bearer {CreateUnsignedJwt("WebApplication1")}";

        var forwardedScheme = selector(context);

        Assert.Equal("LocalJwt", forwardedScheme);
    }

    [Fact]
    public void HybridAuth_WithoutBearer_AndKerberosEnabled_ShouldForwardToNegotiate()
    {
        using var provider = BuildServiceProvider(new Dictionary<string, string?>
        {
            ["Authentication:Kerberos:Enabled"] = "true"
        });

        var selector = GetSelector(provider);
        var context = new DefaultHttpContext();

        var forwardedScheme = selector(context);

        Assert.Equal(NegotiateDefaults.AuthenticationScheme, forwardedScheme);
    }

    [Fact]
    public void HybridAuth_WithoutBearer_AndKerberosDisabled_ShouldForwardToLocalJwt()
    {
        using var provider = BuildServiceProvider(new Dictionary<string, string?>
        {
            ["Authentication:Kerberos:Enabled"] = "false"
        });

        var selector = GetSelector(provider);
        var context = new DefaultHttpContext();

        var forwardedScheme = selector(context);

        Assert.Equal("LocalJwt", forwardedScheme);
    }

    private static Func<HttpContext, string?> GetSelector(IServiceProvider provider)
    {
        var monitor = provider.GetRequiredService<IOptionsMonitor<PolicySchemeOptions>>();
        var options = monitor.Get("HybridAuth");
        Assert.NotNull(options.ForwardDefaultSelector);
        return options.ForwardDefaultSelector!;
    }

    private static ServiceProvider BuildServiceProvider(Dictionary<string, string?> overrides)
    {
        var configMap = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Database"] = "Host=localhost;Port=5432;Database=test;Username=test;Password=test",
            ["Jwt:Issuer"] = "WebApplication1",
            ["Jwt:Audience"] = "WebApplication1",
            ["Jwt:Secret"] = "01234567890123456789012345678901",
            ["ZkBackend:LocalHmacKey"] = "test-zk-key",
            ["Authentication:Kerberos:Enabled"] = "true",
            ["Authentication:Oidc:Enabled"] = "false"
        };

        foreach (var pair in overrides)
        {
            configMap[pair.Key] = pair.Value;
        }

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configMap)
            .Build();

        var services = new ServiceCollection();
        services.AddInfrastructure(configuration);
        return services.BuildServiceProvider();
    }

    private static string CreateUnsignedJwt(string issuer)
    {
        const string header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
        var payloadJson = $$"""{"iss":"{{issuer}}","sub":"tester","aud":"api"}""";
        var payload = Base64UrlEncode(payloadJson);
        return $"{header}.{payload}.";
    }

    private static string Base64UrlEncode(string value)
    {
        return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
