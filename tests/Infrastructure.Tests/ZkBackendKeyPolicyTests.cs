using Application.Abstractions.Cryptography;
using Application.Contracts.Zk;
using Infrastructure.Zk;
using Infrastructure.Zk.Backends;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;

namespace Infrastructure.Tests;

public sealed class ZkBackendKeyPolicyTests
{
    [Fact]
    public void Production_ShouldRejectWeakLocalHmacKey()
    {
        var options = Options.Create(new ZkBackendOptions
        {
            LocalHmacKey = "dev-local-zk-key-change-me"
        });

        var ex = Assert.Throws<InvalidOperationException>(() =>
            new InProcessZkBackend(options, new FakeHostEnvironment("Production"), new FakeWitnessGenerator()));

        Assert.Contains("weak for Production", ex.Message);
    }

    [Fact]
    public void Production_ShouldAcceptStrongBase64LocalHmacKey()
    {
        var strongKey = Convert.ToBase64String(new byte[32]);
        var options = Options.Create(new ZkBackendOptions
        {
            LocalHmacKey = strongKey
        });

        var backend = new InProcessZkBackend(options, new FakeHostEnvironment("Production"), new FakeWitnessGenerator());
        Assert.NotNull(backend);
    }

    [Fact]
    public void Development_ShouldAllowNonStrongLocalHmacKey()
    {
        var options = Options.Create(new ZkBackendOptions
        {
            LocalHmacKey = "dev-local-zk-key-change-me"
        });

        var backend = new InProcessZkBackend(options, new FakeHostEnvironment("Development"), new FakeWitnessGenerator());
        Assert.NotNull(backend);
    }

    private sealed class FakeWitnessGenerator : IZkWitnessGenerator
    {
        public ZkWitness Generate(PreimageRequest request) =>
            new(
                SecretBase64: string.Empty,
                HashPublicBase64: string.Empty,
                SecretSha256Base64: string.Empty,
                ClientId: request.ClientId,
                Nonce: request.Nonce,
                CircuitId: "test",
                Version: 1);
    }

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } =
            new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
