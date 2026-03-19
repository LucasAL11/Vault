namespace Infrastructure.Zk;

public sealed class ZkBackendOptions
{
    /// <summary>Local backend key used to sign in-process proof payloads.</summary>
    public string LocalHmacKey { get; set; } = "dev-local-zk-key-change-me";
}
