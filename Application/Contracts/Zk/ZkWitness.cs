namespace Application.Contracts.Zk;

public sealed record ZkWitness(
    string SecretBase64,
    string HashPublicBase64,
    string SecretSha256Base64,
    string ClientId,
    string Nonce,
    string CircuitId,
    int Version);
