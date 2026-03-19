namespace Application.Contracts.Zk;

public sealed record VerificationRequest(
    string Proof,
    string HashPublic,
    string ClientId,
    string Nonce);
