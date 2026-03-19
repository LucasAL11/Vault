using Shared;

namespace Application.Cryptography;

internal static class ZkInputValidation
{
    internal static Error? ValidatePreimage(string? secret, string? hashPublic, string? clientId, string? nonce)
    {
        if (string.IsNullOrWhiteSpace(secret))
        {
            return ZkErrors.SecretRequired;
        }

        if (string.IsNullOrWhiteSpace(hashPublic))
        {
            return ZkErrors.HashPublicRequired;
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            return Error.BadRequest("Zk.ClientId.Required", "clientId is required.");
        }

        if (string.IsNullOrWhiteSpace(nonce))
        {
            return Error.BadRequest("Zk.Nonce.Required", "nonce is required.");
        }

        return null;
    }

    internal static Error? ValidateVerification(string? proof, string? hashPublic, string? clientId, string? nonce)
    {
        if (string.IsNullOrWhiteSpace(proof))
        {
            return ZkErrors.ProofRequired;
        }

        if (string.IsNullOrWhiteSpace(hashPublic))
        {
            return ZkErrors.HashPublicRequired;
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            return Error.BadRequest("Zk.ClientId.Required", "clientId is required.");
        }

        if (string.IsNullOrWhiteSpace(nonce))
        {
            return Error.BadRequest("Zk.Nonce.Required", "nonce is required.");
        }

        return null;
    }
}
