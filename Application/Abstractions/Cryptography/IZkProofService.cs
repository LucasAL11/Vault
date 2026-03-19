using Application.Contracts.Zk;

namespace Application.Abstractions.Cryptography;

public interface IZkProofService
{
    Task<ZkProofResult> GenerateProofAsync(PreimageRequest request, CancellationToken ct = default);
    Task<bool> VerifyProofAsync(VerificationRequest request, CancellationToken ct = default);
}