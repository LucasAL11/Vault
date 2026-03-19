using Application.Contracts.Zk;

namespace Application.Abstractions.Cryptography;

public interface IZkBackend
{
    Task<ZkProofResult> ProveAsync
        (PreimageRequest request, CancellationToken cancellationToken);
    Task<bool> VerifyAsync
        (VerificationRequest request, CancellationToken cancellationToken);
}