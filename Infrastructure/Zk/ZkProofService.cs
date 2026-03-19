using Application.Abstractions.Cryptography;
using Application.Contracts.Zk;

namespace Infrastructure.Zk;

public class ZkProofService : IZkProofService
{
    private readonly IZkBackend _zkBackend;
    public ZkProofService(IZkBackend backend) => _zkBackend = backend;
    
    public Task<ZkProofResult> GenerateProofAsync(PreimageRequest request, CancellationToken ct = default)
        => _zkBackend.ProveAsync(request, ct);

    public Task<bool> VerifyProofAsync(VerificationRequest request, CancellationToken ct = default)
        => _zkBackend.VerifyAsync(request, ct);
}
