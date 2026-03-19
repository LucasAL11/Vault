namespace Application.Contracts.Zk;

public record ZkProofResult(
    byte[] Proof,
    byte[] PublicInputs);
