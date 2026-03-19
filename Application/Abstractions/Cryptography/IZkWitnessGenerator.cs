using Application.Contracts.Zk;

namespace Application.Abstractions.Cryptography;

public interface IZkWitnessGenerator
{
    ZkWitness Generate(PreimageRequest request);
}
