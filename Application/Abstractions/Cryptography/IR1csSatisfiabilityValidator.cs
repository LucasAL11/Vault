using System.Numerics;
using Application.Cryptography.Constraints;

namespace Application.Abstractions.Cryptography;

public interface IR1csSatisfiabilityValidator
{
    R1csSatisfiabilityResult Validate(
        IReadOnlyList<R1csBuilder.R1csConstraint> constraints,
        IReadOnlyDictionary<int, BigInteger> witness,
        BigInteger modulus);
}
