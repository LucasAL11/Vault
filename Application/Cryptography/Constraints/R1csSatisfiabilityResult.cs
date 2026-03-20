using System.Numerics;

namespace Application.Cryptography.Constraints;

public sealed record R1csSatisfiabilityFailure(
    int ConstraintIndex,
    int? MissingWitnessIndex,
    BigInteger Left,
    BigInteger Right,
    BigInteger Output,
    BigInteger Residual);

public sealed record R1csSatisfiabilityResult(
    bool IsSatisfied,
    R1csSatisfiabilityFailure? Failure)
{
    public static readonly R1csSatisfiabilityResult Satisfied = new(true, null);

    public static R1csSatisfiabilityResult Unsatisfied(R1csSatisfiabilityFailure failure)
    {
        return new R1csSatisfiabilityResult(false, failure);
    }
}
