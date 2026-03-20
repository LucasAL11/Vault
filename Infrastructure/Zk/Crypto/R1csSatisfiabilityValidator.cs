using System.Numerics;
using Application.Abstractions.Cryptography;
using Application.Cryptography.Constraints;

namespace Infrastructure.Zk.Crypto;

internal sealed class R1csSatisfiabilityValidator : IR1csSatisfiabilityValidator
{
    public R1csSatisfiabilityResult Validate(
        IReadOnlyList<R1csBuilder.R1csConstraint> constraints,
        IReadOnlyDictionary<int, BigInteger> witness,
        BigInteger modulus)
    {
        ArgumentNullException.ThrowIfNull(constraints);
        ArgumentNullException.ThrowIfNull(witness);

        if (modulus <= BigInteger.One)
        {
            throw new ArgumentOutOfRangeException(nameof(modulus), "Field modulus must be greater than 1.");
        }

        for (var i = 0; i < constraints.Count; i++)
        {
            var constraint = constraints[i];

            if (!TryDot(constraint.A, witness, modulus, out var left, out var missingIndex))
            {
                return R1csSatisfiabilityResult.Unsatisfied(new R1csSatisfiabilityFailure(
                    ConstraintIndex: i,
                    MissingWitnessIndex: missingIndex,
                    Left: BigInteger.Zero,
                    Right: BigInteger.Zero,
                    Output: BigInteger.Zero,
                    Residual: BigInteger.Zero));
            }

            if (!TryDot(constraint.B, witness, modulus, out var right, out missingIndex))
            {
                return R1csSatisfiabilityResult.Unsatisfied(new R1csSatisfiabilityFailure(
                    ConstraintIndex: i,
                    MissingWitnessIndex: missingIndex,
                    Left: left,
                    Right: BigInteger.Zero,
                    Output: BigInteger.Zero,
                    Residual: BigInteger.Zero));
            }

            if (!TryDot(constraint.C, witness, modulus, out var output, out missingIndex))
            {
                return R1csSatisfiabilityResult.Unsatisfied(new R1csSatisfiabilityFailure(
                    ConstraintIndex: i,
                    MissingWitnessIndex: missingIndex,
                    Left: left,
                    Right: right,
                    Output: BigInteger.Zero,
                    Residual: BigInteger.Zero));
            }

            var residual = Mod(left * right - output, modulus);
            if (!residual.IsZero)
            {
                return R1csSatisfiabilityResult.Unsatisfied(new R1csSatisfiabilityFailure(
                    ConstraintIndex: i,
                    MissingWitnessIndex: null,
                    Left: left,
                    Right: right,
                    Output: output,
                    Residual: residual));
            }
        }

        return R1csSatisfiabilityResult.Satisfied;
    }

    private static bool TryDot(
        R1csBuilder.SparseVec vector,
        IReadOnlyDictionary<int, BigInteger> witness,
        BigInteger modulus,
        out BigInteger acc,
        out int? missingWitnessIndex)
    {
        acc = BigInteger.Zero;
        foreach (var (wireIndex, coeff) in vector.Terms)
        {
            if (!witness.TryGetValue(wireIndex, out var value))
            {
                missingWitnessIndex = wireIndex;
                return false;
            }

            acc = Mod(acc + (coeff * value), modulus);
        }

        missingWitnessIndex = null;
        return true;
    }

    private static BigInteger Mod(BigInteger value, BigInteger modulus)
    {
        var normalized = value % modulus;
        if (normalized.Sign < 0)
        {
            normalized += modulus;
        }

        return normalized;
    }
}
