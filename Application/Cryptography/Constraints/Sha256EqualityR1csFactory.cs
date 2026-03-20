using System.Numerics;

namespace Application.Cryptography.Constraints;

public static class Sha256EqualityR1csFactory
{
    public const int HashSizeBytes = 32;

    public static (
        IReadOnlyList<R1csBuilder.R1csConstraint> constraints,
        IReadOnlyDictionary<string, int> wires) Build(int hashSizeBytes = HashSizeBytes)
    {
        if (hashSizeBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(hashSizeBytes), "hashSizeBytes must be greater than zero.");
        }

        var builder = new R1csBuilder();
        var constraints = new List<R1csBuilder.R1csConstraint>(hashSizeBytes);
        var minusOne = builder.Mod(-BigInteger.One);

        for (var i = 0; i < hashSizeBytes; i++)
        {
            var leftId = builder.IdOf($"lhs_{i}");
            var rightId = builder.IdOf($"rhs_{i}");

            constraints.Add(new R1csBuilder.R1csConstraint(
                new R1csBuilder.SparseVec(new Dictionary<int, BigInteger>
                {
                    [leftId] = BigInteger.One,
                    [rightId] = minusOne
                }),
                new R1csBuilder.SparseVec(new Dictionary<int, BigInteger>
                {
                    [R1csBuilder.ConstantWireId] = BigInteger.One
                }),
                new R1csBuilder.SparseVec(new Dictionary<int, BigInteger>())));
        }

        return (constraints, new Dictionary<string, int>(builder.WireIndex));
    }
}
