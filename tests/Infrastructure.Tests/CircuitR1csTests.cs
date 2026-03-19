using System.Numerics;
using Application.Cryptography.Constraints;
using Xunit;

namespace Infrastructure.Tests;

public sealed class CircuitR1csTests
{
    [Fact]
    public void ExampleR1cs_ShouldGenerateExpectedConstraintCount()
    {
        var (constraints, wires) = ExampleR1csFactory.Build("a", "b", "x", "y");

        Assert.Equal(11, constraints.Count);
        Assert.Contains("a", wires.Keys);
        Assert.Contains("b", wires.Keys);
        Assert.Contains("x", wires.Keys);
        Assert.Contains("y", wires.Keys);
        Assert.Contains("z", wires.Keys);
    }

    [Fact]
    public void ExampleR1cs_ShouldSatisfyConstraints_WhenAGreaterOrEqualB()
    {
        var (constraints, wires) = ExampleR1csFactory.Build("a", "b", "x", "y");
        var p = R1csBuilder.Bls12_381ScalarFieldPrime;

        var values = new Dictionary<string, BigInteger>
        {
            ["a"] = 10,
            ["b"] = 3,
            ["x"] = 8,
            ["y"] = 2,
            ["u"] = 0,
            ["t1"] = 7,
            ["scaledBorrow"] = 0,
            ["d"] = 7,
            ["negU"] = 0,
            ["s"] = 1,
            ["inv_b"] = ModInverse(3, p),
            ["sum_xy"] = 10,
            ["diff_xy"] = 6
        };
        values["div_branch"] = Mod(values["sum_xy"] * values["inv_b"], p);
        values["z"] = values["div_branch"];

        var witness = BuildWitness(wires, values, p);
        AssertAllConstraintsSatisfied(constraints, witness, p);
    }

    [Fact]
    public void ExampleR1cs_ShouldSatisfyConstraints_WhenALessThanB()
    {
        var (constraints, wires) = ExampleR1csFactory.Build("a", "b", "x", "y");
        var p = R1csBuilder.Bls12_381ScalarFieldPrime;

        var values = new Dictionary<string, BigInteger>
        {
            ["a"] = 2,
            ["b"] = 9,
            ["x"] = 8,
            ["y"] = 2,
            ["u"] = 1,
            ["t1"] = Mod(2 - 9, p),
            ["scaledBorrow"] = 1 << 16,
            ["negU"] = Mod(-1, p),
            ["s"] = 0,
            ["inv_b"] = ModInverse(9, p),
            ["sum_xy"] = 10,
            ["diff_xy"] = 6
        };
        values["d"] = Mod(values["t1"] + values["scaledBorrow"], p);
        values["div_branch"] = Mod(values["sum_xy"] * values["inv_b"], p);
        values["z"] = values["diff_xy"];

        var witness = BuildWitness(wires, values, p);
        AssertAllConstraintsSatisfied(constraints, witness, p);
    }

    private static Dictionary<int, BigInteger> BuildWitness(
        IReadOnlyDictionary<string, int> wires,
        IReadOnlyDictionary<string, BigInteger> values,
        BigInteger p)
    {
        var witness = new Dictionary<int, BigInteger>
        {
            [R1csBuilder.ConstantWireId] = 1
        };

        foreach (var (name, id) in wires)
        {
            if (id == R1csBuilder.ConstantWireId)
            {
                continue;
            }

            if (!values.TryGetValue(name, out var value))
            {
                throw new InvalidOperationException($"Missing witness value for wire '{name}'.");
            }

            witness[id] = Mod(value, p);
        }

        return witness;
    }

    private static void AssertAllConstraintsSatisfied(
        IReadOnlyList<R1csBuilder.R1csConstraint> constraints,
        IReadOnlyDictionary<int, BigInteger> witness,
        BigInteger p)
    {
        for (int i = 0; i < constraints.Count; i++)
        {
            var c = constraints[i];
            var left = Dot(c.A, witness, p);
            var right = Dot(c.B, witness, p);
            var output = Dot(c.C, witness, p);
            var result = Mod(left * right - output, p);
            Assert.True(result.IsZero, $"Constraint {i} is not satisfied.");
        }
    }

    private static BigInteger Dot(
        R1csBuilder.SparseVec vec,
        IReadOnlyDictionary<int, BigInteger> witness,
        BigInteger p)
    {
        BigInteger acc = 0;
        foreach (var (idx, coeff) in vec.Terms)
        {
            if (!witness.TryGetValue(idx, out var value))
            {
                throw new InvalidOperationException($"Missing witness value for index {idx}.");
            }

            acc = Mod(acc + (coeff * value), p);
        }

        return acc;
    }

    private static BigInteger Mod(BigInteger value, BigInteger p)
    {
        var normalized = value % p;
        if (normalized.Sign < 0)
        {
            normalized += p;
        }

        return normalized;
    }

    private static BigInteger ModInverse(BigInteger value, BigInteger p)
    {
        if (value.IsZero)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Zero has no inverse in the field.");
        }

        return BigInteger.ModPow(Mod(value, p), p - 2, p);
    }
}
