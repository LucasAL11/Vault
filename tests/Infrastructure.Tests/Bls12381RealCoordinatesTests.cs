using Infrastructure.Zk.Crypto;
using Xunit;

namespace Infrastructure.Tests;

public sealed class Bls12381RealCoordinatesTests
{
    [Fact]
    public void G1_Generator_ShouldBeOnCurve()
    {
        Assert.True(G1AffinePoint.Generator.IsOnCurve());
    }

    [Fact]
    public void G2_Generator_ShouldBeOnCurve()
    {
        Assert.True(G2AffinePoint.Generator.IsOnCurve());
    }

    [Fact]
    public void Generators_ShouldBeInPrimeOrderSubgroup()
    {
        Assert.True(G1AffinePoint.Generator.IsInPrimeOrderSubgroup());
        Assert.True(G2AffinePoint.Generator.IsInPrimeOrderSubgroup());
        Assert.True(G2AffinePoint.Generator.IsInPrimeOrderSubgroupFast());
    }

    [Fact]
    public void G1_ClearCofactor_ShouldProduceSubgroupPoint()
    {
        var point = G1AffinePoint.Generator.ClearCofactor();
        Assert.True(point.IsInPrimeOrderSubgroup());
    }

    [Fact]
    public void Fp2_Inverse_ShouldProduceMultiplicativeIdentity()
    {
        var a = new Fp2(new Fp(9), new Fp(5));
        var inv = a.Inverse();
        Assert.Equal(Fp2.One, a * inv);
    }

    [Fact]
    public void Fp6_Inverse_ShouldProduceMultiplicativeIdentity()
    {
        var a = new Fp6(
            new Fp2(new Fp(3), new Fp(7)),
            new Fp2(new Fp(11), new Fp(13)),
            new Fp2(new Fp(17), new Fp(19)));

        var inv = a.Inverse();

        Assert.Equal(Fp6.One, a * inv);
    }

    [Fact]
    public void Fp12_Inverse_ShouldProduceMultiplicativeIdentity()
    {
        var a = new Fp12(
            new Fp6(
                new Fp2(new Fp(2), new Fp(5)),
                new Fp2(new Fp(7), new Fp(11)),
                new Fp2(new Fp(13), new Fp(17))),
            new Fp6(
                new Fp2(new Fp(19), new Fp(23)),
                new Fp2(new Fp(29), new Fp(31)),
                new Fp2(new Fp(37), new Fp(41))));

        var inv = a.Inverse();

        Assert.Equal(Fp12.One, a * inv);
    }

    [Fact]
    public void Fp12_Frobenius_ShouldBeMultiplicative()
    {
        var a = new Fp12(
            new Fp6(
                new Fp2(new Fp(2), new Fp(3)),
                new Fp2(new Fp(5), new Fp(7)),
                new Fp2(new Fp(11), new Fp(13))),
            new Fp6(
                new Fp2(new Fp(17), new Fp(19)),
                new Fp2(new Fp(23), new Fp(29)),
                new Fp2(new Fp(31), new Fp(37))));

        var b = new Fp12(
            new Fp6(
                new Fp2(new Fp(41), new Fp(43)),
                new Fp2(new Fp(47), new Fp(53)),
                new Fp2(new Fp(59), new Fp(61))),
            new Fp6(
                new Fp2(new Fp(67), new Fp(71)),
                new Fp2(new Fp(73), new Fp(79)),
                new Fp2(new Fp(83), new Fp(89))));

        Assert.Equal((a * b).FrobeniusMap(1), a.FrobeniusMap(1) * b.FrobeniusMap(1));
        Assert.Equal(a.Pow(new System.Numerics.BigInteger(1234)), a.PowWindowed(new System.Numerics.BigInteger(1234), 5));
        Assert.Equal(a.Square(), a.CyclotomicSquare());
        Assert.Equal(
            a.PowWindowed(new System.Numerics.BigInteger(1234), 5),
            a.PowCyclotomicWindowed(new System.Numerics.BigInteger(1234), 5));
    }

    [Fact]
    public void FrobeniusConstantSelectors_ShouldMatchNormalizedTableIndexing()
    {
        for (var power = -24; power <= 24; power++)
        {
            var n6 = ((power % 6) + 6) % 6;
            var n12 = ((power % 12) + 12) % 12;

            Assert.Equal(Bls12381FrobeniusConstants.Fp6C1[n6], Bls12381FrobeniusConstants.GetFp6C1(power));
            Assert.Equal(Bls12381FrobeniusConstants.Fp6C2[n6], Bls12381FrobeniusConstants.GetFp6C2(power));
            Assert.Equal(Bls12381FrobeniusConstants.Fp12C1[n12], Bls12381FrobeniusConstants.GetFp12C1(power));
        }
    }

    [Fact]
    public void PairingReference_ShouldBeBilinear_ForGeneratorMultiples()
    {
        var a = new Fr(7);
        var b = new Fr(11);
        var s = new Fr(3);
        var t = new Fr(13);

        var p = G1AffinePoint.Generator.Multiply(a);
        var q = G2AffinePoint.Generator.Multiply(b);

        var left = Bls12381PairingReferenceEngine.Pair(p.Multiply(s), q.Multiply(t));
        var right = Bls12381PairingReferenceEngine.Pair(p, q).Pow(s * t);

        Assert.Equal(left, right);
    }

    [Fact]
    public void MillerLoop_ShouldProduceNonTrivialFp12_ForGenerators()
    {
        var f = Bls12381PairingReferenceEngine.MillerLoop(G1AffinePoint.Generator, G2AffinePoint.Generator);
        Assert.NotEqual(Fp12.One, f.Value);
    }

    [Fact]
    public void FinalExponentiationRaw_ShouldBeDeterministic()
    {
        var f = Bls12381PairingReferenceEngine.MillerLoop(G1AffinePoint.Generator, G2AffinePoint.Generator);
        var fe1 = Bls12381PairingReferenceEngine.FinalExponentiationRaw(f);
        var fe2 = Bls12381PairingReferenceEngine.FinalExponentiationRaw(f);

        Assert.Equal(fe1, fe2);
    }

    [Fact]
    public void FinalExponentiationRaw_ShouldMatchDirectExponentiation()
    {
        var f = Bls12381PairingReferenceEngine.MillerLoop(G1AffinePoint.Generator, G2AffinePoint.Generator);
        var optimized = Bls12381PairingReferenceEngine.FinalExponentiationRaw(f);
        var direct = f.Value.Pow(Bls12381Constants.FinalExponent);

        Assert.Equal(direct, optimized);
    }

    [Fact]
    public void ExpByBlsX_ShouldMatchSignedPow()
    {
        var value = new Fp12(
            new Fp6(
                new Fp2(new Fp(3), new Fp(5)),
                new Fp2(new Fp(7), new Fp(11)),
                new Fp2(new Fp(13), new Fp(17))),
            new Fp6(
                new Fp2(new Fp(19), new Fp(23)),
                new Fp2(new Fp(29), new Fp(31)),
                new Fp2(new Fp(37), new Fp(41))));

        var byX = value.ExpByBlsX();
        var directAbs = value.Pow(Bls12381Constants.BParameterXAbs);
        var directSigned = Bls12381Constants.BParameterXIsNegative ? directAbs.Conjugate() : directAbs;

        Assert.Equal(directSigned, byX);
    }

    [Fact]
    public void MillerLoop_ShouldRejectUnknownScalarPoints()
    {
        var p = G1AffinePoint.FromCoordinates(new Fp(1), new Fp(2));
        var q = G2AffinePoint.Generator;

        Assert.Throws<InvalidOperationException>(() => Bls12381PairingReferenceEngine.MillerLoop(p, q));
    }

    [Fact]
    public void PairingValidation_ShouldRejectInfinity()
    {
        Assert.Throws<InvalidOperationException>(
            () => Bls12381Validation.EnsureValidG1ForPairing(G1AffinePoint.Infinity));

        Assert.Throws<InvalidOperationException>(
            () => Bls12381Validation.EnsureValidG2ForPairing(G2AffinePoint.Infinity));
    }

    [Fact]
    public void G1_CompressedSerialization_ShouldRoundTrip()
    {
        var encoded = Bls12381PointSerialization.SerializeG1Compressed(G1AffinePoint.Generator);
        var decoded = Bls12381PointSerialization.DeserializeG1Compressed(encoded);
        Assert.Equal(G1AffinePoint.Generator, decoded);
    }

    [Fact]
    public void G2_CompressedSerialization_ShouldRoundTrip()
    {
        var encoded = Bls12381PointSerialization.SerializeG2Compressed(G2AffinePoint.Generator);
        var decoded = Bls12381PointSerialization.DeserializeG2Compressed(encoded);
        Assert.Equal(G2AffinePoint.Generator, decoded);
    }

    [Fact]
    public void CompressedDeserialization_ShouldRejectUncompressedFlag()
    {
        var g1 = Bls12381PointSerialization.SerializeG1Compressed(G1AffinePoint.Generator);
        g1[0] &= 0b0111_1111;
        Assert.Throws<FormatException>(() => Bls12381PointSerialization.DeserializeG1Compressed(g1));
    }
}
