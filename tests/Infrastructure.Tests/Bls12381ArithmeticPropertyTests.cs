using System.Numerics;
using Infrastructure.Zk.Crypto;
using Xunit;

namespace Infrastructure.Tests;

public sealed class Bls12381ArithmeticPropertyTests
{
    [Fact]
    public void Fp_AdditiveAndMultiplicativeIdentities_ShouldHold()
    {
        var a = new Fp(BigInteger.Parse("123456789012345678901234567890"));

        Assert.Equal(a, a + Fp.Zero);
        Assert.Equal(a, Fp.Zero + a);
        Assert.Equal(a, a * Fp.One);
        Assert.Equal(a, Fp.One * a);
    }

    [Fact]
    public void Fr_Inverse_ShouldProduceMultiplicativeIdentity()
    {
        var a = new Fr(BigInteger.Parse("98765432109876543210987654321"));
        var inv = a.Inverse();

        Assert.Equal(Fr.One, a * inv);
    }

    [Fact]
    public void G1AndG2_GroupLaw_ShouldHold()
    {
        var a = new Fr(17);
        var b = new Fr(29);

        var p = G1Point.Generator.Multiply(a);
        var q = G1Point.Generator.Multiply(b);
        var r = G1Point.Generator.Multiply(a + b);

        Assert.Equal(r, p + q);
        Assert.Equal(G1Point.Infinity, p + (-p));

        var p2 = G2Point.Generator.Multiply(a);
        var q2 = G2Point.Generator.Multiply(b);
        var r2 = G2Point.Generator.Multiply(a + b);

        Assert.Equal(r2, p2 + q2);
        Assert.Equal(G2Point.Infinity, p2 + (-p2));
    }

    [Fact]
    public void Pairing_Bilinearity_ShouldHold()
    {
        var a = new Fr(13);
        var b = new Fr(19);
        var s = new Fr(7);
        var t = new Fr(5);

        var p = G1Point.Generator.Multiply(a);
        var q = G2Point.Generator.Multiply(b);

        var left = Bls12381Pairing.Pair(p.Multiply(s), q.Multiply(t));
        var right = Bls12381Pairing.Pair(p, q).Pow(s * t);

        Assert.Equal(left, right);
    }

    [Fact]
    public void Pairing_NonDegenerateForGenerators_ShouldHold()
    {
        var gt = Bls12381Pairing.Pair(G1Point.Generator, G2Point.Generator);
        Assert.NotEqual(GtElement.One, gt);
    }
}
