using System.Collections.Generic;
using System.Numerics;

namespace Infrastructure.Zk.Crypto;

public static class Bls12381FrobeniusConstants
{
    public static readonly Fp2[] Fp6C1;
    public static readonly Fp2[] Fp6C2;
    public static readonly Fp6[] Fp12C1;

    static Bls12381FrobeniusConstants()
    {
        var p = Bls12381Constants.FpModulus;
        var xi = new Fp2(new Fp(1), new Fp(1));
        var v = Fp6.V;

        Fp6C1 = new Fp2[6];
        Fp6C2 = new Fp2[6];
        Fp12C1 = new Fp6[12];

        var pPow = BigInteger.One;
        for (var i = 0; i < 12; i++)
        {
            if (i > 0)
            {
                pPow *= p;
            }

            if (i < 6)
            {
                var e1 = (pPow - BigInteger.One) / 3;
                Fp6C1[i] = xi.Pow(e1);
                Fp6C2[i] = xi.Pow(e1 * 2);
            }

            var eFp12 = (pPow - BigInteger.One) / 2;
            Fp12C1[i] = v.Pow(eFp12);
        }
    }

    public static Fp2 GetFp6C1(int power)
        => SelectFp2(Fp6C1, power);

    public static Fp2 GetFp6C2(int power)
        => SelectFp2(Fp6C2, power);

    public static Fp6 GetFp12C1(int power)
        => SelectFp6(Fp12C1, power);

    private static Fp2 SelectFp2(IReadOnlyList<Fp2> table, int power)
    {
        var normalized = NormalizePower(power, table.Count);
        var selected = Fp2.Zero;

        for (var i = 0; i < table.Count; i++)
        {
            var matchBit = ConstantTimeIntEquals(i, normalized);
            selected = SelectFp2(selected, table[i], matchBit);
        }

        return selected;
    }

    private static Fp6 SelectFp6(IReadOnlyList<Fp6> table, int power)
    {
        var normalized = NormalizePower(power, table.Count);
        var selected = Fp6.Zero;

        for (var i = 0; i < table.Count; i++)
        {
            var matchBit = ConstantTimeIntEquals(i, normalized);
            selected = Fp6.Select(selected, table[i], matchBit);
        }

        return selected;
    }

    private static Fp2 SelectFp2(Fp2 whenZero, Fp2 whenOne, int bit)
        => new(
            FieldElementMath.SelectFp(whenZero.C0, whenOne.C0, bit),
            FieldElementMath.SelectFp(whenZero.C1, whenOne.C1, bit));

    private static int NormalizePower(int power, int modulus)
        => ((power % modulus) + modulus) % modulus;

    private static int ConstantTimeIntEquals(int left, int right)
    {
        var x = (uint)(left ^ right);
        x |= (uint)-(int)x;
        return (int)((x >> 31) ^ 1u);
    }
}
