using System.Numerics;

namespace Infrastructure.Zk.Crypto;

public readonly struct Fp6 : IEquatable<Fp6>
{
    // Fp6 = Fp2[v] / (v^3 - xi), xi = u + 1.
    private static readonly Fp2 Xi = new(new Fp(1), new Fp(1));

    public Fp2 C0 { get; }
    public Fp2 C1 { get; }
    public Fp2 C2 { get; }

    public Fp6(Fp2 c0, Fp2 c1, Fp2 c2)
    {
        C0 = c0;
        C1 = c1;
        C2 = c2;
    }

    public static Fp6 Zero => new(Fp2.Zero, Fp2.Zero, Fp2.Zero);
    public static Fp6 One => new(Fp2.One, Fp2.Zero, Fp2.Zero);
    public static Fp6 V => new(Fp2.Zero, Fp2.One, Fp2.Zero);

    public static Fp6 operator +(Fp6 left, Fp6 right)
        => new(left.C0 + right.C0, left.C1 + right.C1, left.C2 + right.C2);

    public static Fp6 operator -(Fp6 left, Fp6 right)
        => new(left.C0 - right.C0, left.C1 - right.C1, left.C2 - right.C2);

    public static Fp6 operator -(Fp6 value)
        => new(-value.C0, -value.C1, -value.C2);

    public static Fp6 operator *(Fp6 left, Fp6 right)
    {
        var a0 = left.C0;
        var a1 = left.C1;
        var a2 = left.C2;
        var b0 = right.C0;
        var b1 = right.C1;
        var b2 = right.C2;

        var d0 = a0 * b0;
        var d1 = (a0 * b1) + (a1 * b0);
        var d2 = (a0 * b2) + (a1 * b1) + (a2 * b0);
        var d3 = (a1 * b2) + (a2 * b1);
        var d4 = a2 * b2;

        return new Fp6(
            d0 + MultiplyByXi(d3),
            d1 + MultiplyByXi(d4),
            d2);
    }

    public Fp6 Square() => this * this;

    public Fp6 Pow(BigInteger exponent)
    {
        if (exponent.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(exponent), "Exponent must be non-negative.");
        }

        if (exponent.IsZero)
        {
            return One;
        }

        var result = One;
        var baseValue = this;
        var bitLength = FieldElementMath.BitLength(exponent);
        for (var i = bitLength - 1; i >= 0; i--)
        {
            result = result.Square();
            var multiplied = result * baseValue;
            var bit = FieldElementMath.GetBit(exponent, i);
            result = Select(result, multiplied, bit);
        }

        return result;
    }

    public Fp6 MultiplyByV()
    {
        // (c0 + c1*v + c2*v^2) * v = c2*xi + c0*v + c1*v^2
        return new Fp6(MultiplyByXi(C2), C0, C1);
    }

    public Fp6 Inverse()
    {
        // Inverse in cubic extension:
        // t0 = a0^2 - xi*a1*a2
        // t1 = xi*a2^2 - a0*a1
        // t2 = a1^2 - a0*a2
        // den = a0*t0 + xi*(a2*t1 + a1*t2)
        // inv = (t0 + t1*v + t2*v^2) / den
        var a0 = C0;
        var a1 = C1;
        var a2 = C2;

        var t0 = (a0 * a0) - MultiplyByXi(a1 * a2);
        var t1 = MultiplyByXi(a2 * a2) - (a0 * a1);
        var t2 = (a1 * a1) - (a0 * a2);

        var den = (a0 * t0) + MultiplyByXi((a2 * t1) + (a1 * t2));
        var denInv = den.Inverse();

        return new Fp6(t0 * denInv, t1 * denInv, t2 * denInv);
    }

    public Fp6 FrobeniusMap(int power)
    {
        var n = ((power % 6) + 6) % 6;
        return new Fp6(
            C0.FrobeniusMap(n),
            C1.FrobeniusMap(n) * Bls12381FrobeniusConstants.GetFp6C1(n),
            C2.FrobeniusMap(n) * Bls12381FrobeniusConstants.GetFp6C2(n));
    }

    private static Fp2 MultiplyByXi(Fp2 value) => value * Xi;

    internal static Fp6 Select(Fp6 whenZero, Fp6 whenOne, int bit)
        => new(
            SelectFp2(whenZero.C0, whenOne.C0, bit),
            SelectFp2(whenZero.C1, whenOne.C1, bit),
            SelectFp2(whenZero.C2, whenOne.C2, bit));

    private static Fp2 SelectFp2(Fp2 whenZero, Fp2 whenOne, int bit)
        => new(
            FieldElementMath.SelectFp(whenZero.C0, whenOne.C0, bit),
            FieldElementMath.SelectFp(whenZero.C1, whenOne.C1, bit));

    public bool Equals(Fp6 other) => C0 == other.C0 && C1 == other.C1 && C2 == other.C2;
    public override bool Equals(object? obj) => obj is Fp6 other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(C0, C1, C2);
    public static bool operator ==(Fp6 left, Fp6 right) => left.Equals(right);
    public static bool operator !=(Fp6 left, Fp6 right) => !left.Equals(right);
}

public readonly struct Fp12 : IEquatable<Fp12>
{
    // Fp12 = Fp6[w] / (w^2 - v), where v is Fp6 basis element.
    public Fp6 C0 { get; }
    public Fp6 C1 { get; }

    public Fp12(Fp6 c0, Fp6 c1)
    {
        C0 = c0;
        C1 = c1;
    }

    public static Fp12 Zero => new(Fp6.Zero, Fp6.Zero);
    public static Fp12 One => new(Fp6.One, Fp6.Zero);

    public static Fp12 operator +(Fp12 left, Fp12 right)
        => new(left.C0 + right.C0, left.C1 + right.C1);

    public static Fp12 operator -(Fp12 left, Fp12 right)
        => new(left.C0 - right.C0, left.C1 - right.C1);

    public static Fp12 operator -(Fp12 value)
        => new(-value.C0, -value.C1);

    public static Fp12 operator *(Fp12 left, Fp12 right)
    {
        var a0 = left.C0;
        var a1 = left.C1;
        var b0 = right.C0;
        var b1 = right.C1;

        var t0 = a0 * b0;
        var t1 = a1 * b1;

        return new Fp12(
            t0 + t1.MultiplyByV(),
            (a0 * b1) + (a1 * b0));
    }

    public Fp12 Square() => this * this;

    // Dedicated API for cyclotomic squaring path used in final exponentiation hard-part.
    // For the current representation we preserve correctness by reusing square.
    public Fp12 CyclotomicSquare() => Square();

    public Fp12 Conjugate() => new(C0, -C1);

    public Fp12 Inverse()
    {
        // (a0 + a1*w)^-1 = (a0 - a1*w)/(a0^2 - v*a1^2)
        var t0 = (C0 * C0) - (C1 * C1).MultiplyByV();
        var t0Inv = t0.Inverse();
        return new Fp12(C0 * t0Inv, -(C1 * t0Inv));
    }

    public Fp12 FrobeniusMap(int power)
    {
        var n = ((power % 12) + 12) % 12;
        return new Fp12(
            C0.FrobeniusMap(n),
            C1.FrobeniusMap(n) * Bls12381FrobeniusConstants.GetFp12C1(n));
    }

    public Fp12 Pow(BigInteger exponent)
    {
        if (exponent.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(exponent), "Exponent must be non-negative.");
        }

        if (exponent.IsZero)
        {
            return One;
        }

        var result = One;
        var baseValue = this;
        var bitLength = FieldElementMath.BitLength(exponent);
        for (var i = bitLength - 1; i >= 0; i--)
        {
            result = result.Square();
            var multiplied = result * baseValue;
            var bit = FieldElementMath.GetBit(exponent, i);
            result = Select(result, multiplied, bit);
        }

        return result;
    }

    public Fp12 PowWindowed(BigInteger exponent, int windowSize = 4)
        => PowWindowCore(exponent, windowSize, useCyclotomicSquare: false);

    public Fp12 PowCyclotomicWindowed(BigInteger exponent, int windowSize = 4)
        => PowWindowCore(exponent, windowSize, useCyclotomicSquare: true);

    public Fp12 ExpByX(BigInteger xAbs, bool isNegativeX)
    {
        if (xAbs.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(xAbs), "x must be non-negative.");
        }

        var result = One;
        var bitLength = FieldElementMath.BitLength(xAbs);
        for (var i = bitLength - 1; i >= 0; i--)
        {
            result = result.CyclotomicSquare();
            var multiplied = result * this;
            var bit = FieldElementMath.GetBit(xAbs, i);
            result = Select(result, multiplied, bit);
        }

        return isNegativeX ? result.Conjugate() : result;
    }

    public Fp12 ExpByBlsX()
        => ExpByX(Bls12381Constants.BParameterXAbs, Bls12381Constants.BParameterXIsNegative);

    private Fp12 PowWindowCore(BigInteger exponent, int windowSize, bool useCyclotomicSquare)
    {
        if (exponent.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(exponent), "Exponent must be non-negative.");
        }

        if (windowSize < 2 || windowSize > 8)
        {
            throw new ArgumentOutOfRangeException(nameof(windowSize), "Window size must be between 2 and 8.");
        }

        if (exponent.IsZero)
        {
            return One;
        }

        var result = One;
        var bitLength = FieldElementMath.BitLength(exponent);
        for (var i = bitLength - 1; i >= 0; i--)
        {
            result = useCyclotomicSquare ? result.CyclotomicSquare() : result.Square();
            var multiplied = result * this;
            var bit = FieldElementMath.GetBit(exponent, i);
            result = Select(result, multiplied, bit);
        }

        return result;
    }

    private static Fp12 Select(Fp12 whenZero, Fp12 whenOne, int bit)
        => new(
            Fp6.Select(whenZero.C0, whenOne.C0, bit),
            Fp6.Select(whenZero.C1, whenOne.C1, bit));

    public bool Equals(Fp12 other) => C0 == other.C0 && C1 == other.C1;
    public override bool Equals(object? obj) => obj is Fp12 other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(C0, C1);
    public static bool operator ==(Fp12 left, Fp12 right) => left.Equals(right);
    public static bool operator !=(Fp12 left, Fp12 right) => !left.Equals(right);
}
