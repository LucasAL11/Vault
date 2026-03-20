using System.Numerics;

namespace Infrastructure.Zk.Crypto;

public readonly struct Fp2 : IEquatable<Fp2>
{
    public Fp C0 { get; }
    public Fp C1 { get; }

    public Fp2(Fp c0, Fp c1)
    {
        C0 = c0;
        C1 = c1;
    }

    public static Fp2 Zero => new(Fp.Zero, Fp.Zero);
    public static Fp2 One => new(Fp.One, Fp.Zero);

    public static Fp2 operator +(Fp2 left, Fp2 right) => new(left.C0 + right.C0, left.C1 + right.C1);
    public static Fp2 operator -(Fp2 left, Fp2 right) => new(left.C0 - right.C0, left.C1 - right.C1);
    public static Fp2 operator -(Fp2 value) => new(-value.C0, -value.C1);
    public static Fp2 operator /(Fp2 left, Fp2 right) => left * right.Inverse();

    // u^2 = -1 for this in-process model.
    public static Fp2 operator *(Fp2 left, Fp2 right)
    {
        var a = left.C0;
        var b = left.C1;
        var c = right.C0;
        var d = right.C1;

        return new Fp2((a * c) - (b * d), (a * d) + (b * c));
    }

    public Fp2 Square() => this * this;

    public Fp2 Inverse()
    {
        var denominator = (C0 * C0) + (C1 * C1);
        var inv = denominator.Inverse();
        return new Fp2(C0 * inv, -C1 * inv);
    }

    public Fp2 Conjugate() => new(C0, -C1);

    public Fp2 FrobeniusMap(int power)
    {
        var n = ((power % 2) + 2) % 2;
        return n == 0 ? this : Conjugate();
    }

    public Fp2 Pow(BigInteger exponent)
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

    public bool IsLexicographicallyLargest()
    {
        if (C1 != Fp.Zero)
        {
            return C1.IsLexicographicallyLargest();
        }

        return C0.IsLexicographicallyLargest();
    }

    public bool TrySqrt(out Fp2 root)
    {
        // For u^2 = -1:
        // If z = a + bu, solve x^2 - y^2 = a and 2xy = b.
        if (this == Zero)
        {
            root = Zero;
            return true;
        }

        if (C1 == Fp.Zero)
        {
            if (C0.TrySqrt(out var r0))
            {
                root = new Fp2(r0, Fp.Zero);
                return true;
            }

            // sqrt(a) = i*sqrt(-a)
            var neg = -C0;
            if (neg.TrySqrt(out var ri))
            {
                root = new Fp2(Fp.Zero, ri);
                return true;
            }

            root = Zero;
            return false;
        }

        var alpha = (C0 * C0) + (C1 * C1);
        if (!alpha.TrySqrt(out var sqrtAlpha))
        {
            root = Zero;
            return false;
        }

        var twoInv = new Fp(2).Inverse();
        var delta = (C0 + sqrtAlpha) * twoInv;
        if (!delta.TrySqrt(out var x))
        {
            delta = (C0 - sqrtAlpha) * twoInv;
            if (!delta.TrySqrt(out x))
            {
                root = Zero;
                return false;
            }
        }

        if (x == Fp.Zero)
        {
            root = Zero;
            return false;
        }

        var y = C1 * (new Fp(2) * x).Inverse();
        root = new Fp2(x, y);
        return true;
    }

    public bool Equals(Fp2 other) => C0 == other.C0 && C1 == other.C1;
    public override bool Equals(object? obj) => obj is Fp2 other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(C0, C1);
    public static bool operator ==(Fp2 left, Fp2 right) => left.Equals(right);
    public static bool operator !=(Fp2 left, Fp2 right) => !left.Equals(right);
    public override string ToString() => $"({C0}, {C1})";

    private static Fp2 Select(Fp2 whenZero, Fp2 whenOne, int bit)
        => new(
            FieldElementMath.SelectFp(whenZero.C0, whenOne.C0, bit),
            FieldElementMath.SelectFp(whenZero.C1, whenOne.C1, bit));
}

public static class Bls12381FieldParsing
{
    public static Fp ParseFpHex(string hex)
    {
        var bytes = Convert.FromHexString(hex);
        var little = new byte[bytes.Length + 1];
        for (var i = 0; i < bytes.Length; i++)
        {
            little[i] = bytes[bytes.Length - 1 - i];
        }

        return new Fp(new BigInteger(little));
    }

    public static Fp ParseFpBytes(ReadOnlySpan<byte> bigEndian)
    {
        var little = new byte[bigEndian.Length + 1];
        for (var i = 0; i < bigEndian.Length; i++)
        {
            little[i] = bigEndian[bigEndian.Length - 1 - i];
        }

        return new Fp(new BigInteger(little));
    }
}
