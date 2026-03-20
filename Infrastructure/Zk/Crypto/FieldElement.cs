using System.Numerics;

namespace Infrastructure.Zk.Crypto;

public readonly struct Fp : IEquatable<Fp>
{
    private readonly BigInteger _value;
    public BigInteger Value => _value;

    public Fp(BigInteger value) => _value = FieldElementMath.Mod(value, Bls12381Constants.FpModulus);

    public static Fp Zero => new(0);
    public static Fp One => new(1);

    public static Fp operator +(Fp left, Fp right) => new(left._value + right._value);
    public static Fp operator -(Fp left, Fp right) => new(left._value - right._value);
    public static Fp operator *(Fp left, Fp right) => new(left._value * right._value);
    public static Fp operator /(Fp left, Fp right) => left * right.Inverse();
    public static Fp operator -(Fp value) => new(-value._value);

    public Fp Inverse() => new(FieldElementMath.ModInverse(_value, Bls12381Constants.FpModulus));
    public Fp Pow(BigInteger exponent) => new(BigInteger.ModPow(_value, exponent, Bls12381Constants.FpModulus));

    public bool IsLexicographicallyLargest()
    {
        // Largest when value > (p - 1)/2
        var half = (Bls12381Constants.FpModulus - BigInteger.One) >> 1;
        return _value > half;
    }

    public bool TrySqrt(out Fp root)
    {
        var ok = FieldElementMath.TryModSqrt(_value, Bls12381Constants.FpModulus, out var r);
        root = new Fp(r);
        return ok;
    }

    public bool Equals(Fp other) => FieldElementMath.ConstantTimeEquals(ToFixedBigEndian(), other.ToFixedBigEndian());
    public override bool Equals(object? obj) => obj is Fp other && Equals(other);
    public override int GetHashCode() => _value.GetHashCode();
    public override string ToString() => _value.ToString();

    public static bool operator ==(Fp left, Fp right) => left.Equals(right);
    public static bool operator !=(Fp left, Fp right) => !left.Equals(right);

    public byte[] ToBytes48() => FieldElementMath.ToFixedBigEndian(_value, 48);
    private byte[] ToFixedBigEndian() => ToBytes48();
}

public readonly struct Fr : IEquatable<Fr>
{
    private readonly BigInteger _value;
    public BigInteger Value => _value;

    public Fr(BigInteger value) => _value = FieldElementMath.Mod(value, Bls12381Constants.FrModulus);

    public static Fr Zero => new(0);
    public static Fr One => new(1);

    public static Fr operator +(Fr left, Fr right) => new(left._value + right._value);
    public static Fr operator -(Fr left, Fr right) => new(left._value - right._value);
    public static Fr operator *(Fr left, Fr right) => new(left._value * right._value);
    public static Fr operator -(Fr value) => new(-value._value);

    public Fr Inverse() => new(FieldElementMath.ModInverse(_value, Bls12381Constants.FrModulus));

    public bool Equals(Fr other) => FieldElementMath.ConstantTimeEquals(ToFixedBigEndian(), other.ToFixedBigEndian());
    public override bool Equals(object? obj) => obj is Fr other && Equals(other);
    public override int GetHashCode() => _value.GetHashCode();
    public override string ToString() => _value.ToString();

    public static bool operator ==(Fr left, Fr right) => left.Equals(right);
    public static bool operator !=(Fr left, Fr right) => !left.Equals(right);

    private byte[] ToFixedBigEndian() => FieldElementMath.ToFixedBigEndian(_value, 32);
}

internal static class FieldElementMath
{
    public static BigInteger Mod(BigInteger value, BigInteger modulus)
    {
        var result = value % modulus;
        return result.Sign < 0 ? result + modulus : result;
    }

    public static BigInteger ModInverse(BigInteger value, BigInteger modulus)
    {
        if (value.IsZero)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Zero has no inverse in the field.");
        }

        // Extended Euclidean algorithm.
        var t = BigInteger.Zero;
        var newT = BigInteger.One;
        var r = modulus;
        var newR = Mod(value, modulus);

        while (newR != BigInteger.Zero)
        {
            var q = r / newR;
            (t, newT) = (newT, t - q * newT);
            (r, newR) = (newR, r - q * newR);
        }

        if (r > BigInteger.One)
        {
            throw new InvalidOperationException("Element is not invertible modulo field prime.");
        }

        if (t.Sign < 0)
        {
            t += modulus;
        }

        return t;
    }

    public static byte[] ToFixedBigEndian(BigInteger value, int length)
    {
        var normalized = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (normalized.Length > length)
        {
            throw new InvalidOperationException("Value does not fit fixed field element length.");
        }

        if (normalized.Length == length)
        {
            return normalized;
        }

        var result = new byte[length];
        Buffer.BlockCopy(normalized, 0, result, length - normalized.Length, normalized.Length);
        return result;
    }

    public static bool ConstantTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var maxLength = Math.Max(left.Length, right.Length);
        var leftBuffer = new byte[maxLength];
        var rightBuffer = new byte[maxLength];

        left.CopyTo(leftBuffer);
        right.CopyTo(rightBuffer);

        var diff = left.Length ^ right.Length;
        for (var i = 0; i < maxLength; i++)
        {
            diff |= leftBuffer[i] ^ rightBuffer[i];
        }

        return diff == 0;
    }

    public static int BitLength(BigInteger value)
    {
        if (value.Sign <= 0)
        {
            return 0;
        }

        var bits = 0;
        var n = value;
        while (n > 0)
        {
            bits++;
            n >>= 1;
        }

        return bits;
    }

    public static int GetBit(BigInteger value, int index)
        => (int)((value >> index) & BigInteger.One);

    public static BigInteger SelectBigInteger(BigInteger whenZero, BigInteger whenOne, int bit)
    {
        var normalizedBit = bit & 1;
        var mask = new BigInteger(-normalizedBit);
        return (whenZero & ~mask) | (whenOne & mask);
    }

    public static Fp SelectFp(Fp whenZero, Fp whenOne, int bit)
        => new(SelectBigInteger(whenZero.Value, whenOne.Value, bit));

    public static bool SelectBool(bool whenZero, bool whenOne, int bit)
    {
        var z = whenZero ? 1 : 0;
        var o = whenOne ? 1 : 0;
        var selected = z ^ ((z ^ o) & (bit & 1));
        return selected != 0;
    }

    public static bool TryModSqrt(BigInteger value, BigInteger prime, out BigInteger root)
    {
        var a = Mod(value, prime);
        if (a.IsZero)
        {
            root = BigInteger.Zero;
            return true;
        }

        // Legendre symbol check.
        if (BigInteger.ModPow(a, (prime - BigInteger.One) >> 1, prime) != BigInteger.One)
        {
            root = BigInteger.Zero;
            return false;
        }

        // p % 4 == 3 fast path.
        if ((prime & 3) == 3)
        {
            root = BigInteger.ModPow(a, (prime + BigInteger.One) >> 2, prime);
            return true;
        }

        // Tonelli-Shanks.
        var q = prime - BigInteger.One;
        var s = 0;
        while (q.IsEven)
        {
            q >>= 1;
            s++;
        }

        var z = new BigInteger(2);
        while (BigInteger.ModPow(z, (prime - BigInteger.One) >> 1, prime) != prime - BigInteger.One)
        {
            z++;
        }

        var m = s;
        var c = BigInteger.ModPow(z, q, prime);
        var t = BigInteger.ModPow(a, q, prime);
        var r = BigInteger.ModPow(a, (q + BigInteger.One) >> 1, prime);

        while (t != BigInteger.One)
        {
            var i = 1;
            var t2i = (t * t) % prime;
            while (i < m && t2i != BigInteger.One)
            {
                t2i = (t2i * t2i) % prime;
                i++;
            }

            if (i == m)
            {
                root = BigInteger.Zero;
                return false;
            }

            var b = BigInteger.ModPow(c, BigInteger.One << (m - i - 1), prime);
            r = (r * b) % prime;
            c = (b * b) % prime;
            t = (t * c) % prime;
            m = i;
        }

        root = Mod(r, prime);
        return true;
    }
}
