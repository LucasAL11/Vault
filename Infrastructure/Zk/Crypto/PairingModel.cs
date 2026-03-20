namespace Infrastructure.Zk.Crypto;

// In-process algebraic model for BLS12-381 groups.
// This preserves group and bilinearity properties for tests and API contracts,
// but does not implement affine/jacobian curve coordinates.
public readonly struct G1Point : IEquatable<G1Point>
{
    private readonly Fr _scalar;

    private G1Point(Fr scalar, bool isInfinity)
    {
        _scalar = scalar;
        IsInfinity = isInfinity;
    }

    public bool IsInfinity { get; }
    public static G1Point Infinity => new(Fr.Zero, true);
    public static G1Point Generator => new(Fr.One, false);

    public static G1Point FromScalar(Fr scalar) => scalar == Fr.Zero ? Infinity : new(scalar, false);
    public Fr Scalar => IsInfinity ? Fr.Zero : _scalar;

    public static G1Point operator +(G1Point left, G1Point right)
        => FromScalar(left.Scalar + right.Scalar);

    public static G1Point operator -(G1Point value)
        => FromScalar(-value.Scalar);

    public G1Point Multiply(Fr scalar) => FromScalar(Scalar * scalar);

    public bool Equals(G1Point other) => IsInfinity == other.IsInfinity && Scalar == other.Scalar;
    public override bool Equals(object? obj) => obj is G1Point other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(Scalar, IsInfinity);
    public static bool operator ==(G1Point left, G1Point right) => left.Equals(right);
    public static bool operator !=(G1Point left, G1Point right) => !left.Equals(right);
}

public readonly struct G2Point : IEquatable<G2Point>
{
    private readonly Fr _scalar;

    private G2Point(Fr scalar, bool isInfinity)
    {
        _scalar = scalar;
        IsInfinity = isInfinity;
    }

    public bool IsInfinity { get; }
    public static G2Point Infinity => new(Fr.Zero, true);
    public static G2Point Generator => new(Fr.One, false);

    public static G2Point FromScalar(Fr scalar) => scalar == Fr.Zero ? Infinity : new(scalar, false);
    public Fr Scalar => IsInfinity ? Fr.Zero : _scalar;

    public static G2Point operator +(G2Point left, G2Point right)
        => FromScalar(left.Scalar + right.Scalar);

    public static G2Point operator -(G2Point value)
        => FromScalar(-value.Scalar);

    public G2Point Multiply(Fr scalar) => FromScalar(Scalar * scalar);

    public bool Equals(G2Point other) => IsInfinity == other.IsInfinity && Scalar == other.Scalar;
    public override bool Equals(object? obj) => obj is G2Point other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(Scalar, IsInfinity);
    public static bool operator ==(G2Point left, G2Point right) => left.Equals(right);
    public static bool operator !=(G2Point left, G2Point right) => !left.Equals(right);
}

public readonly struct GtElement : IEquatable<GtElement>
{
    private readonly Fr _exponent;

    public GtElement(Fr exponent)
    {
        _exponent = exponent;
    }

    public static GtElement One => new(Fr.Zero);
    public Fr Exponent => _exponent;

    public static GtElement operator *(GtElement left, GtElement right)
        => new(left._exponent + right._exponent);

    public GtElement Pow(Fr scalar) => new(_exponent * scalar);

    public bool Equals(GtElement other) => _exponent == other._exponent;
    public override bool Equals(object? obj) => obj is GtElement other && Equals(other);
    public override int GetHashCode() => _exponent.GetHashCode();
    public static bool operator ==(GtElement left, GtElement right) => left.Equals(right);
    public static bool operator !=(GtElement left, GtElement right) => !left.Equals(right);
}

public static class Bls12381Pairing
{
    public static GtElement Pair(G1Point p, G2Point q)
    {
        if (p.IsInfinity || q.IsInfinity)
        {
            return GtElement.One;
        }

        // e(g1^a, g2^b) = gt^(a*b) in this algebraic model.
        return new GtElement(p.Scalar * q.Scalar);
    }
}
