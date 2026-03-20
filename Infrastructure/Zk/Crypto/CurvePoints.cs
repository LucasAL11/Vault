using System.Numerics;

namespace Infrastructure.Zk.Crypto;

public readonly struct G1AffinePoint : IEquatable<G1AffinePoint>
{
    private readonly bool _hasKnownScalar;
    private readonly Fr _knownScalar;

    public Fp X { get; }
    public Fp Y { get; }
    public bool IsInfinity { get; }

    private G1AffinePoint(Fp x, Fp y, bool infinity, bool hasKnownScalar, Fr knownScalar)
    {
        X = x;
        Y = y;
        IsInfinity = infinity;
        _hasKnownScalar = hasKnownScalar;
        _knownScalar = knownScalar;
    }

    public static G1AffinePoint Infinity => new(Fp.Zero, Fp.Zero, true, true, Fr.Zero);
    public static G1AffinePoint FromCoordinates(Fp x, Fp y) => new(x, y, false, false, Fr.Zero);

    // IETF BLS12-381 G1 generator
    public static G1AffinePoint Generator => new(
        Bls12381FieldParsing.ParseFpHex("17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB"),
        Bls12381FieldParsing.ParseFpHex("08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1"),
        false,
        true,
        Fr.One);

    public bool IsOnCurve()
    {
        if (IsInfinity)
        {
            return true;
        }

        // y^2 = x^3 + 4
        var left = Y * Y;
        var right = (X * X * X) + new Fp(4);
        return left == right;
    }

    public G1AffinePoint Add(G1AffinePoint other)
    {
        if (IsInfinity) return other;
        if (other.IsInfinity) return this;

        if (X == other.X)
        {
            if (Y != other.Y)
            {
                return Infinity;
            }

            return Double();
        }

        var lambda = (other.Y - Y) * (other.X - X).Inverse();
        var xr = (lambda * lambda) - X - other.X;
        var yr = lambda * (X - xr) - Y;

        return new G1AffinePoint(
            xr,
            yr,
            false,
            _hasKnownScalar && other._hasKnownScalar,
            new Fr(_knownScalar.Value + other._knownScalar.Value));
    }

    public G1AffinePoint Double()
    {
        if (IsInfinity || Y == Fp.Zero)
        {
            return Infinity;
        }

        var lambda = (new Fp(3) * X * X) * (new Fp(2) * Y).Inverse();
        var xr = (lambda * lambda) - (new Fp(2) * X);
        var yr = lambda * (X - xr) - Y;

        return new G1AffinePoint(
            xr,
            yr,
            false,
            _hasKnownScalar,
            new Fr(_knownScalar.Value + _knownScalar.Value));
    }

    public G1AffinePoint Multiply(Fr scalar)
    {
        var acc = MultiplyUnchecked(scalar.Value);
        return new G1AffinePoint(acc.X, acc.Y, acc.IsInfinity, _hasKnownScalar, new Fr(_knownScalar.Value * scalar.Value));
    }

    public G1AffinePoint Negate()
    {
        if (IsInfinity)
        {
            return this;
        }

        return new G1AffinePoint(X, -Y, false, _hasKnownScalar, new Fr(-_knownScalar.Value));
    }

    public bool IsInPrimeOrderSubgroup()
    {
        if (IsInfinity)
        {
            return false;
        }

        return MultiplyUnchecked(Bls12381Constants.SubgroupOrder).IsInfinity;
    }

    public G1AffinePoint ClearCofactor()
    {
        var acc = MultiplyUnchecked(Bls12381Constants.G1Cofactor);
        return new G1AffinePoint(acc.X, acc.Y, acc.IsInfinity, false, Fr.Zero);
    }

    internal bool TryGetKnownScalar(out Fr scalar)
    {
        scalar = _knownScalar;
        return _hasKnownScalar;
    }

    private G1AffinePoint MultiplyUnchecked(BigInteger scalar)
    {
        if (scalar.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(scalar), "Scalar must be non-negative.");
        }

        if (scalar.IsZero || IsInfinity)
        {
            return Infinity;
        }

        var r0 = Infinity;
        var r1 = this;
        var bitLength = FieldElementMath.BitLength(scalar);
        for (var i = bitLength - 1; i >= 0; i--)
        {
            var bit = FieldElementMath.GetBit(scalar, i);
            var sum = r0.Add(r1);
            var dbl0 = r0.Double();
            var dbl1 = r1.Double();
            r0 = SelectPoint(dbl0, sum, bit);
            r1 = SelectPoint(sum, dbl1, bit);
        }

        return r0;
    }

    private static G1AffinePoint SelectPoint(G1AffinePoint whenZero, G1AffinePoint whenOne, int bit)
    {
        return new G1AffinePoint(
            FieldElementMath.SelectFp(whenZero.X, whenOne.X, bit),
            FieldElementMath.SelectFp(whenZero.Y, whenOne.Y, bit),
            FieldElementMath.SelectBool(whenZero.IsInfinity, whenOne.IsInfinity, bit),
            false,
            Fr.Zero);
    }

    public bool Equals(G1AffinePoint other)
        => IsInfinity == other.IsInfinity && X == other.X && Y == other.Y;

    public override bool Equals(object? obj) => obj is G1AffinePoint other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(X, Y, IsInfinity);
    public static bool operator ==(G1AffinePoint left, G1AffinePoint right) => left.Equals(right);
    public static bool operator !=(G1AffinePoint left, G1AffinePoint right) => !left.Equals(right);
}

public readonly struct G2AffinePoint : IEquatable<G2AffinePoint>
{
    private readonly bool _hasKnownScalar;
    private readonly Fr _knownScalar;

    public Fp2 X { get; }
    public Fp2 Y { get; }
    public bool IsInfinity { get; }

    private G2AffinePoint(Fp2 x, Fp2 y, bool infinity, bool hasKnownScalar, Fr knownScalar)
    {
        X = x;
        Y = y;
        IsInfinity = infinity;
        _hasKnownScalar = hasKnownScalar;
        _knownScalar = knownScalar;
    }

    public static G2AffinePoint Infinity => new(Fp2.Zero, Fp2.Zero, true, true, Fr.Zero);
    public static G2AffinePoint FromCoordinates(Fp2 x, Fp2 y) => new(x, y, false, false, Fr.Zero);

    // IETF BLS12-381 G2 generator over Fp2.
    public static G2AffinePoint Generator => new(
        new Fp2(
            Bls12381FieldParsing.ParseFpHex("024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8"),
            Bls12381FieldParsing.ParseFpHex("13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E")),
        new Fp2(
            Bls12381FieldParsing.ParseFpHex("0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801"),
            Bls12381FieldParsing.ParseFpHex("0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE")),
        false,
        true,
        Fr.One);

    public bool IsOnCurve()
    {
        if (IsInfinity)
        {
            return true;
        }

        // y^2 = x^3 + b2, with b2 = 4(u + 1) = (4,4) for BLS12-381 twist.
        var left = Y * Y;
        var right = (X * X * X) + new Fp2(new Fp(4), new Fp(4));
        return left == right;
    }

    public G2AffinePoint Add(G2AffinePoint other)
    {
        if (IsInfinity) return other;
        if (other.IsInfinity) return this;

        if (X == other.X)
        {
            if (Y != other.Y)
            {
                return Infinity;
            }

            return Double();
        }

        var lambda = (other.Y - Y) * (other.X - X).Inverse();
        var xr = (lambda * lambda) - X - other.X;
        var yr = lambda * (X - xr) - Y;

        return new G2AffinePoint(
            xr,
            yr,
            false,
            _hasKnownScalar && other._hasKnownScalar,
            new Fr(_knownScalar.Value + other._knownScalar.Value));
    }

    public G2AffinePoint Double()
    {
        if (IsInfinity || Y == Fp2.Zero)
        {
            return Infinity;
        }

        var lambda = (new Fp2(new Fp(3), Fp.Zero) * X * X) * (new Fp2(new Fp(2), Fp.Zero) * Y).Inverse();
        var xr = (lambda * lambda) - (new Fp2(new Fp(2), Fp.Zero) * X);
        var yr = lambda * (X - xr) - Y;

        return new G2AffinePoint(
            xr,
            yr,
            false,
            _hasKnownScalar,
            new Fr(_knownScalar.Value + _knownScalar.Value));
    }

    public G2AffinePoint Multiply(Fr scalar)
    {
        var acc = MultiplyUnchecked(scalar.Value);
        return new G2AffinePoint(acc.X, acc.Y, acc.IsInfinity, _hasKnownScalar, new Fr(_knownScalar.Value * scalar.Value));
    }

    public G2AffinePoint MultiplyByBigInteger(BigInteger scalar)
    {
        var acc = MultiplyUnchecked(scalar);
        return new G2AffinePoint(acc.X, acc.Y, acc.IsInfinity, false, Fr.Zero);
    }

    public G2AffinePoint Negate()
    {
        if (IsInfinity)
        {
            return this;
        }

        return new G2AffinePoint(X, -Y, false, _hasKnownScalar, new Fr(-_knownScalar.Value));
    }

    public bool IsInPrimeOrderSubgroup()
    {
        if (IsInfinity)
        {
            return false;
        }

        return MultiplyUnchecked(Bls12381Constants.SubgroupOrder).IsInfinity;
    }

    public bool IsInPrimeOrderSubgroupFast()
    {
        if (IsInfinity)
        {
            return false;
        }

        var psi = ApplyPsi();
        var xQ = MultiplyByBigInteger(Bls12381Constants.BParameterXAbs);

        // x for BLS12-381 is negative. Relation uses [-x]Q.
        if (psi == xQ.Negate())
        {
            return true;
        }

        // Safe fallback.
        return IsInPrimeOrderSubgroup();
    }

    internal bool TryGetKnownScalar(out Fr scalar)
    {
        scalar = _knownScalar;
        return _hasKnownScalar;
    }

    private G2AffinePoint MultiplyUnchecked(BigInteger scalar)
    {
        if (scalar.Sign < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(scalar), "Scalar must be non-negative.");
        }

        if (scalar.IsZero || IsInfinity)
        {
            return Infinity;
        }

        var r0 = Infinity;
        var r1 = this;
        var bitLength = FieldElementMath.BitLength(scalar);
        for (var i = bitLength - 1; i >= 0; i--)
        {
            var bit = FieldElementMath.GetBit(scalar, i);
            var sum = r0.Add(r1);
            var dbl0 = r0.Double();
            var dbl1 = r1.Double();
            r0 = SelectPoint(dbl0, sum, bit);
            r1 = SelectPoint(sum, dbl1, bit);
        }

        return r0;
    }

    private static G2AffinePoint SelectPoint(G2AffinePoint whenZero, G2AffinePoint whenOne, int bit)
    {
        return new G2AffinePoint(
            SelectFp2(whenZero.X, whenOne.X, bit),
            SelectFp2(whenZero.Y, whenOne.Y, bit),
            FieldElementMath.SelectBool(whenZero.IsInfinity, whenOne.IsInfinity, bit),
            false,
            Fr.Zero);
    }

    private static Fp2 SelectFp2(Fp2 whenZero, Fp2 whenOne, int bit)
    {
        return new Fp2(
            FieldElementMath.SelectFp(whenZero.C0, whenOne.C0, bit),
            FieldElementMath.SelectFp(whenZero.C1, whenOne.C1, bit));
    }

    private G2AffinePoint ApplyPsi()
    {
        if (IsInfinity)
        {
            return this;
        }

        var x = X.FrobeniusMap(1) * Bls12381Constants.PsiCoeffX;
        var y = Y.FrobeniusMap(1) * Bls12381Constants.PsiCoeffY;
        return new G2AffinePoint(x, y, false, false, Fr.Zero);
    }

    public bool Equals(G2AffinePoint other)
        => IsInfinity == other.IsInfinity && X == other.X && Y == other.Y;

    public override bool Equals(object? obj) => obj is G2AffinePoint other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(X, Y, IsInfinity);
    public static bool operator ==(G2AffinePoint left, G2AffinePoint right) => left.Equals(right);
    public static bool operator !=(G2AffinePoint left, G2AffinePoint right) => !left.Equals(right);
}
