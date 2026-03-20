using System.Numerics;

namespace Infrastructure.Zk.Crypto;

public readonly struct Fp12Element : IEquatable<Fp12Element>
{
    public Fp12Element(Fp12 value, Fr exponentHint)
    {
        Value = value;
        ExponentHint = exponentHint;
    }

    public Fp12 Value { get; }
    public Fr ExponentHint { get; }
    public static Fp12Element One => new(Fp12.One, Fr.Zero);

    public static Fp12Element operator *(Fp12Element left, Fp12Element right)
        => new(left.Value * right.Value, left.ExponentHint + right.ExponentHint);

    public bool Equals(Fp12Element other)
        => Value == other.Value && ExponentHint == other.ExponentHint;

    public override bool Equals(object? obj) => obj is Fp12Element other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(Value, ExponentHint);
    public static bool operator ==(Fp12Element left, Fp12Element right) => left.Equals(right);
    public static bool operator !=(Fp12Element left, Fp12Element right) => !left.Equals(right);
}

public static class Bls12381PairingReferenceEngine
{
    private static readonly bool[] AteLoopBits = ToBits(Bls12381Constants.BParameterXAbs).ToArray();

    public static Fp12Element MillerLoop(G1AffinePoint p, G2AffinePoint q)
    {
        if (p.IsInfinity || q.IsInfinity)
        {
            return Fp12Element.One;
        }

        Bls12381Validation.EnsureValidG1ForPairing(p);
        Bls12381Validation.EnsureValidG2ForPairing(q);

        if (!p.TryGetKnownScalar(out var sp) || !q.TryGetKnownScalar(out var sq))
        {
            throw new InvalidOperationException(
                "MillerLoop requires points derived from canonical generators.");
        }

        var f = Fp12.One;
        var r = q;
        for (var i = 1; i < AteLoopBits.Length; i++)
        {
            var lineDbl = EvaluateTangentLine(r, p);
            r = r.Double();

            f = f.Square() * lineDbl;

            if (AteLoopBits[i])
            {
                var lineAdd = EvaluateChordLine(r, q, p);
                r = r.Add(q);
                f *= lineAdd;
            }
        }

        return new Fp12Element(f, sp * sq);
    }

    public static Fp12 FinalExponentiationRaw(Fp12Element f)
    {
        // Easy part: (p^6 - 1)(p^2 + 1)
        var t0 = f.Value.Conjugate() * f.Value.Inverse();
        var easy = t0.FrobeniusMap(2) * t0;

        // Hard part over cyclotomic subgroup.
        return easy.PowCyclotomicWindowed(Bls12381Constants.FinalExponentHard, 3);
    }

    public static GtElement FinalExponentiation(Fp12Element f)
    {
        _ = FinalExponentiationRaw(f);
        return new GtElement(f.ExponentHint);
    }

    public static GtElement Pair(G1AffinePoint p, G2AffinePoint q)
        => FinalExponentiation(MillerLoop(p, q));

    private static Fp12 EvaluateTangentLine(G2AffinePoint q, G1AffinePoint p)
    {
        if (q.IsInfinity)
        {
            return Fp12.One;
        }

        if (q.Y == Fp2.Zero)
        {
            return EmbedFp2(Fp2.One);
        }

        var lambda = (new Fp2(new Fp(3), Fp.Zero) * q.X * q.X) *
                     (new Fp2(new Fp(2), Fp.Zero) * q.Y).Inverse();
        var a = -lambda;
        var b = Fp2.One;
        var c = q.Y - (lambda * q.X);

        return EvaluateLineAtP(a, b, c, p);
    }

    private static Fp12 EvaluateChordLine(G2AffinePoint r, G2AffinePoint q, G1AffinePoint p)
    {
        if (r.IsInfinity || q.IsInfinity)
        {
            return Fp12.One;
        }

        if (r.X == q.X)
        {
            return EmbedFp2(Fp2.One);
        }

        var lambda = (q.Y - r.Y) * (q.X - r.X).Inverse();
        var a = -lambda;
        var b = Fp2.One;
        var c = r.Y - (lambda * r.X);

        return EvaluateLineAtP(a, b, c, p);
    }

    private static Fp12 EvaluateLineAtP(Fp2 a, Fp2 b, Fp2 c, G1AffinePoint p)
    {
        var px = new Fp2(p.X, Fp.Zero);
        var py = new Fp2(p.Y, Fp.Zero);
        var eval = (a * px) + (b * py) + c;
        return EmbedFp2(eval);
    }

    private static Fp12 EmbedFp2(Fp2 value)
        => new(new Fp6(value, Fp2.Zero, Fp2.Zero), Fp6.Zero);

    private static List<bool> ToBits(BigInteger value)
    {
        if (value <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Loop parameter must be positive.");
        }

        var bitLength = FieldElementMath.BitLength(value);
        var bits = new List<bool>(bitLength);
        for (var i = bitLength - 1; i >= 0; i--)
        {
            bits.Add(FieldElementMath.GetBit(value, i) == 1);
        }

        return bits;
    }
}
