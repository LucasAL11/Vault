namespace Infrastructure.Zk.Crypto;

public static class Bls12381PointSerialization
{
    private const byte CompressionFlag = 0b1000_0000;
    private const byte InfinityFlag = 0b0100_0000;
    private const byte SortFlag = 0b0010_0000;

    public static byte[] SerializeG1Compressed(G1AffinePoint point)
    {
        var bytes = new byte[48];
        if (point.IsInfinity)
        {
            bytes[0] = (byte)(CompressionFlag | InfinityFlag);
            return bytes;
        }

        point.X.ToBytes48().CopyTo(bytes, 0);
        bytes[0] |= CompressionFlag;
        if (point.Y.IsLexicographicallyLargest())
        {
            bytes[0] |= SortFlag;
        }

        return bytes;
    }

    public static G1AffinePoint DeserializeG1Compressed(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 48)
        {
            throw new FormatException("Invalid G1 compressed size.");
        }

        var b0 = bytes[0];
        if ((b0 & CompressionFlag) == 0)
        {
            throw new FormatException("G1 point must be compressed.");
        }

        var isInfinity = (b0 & InfinityFlag) != 0;
        var isLargest = (b0 & SortFlag) != 0;

        Span<byte> xBytes = stackalloc byte[48];
        bytes.CopyTo(xBytes);
        xBytes[0] &= 0b0001_1111;

        var x = Bls12381FieldParsing.ParseFpBytes(xBytes);
        if (isInfinity)
        {
            if (x != Fp.Zero || isLargest)
            {
                throw new FormatException("Invalid G1 infinity encoding.");
            }

            return G1AffinePoint.Infinity;
        }

        var rhs = (x * x * x) + new Fp(4);
        if (!rhs.TrySqrt(out var y))
        {
            throw new FormatException("G1 point is not on curve.");
        }

        if (y.IsLexicographicallyLargest() != isLargest)
        {
            y = -y;
        }

        var point = G1AffinePoint.FromCoordinates(x, y);
        if (!point.IsOnCurve() || !point.IsInPrimeOrderSubgroup())
        {
            throw new FormatException("Invalid G1 subgroup encoding.");
        }

        return point;
    }

    public static byte[] SerializeG2Compressed(G2AffinePoint point)
    {
        var bytes = new byte[96];
        if (point.IsInfinity)
        {
            bytes[0] = (byte)(CompressionFlag | InfinityFlag);
            return bytes;
        }

        point.X.C1.ToBytes48().CopyTo(bytes, 0);
        point.X.C0.ToBytes48().CopyTo(bytes, 48);
        bytes[0] |= CompressionFlag;
        if (point.Y.IsLexicographicallyLargest())
        {
            bytes[0] |= SortFlag;
        }

        return bytes;
    }

    public static G2AffinePoint DeserializeG2Compressed(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 96)
        {
            throw new FormatException("Invalid G2 compressed size.");
        }

        var b0 = bytes[0];
        if ((b0 & CompressionFlag) == 0)
        {
            throw new FormatException("G2 point must be compressed.");
        }

        var isInfinity = (b0 & InfinityFlag) != 0;
        var isLargest = (b0 & SortFlag) != 0;

        Span<byte> x1Bytes = stackalloc byte[48];
        Span<byte> x0Bytes = stackalloc byte[48];
        bytes[..48].CopyTo(x1Bytes);
        bytes[48..].CopyTo(x0Bytes);
        x1Bytes[0] &= 0b0001_1111;

        var x = new Fp2(Bls12381FieldParsing.ParseFpBytes(x0Bytes), Bls12381FieldParsing.ParseFpBytes(x1Bytes));
        if (isInfinity)
        {
            if (x != Fp2.Zero || isLargest)
            {
                throw new FormatException("Invalid G2 infinity encoding.");
            }

            return G2AffinePoint.Infinity;
        }

        var rhs = (x * x * x) + new Fp2(new Fp(4), new Fp(4));
        if (!rhs.TrySqrt(out var y))
        {
            throw new FormatException("G2 point is not on curve.");
        }

        if (y.IsLexicographicallyLargest() != isLargest)
        {
            y = -y;
        }

        var point = G2AffinePoint.FromCoordinates(x, y);
        if (!point.IsOnCurve() || !point.IsInPrimeOrderSubgroupFast())
        {
            throw new FormatException("Invalid G2 subgroup encoding.");
        }

        return point;
    }
}
