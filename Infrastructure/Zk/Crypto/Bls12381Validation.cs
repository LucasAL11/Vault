namespace Infrastructure.Zk.Crypto;

public static class Bls12381Validation
{
    public static void EnsureValidG1ForPairing(G1AffinePoint point)
    {
        if (point.IsInfinity)
        {
            throw new InvalidOperationException("G1 point at infinity is not allowed for pairing input.");
        }

        if (!point.IsOnCurve())
        {
            throw new InvalidOperationException("G1 point is not on curve.");
        }

        if (!point.IsInPrimeOrderSubgroup())
        {
            throw new InvalidOperationException("G1 point is not in prime-order subgroup.");
        }
    }

    public static void EnsureValidG2ForPairing(G2AffinePoint point)
    {
        if (point.IsInfinity)
        {
            throw new InvalidOperationException("G2 point at infinity is not allowed for pairing input.");
        }

        if (!point.IsOnCurve())
        {
            throw new InvalidOperationException("G2 point is not on curve.");
        }

        if (!point.IsInPrimeOrderSubgroupFast())
        {
            throw new InvalidOperationException("G2 point is not in prime-order subgroup.");
        }
    }
}
