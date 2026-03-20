using System.Numerics;
using System.Globalization;

namespace Infrastructure.Zk.Crypto;

public static class Bls12381Constants
{
    // Prime field modulus for BLS12-381 Fp.
    public static readonly BigInteger FpModulus = ParseHex(
        "1A0111EA397FE69A4B1BA7B6434BACD7" +
        "64774B84F38512BF6730D2A0F6B0F624" +
        "1EABFFFEB153FFFFB9FEFFFFFFFFAAAB");

    // Scalar field modulus (group order) for BLS12-381 Fr.
    public static readonly BigInteger FrModulus = ParseHex(
        "73EDA753299D7D483339D80809A1D805" +
        "53BDA402FFFE5BFEFFFFFFFF00000001");

    // BLS parameter x for BLS12-381: x = -0xd201000000010000.
    public static readonly BigInteger BParameterXAbs = ParseHex("00D201000000010000");
    public const bool BParameterXIsNegative = true;

    // Prime subgroup order r (same value as Fr modulus).
    public static readonly BigInteger SubgroupOrder = FrModulus;

    // Cofactor for G1 subgroup in E(Fp).
    public static readonly BigInteger G1Cofactor = ParseHex("396C8C005555E1568C00AAAB0000AAAB");

    // Exponent used by final exponentiation map into GT.
    public static readonly BigInteger FinalExponent = (BigInteger.Pow(FpModulus, 12) - BigInteger.One) / SubgroupOrder;
    public static readonly BigInteger FinalExponentEasy = (BigInteger.Pow(FpModulus, 6) - BigInteger.One) * (BigInteger.Pow(FpModulus, 2) + BigInteger.One);
    public static readonly BigInteger FinalExponentHard = FinalExponent / FinalExponentEasy;

    public static readonly Fp2 PsiCoeffX;
    public static readonly Fp2 PsiCoeffY;

    static Bls12381Constants()
    {
        var xi = new Fp2(new Fp(1), new Fp(1));
        PsiCoeffX = xi.Pow((FpModulus - BigInteger.One) / 3);
        PsiCoeffY = xi.Pow((FpModulus - BigInteger.One) / 2);
    }

    public static BigInteger ParseHex(string hex)
    {
        var normalized = hex.Replace(" ", string.Empty)
            .Replace("_", string.Empty)
            .Trim();
        var bytes = Convert.FromHexString(normalized);
        var unsignedLittleEndian = new byte[bytes.Length + 1];
        for (var i = 0; i < bytes.Length; i++)
        {
            unsignedLittleEndian[i] = bytes[bytes.Length - 1 - i];
        }

        return new BigInteger(unsignedLittleEndian);
    }

    public static string ToHex(BigInteger value)
        => value.ToString("X", CultureInfo.InvariantCulture);
}
