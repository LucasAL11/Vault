using System.Diagnostics;
using Infrastructure.Zk.Crypto;

public static class FullPairingCalculationRunner
{
    public static void Run()
    {
        var sw = Stopwatch.StartNew();
        PrintHeader("BLS12-381 Full Calculation Run");

        var g1 = G1AffinePoint.Generator;
        var g2 = G2AffinePoint.Generator;

        Step("1) Domain and generator validation", () =>
        {
            Console.WriteLine($"G1 on curve: {g1.IsOnCurve()}");
            Console.WriteLine($"G2 on curve: {g2.IsOnCurve()}");
            Console.WriteLine($"G1 subgroup: {g1.IsInPrimeOrderSubgroup()}");
            Console.WriteLine($"G2 subgroup (fast): {g2.IsInPrimeOrderSubgroupFast()}");
            Bls12381Validation.EnsureValidG1ForPairing(g1);
            Bls12381Validation.EnsureValidG2ForPairing(g2);
        });

        Step("2) Compressed serialization roundtrip", () =>
        {
            var g1Bytes = Bls12381PointSerialization.SerializeG1Compressed(g1);
            var g2Bytes = Bls12381PointSerialization.SerializeG2Compressed(g2);
            var g1Decoded = Bls12381PointSerialization.DeserializeG1Compressed(g1Bytes);
            var g2Decoded = Bls12381PointSerialization.DeserializeG2Compressed(g2Bytes);

            Console.WriteLine($"G1 bytes: {g1Bytes.Length}, roundtrip: {g1Decoded == g1}");
            Console.WriteLine($"G2 bytes: {g2Bytes.Length}, roundtrip: {g2Decoded == g2}");
        });

        var a = new Fr(7);
        var b = new Fr(11);
        var s = new Fr(3);
        var t = new Fr(13);

        var p = g1.Multiply(a);
        var q = g2.Multiply(b);

        Step("3) Point scalar multiplication", () =>
        {
            Console.WriteLine("Built P=[a]G1 and Q=[b]G2");
            Console.WriteLine($"a={a.Value}, b={b.Value}, s={s.Value}, t={t.Value}");
        });

        Fp12Element miller = default;
        Step("4) Miller loop", () =>
        {
            miller = Bls12381PairingReferenceEngine.MillerLoop(p, q);
            Console.WriteLine($"Miller hint exponent (mod r): {miller.ExponentHint.Value}");
            Console.WriteLine($"Miller value is one: {miller.Value == Fp12.One}");
        });

        Step("5) Final exponentiation (easy + hard/windowed)", () =>
        {
            var fe = Bls12381PairingReferenceEngine.FinalExponentiationRaw(miller);
            var feDirect = miller.Value.Pow(Bls12381Constants.FinalExponent);
            Console.WriteLine($"Final exp matches direct: {fe == feDirect}");
        });

        Step("6) GT projection and bilinearity check", () =>
        {
            var left = Bls12381PairingReferenceEngine.Pair(p.Multiply(s), q.Multiply(t));
            var right = Bls12381PairingReferenceEngine.Pair(p, q).Pow(s * t);
            Console.WriteLine($"Bilinearity: {left == right}");
            Console.WriteLine($"GT exponent(left): {left.Exponent.Value}");
            Console.WriteLine($"GT exponent(right): {right.Exponent.Value}");
        });

        sw.Stop();
        Console.WriteLine();
        Console.WriteLine($"Total elapsed: {sw.ElapsedMilliseconds} ms");
    }

    private static void Step(string name, Action action)
    {
        Console.WriteLine();
        Console.WriteLine(name);
        var sw = Stopwatch.StartNew();
        action();
        sw.Stop();
        Console.WriteLine($"Step time: {sw.ElapsedMilliseconds} ms");
    }

    private static void PrintHeader(string title)
    {
        Console.WriteLine(new string('=', title.Length));
        Console.WriteLine(title);
        Console.WriteLine(new string('=', title.Length));
    }
}
