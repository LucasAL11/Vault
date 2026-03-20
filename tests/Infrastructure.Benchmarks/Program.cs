using BenchmarkDotNet.Running;

if (args.Any(a => string.Equals(a, "--calc", StringComparison.OrdinalIgnoreCase)))
{
    FullPairingCalculationRunner.Run();
    return;
}

BenchmarkRunner.Run<Fp12PowBenchmarks>();
