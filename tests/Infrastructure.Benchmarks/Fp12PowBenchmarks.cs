using System.Numerics;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using Infrastructure.Zk.Crypto;

[MemoryDiagnoser]
[SimpleJob(launchCount: 1, warmupCount: 1, iterationCount: 3)]
public class Fp12PowBenchmarks
{
    private Fp12 _baseValue;
    private BigInteger _hardExponent;
    private BigInteger _mediumExponent;

    [Params(3, 4, 5)]
    public int WindowSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _baseValue = new Fp12(
            new Fp6(
                new Fp2(new Fp(2), new Fp(3)),
                new Fp2(new Fp(5), new Fp(7)),
                new Fp2(new Fp(11), new Fp(13))),
            new Fp6(
                new Fp2(new Fp(17), new Fp(19)),
                new Fp2(new Fp(23), new Fp(29)),
                new Fp2(new Fp(31), new Fp(37))));

        _hardExponent = Bls12381Constants.FinalExponentHard;
        _mediumExponent = new BigInteger(123456789);
    }

    [Benchmark(Baseline = true)]
    public Fp12 Pow_Medium()
        => _baseValue.Pow(_mediumExponent);

    [Benchmark]
    public Fp12 PowWindowed_Medium()
        => _baseValue.PowWindowed(_mediumExponent, WindowSize);

    [Benchmark]
    public Fp12 Pow_HardPart()
        => _baseValue.Pow(_hardExponent);

    [Benchmark]
    public Fp12 PowWindowed_HardPart()
        => _baseValue.PowWindowed(_hardExponent, WindowSize);

    [Benchmark]
    public Fp12 PowCyclotomicWindowed_HardPart()
        => _baseValue.PowCyclotomicWindowed(_hardExponent, WindowSize);

    [Benchmark]
    public Fp12 ExpByBlsX()
        => _baseValue.ExpByBlsX();
}
