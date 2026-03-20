using System.Numerics;
using Application.Abstractions.Cryptography;
using Application.Cryptography.Constraints;
using Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Infrastructure.Tests;

public sealed class R1csSatisfiabilityValidatorTests
{
    [Fact]
    public void Validate_ShouldReturnSatisfied_WhenWitnessSatisfiesConstraints()
    {
        using var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IR1csSatisfiabilityValidator>();

        var (constraints, wires) = ExampleR1csFactory.Build("a", "b", "x", "y");
        var p = R1csBuilder.Bls12_381ScalarFieldPrime;

        var values = BuildBaseSatisfiedValues(p);
        var witness = BuildWitness(wires, values, p);

        var result = validator.Validate(constraints, witness, p);

        Assert.True(result.IsSatisfied);
        Assert.Null(result.Failure);
    }

    [Fact]
    public void Validate_ShouldReturnUnsatisfied_WhenConstraintIsBroken()
    {
        using var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IR1csSatisfiabilityValidator>();

        var (constraints, wires) = ExampleR1csFactory.Build("a", "b", "x", "y");
        var p = R1csBuilder.Bls12_381ScalarFieldPrime;

        var values = BuildBaseSatisfiedValues(p);
        values["z"] = 0; // quebra propositalmente a ultima seletora de saida
        var witness = BuildWitness(wires, values, p);

        var result = validator.Validate(constraints, witness, p);

        Assert.False(result.IsSatisfied);
        Assert.NotNull(result.Failure);
        Assert.Null(result.Failure!.MissingWitnessIndex);
        Assert.False(result.Failure.Residual.IsZero);
    }

    [Fact]
    public void Validate_ShouldReturnUnsatisfied_WhenWitnessIsMissingWire()
    {
        using var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IR1csSatisfiabilityValidator>();

        var (constraints, wires) = ExampleR1csFactory.Build("a", "b", "x", "y");
        var p = R1csBuilder.Bls12_381ScalarFieldPrime;

        var values = BuildBaseSatisfiedValues(p);
        var witness = BuildWitness(wires, values, p);

        var zId = wires["z"];
        witness.Remove(zId);

        var result = validator.Validate(constraints, witness, p);

        Assert.False(result.IsSatisfied);
        Assert.NotNull(result.Failure);
        Assert.Equal(zId, result.Failure!.MissingWitnessIndex);
    }

    private static Dictionary<string, BigInteger> BuildBaseSatisfiedValues(BigInteger p)
    {
        var values = new Dictionary<string, BigInteger>
        {
            ["a"] = 10,
            ["b"] = 3,
            ["x"] = 8,
            ["y"] = 2,
            ["u"] = 0,
            ["t1"] = 7,
            ["scaledBorrow"] = 0,
            ["d"] = 7,
            ["negU"] = 0,
            ["s"] = 1,
            ["inv_b"] = ModInverse(3, p),
            ["sum_xy"] = 10,
            ["diff_xy"] = 6
        };

        values["div_branch"] = Mod(values["sum_xy"] * values["inv_b"], p);
        values["z"] = values["div_branch"];
        return values;
    }

    private static Dictionary<int, BigInteger> BuildWitness(
        IReadOnlyDictionary<string, int> wires,
        IReadOnlyDictionary<string, BigInteger> values,
        BigInteger p)
    {
        var witness = new Dictionary<int, BigInteger>
        {
            [R1csBuilder.ConstantWireId] = 1
        };

        foreach (var (name, id) in wires)
        {
            if (id == R1csBuilder.ConstantWireId)
            {
                continue;
            }

            if (!values.TryGetValue(name, out var value))
            {
                throw new InvalidOperationException($"Missing witness value for wire '{name}'.");
            }

            witness[id] = Mod(value, p);
        }

        return witness;
    }

    private static BigInteger Mod(BigInteger value, BigInteger p)
    {
        var normalized = value % p;
        if (normalized.Sign < 0)
        {
            normalized += p;
        }

        return normalized;
    }

    private static BigInteger ModInverse(BigInteger value, BigInteger p)
    {
        if (value.IsZero)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Zero has no inverse in the field.");
        }

        return BigInteger.ModPow(Mod(value, p), p - 2, p);
    }

    private static ServiceProvider BuildServiceProvider()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Database"] = "Host=localhost;Port=5432;Database=test;Username=test;Password=test",
                ["Jwt:Issuer"] = "test-issuer",
                ["Jwt:Audience"] = "test-audience",
                ["Jwt:Secret"] = "01234567890123456789012345678901",
                ["ZkBackend:LocalHmacKey"] = "test-zk-key-with-16chars"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddInfrastructure(config);
        return services.BuildServiceProvider();
    }
}
