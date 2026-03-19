using System.Numerics;
using Application.Cryptography.Constraints;
using Xunit;

namespace Infrastructure.Tests;

public sealed class R1csBuilderModPTests
{
    [Fact]
    public void AddConst_ShouldNormalizeConstantCoefficient_ModP()
    {
        var builder = new R1csBuilder(modulus: 7);
        builder.AddConst("r", "x", 9);

        var constraint = Assert.Single(builder.Constraints);
        var oneId = R1csBuilder.ConstantWireId;
        Assert.Equal(new BigInteger(2), constraint.A.Terms[oneId]);
    }

    [Fact]
    public void SubFn_ShouldEncodeNegativeCoefficient_ModP()
    {
        var builder = new R1csBuilder(modulus: 7);
        builder.SubFn("r", "x", "y");

        var constraint = Assert.Single(builder.Constraints);
        var yId = builder.IdOf("y");
        Assert.Equal(new BigInteger(6), constraint.A.Terms[yId]);
    }

    [Fact]
    public void Mod_ShouldNormalizeNegativeValues()
    {
        var builder = new R1csBuilder(modulus: 7);
        Assert.Equal(new BigInteger(4), builder.Mod(-3));
    }
}
