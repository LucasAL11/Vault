using Api.Endpoints;
using NetArchTest.Rules;
using Shouldly;
using Xunit;

namespace Architecture.Tests.Api;

/// <summary>
/// Validates endpoint conventions in the Api layer:
/// - All endpoints implement IEndpoint
/// - Endpoints are sealed (not meant to be subclassed)
/// - No domain entities are exposed directly from endpoints
/// </summary>
public class EndpointConventionTests : BaseTest
{
    [Fact]
    public void AllEndpoints_ShouldImplement_IEndpoint()
    {
        var result = Types.InAssembly(ApiAssembly)
            .That()
            .HaveNameEndingWith("Endpoint")
            .And()
            .AreNotAbstract()
            .Should()
            .ImplementInterface(typeof(IEndpoint))
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"Endpoints not implementing IEndpoint: {string.Join(", ", result.FailingTypeNames ?? [])}");
    }

    [Fact]
    public void Endpoints_ShouldBeSealed()
    {
        var result = Types.InAssembly(ApiAssembly)
            .That()
            .ImplementInterface(typeof(IEndpoint))
            .Should()
            .BeSealed()
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"Non-sealed endpoints: {string.Join(", ", result.FailingTypeNames ?? [])}");
    }

    [Fact]
    public void Api_ShouldNotDependOn_DomainEntities_Directly()
    {
        // Api should use DTOs/response records, not expose domain entities
        var result = Types.InAssembly(ApiAssembly)
            .That()
            .HaveNameEndingWith("Endpoint")
            .Should()
            .NotHaveDependencyOn("Domain.vault.Secret")
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"Endpoints exposing domain entities: {string.Join(", ", result.FailingTypeNames ?? [])}");
    }
}
