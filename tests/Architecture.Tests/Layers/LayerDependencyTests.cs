using NetArchTest.Rules;
using Shouldly;
using Xunit;

namespace Architecture.Tests.Layers;

/// <summary>
/// Validates that architectural layer boundaries are respected.
///
/// Dependency rule (Clean Architecture):
///   Domain ← Application ← Infrastructure ← Api
///                 ↑
///              Shared (can be referenced by all)
///
/// Inner layers must never reference outer layers.
/// </summary>
public class LayerDependencyTests : BaseTest
{
    // ──────────────────────────────── Domain ────────────────────────────────

    [Fact]
    public void Domain_ShouldNotDependOn_Application()
    {
        Types.InAssembly(DomainAssembly)
            .Should()
            .NotHaveDependencyOn(ApplicationAssembly.GetName().Name)
            .GetResult()
            .IsSuccessful
            .ShouldBeTrue();
    }

    [Fact]
    public void Domain_ShouldNotDependOn_Infrastructure()
    {
        Types.InAssembly(DomainAssembly)
            .Should()
            .NotHaveDependencyOn(InfrastructureAssembly.GetName().Name)
            .GetResult()
            .IsSuccessful
            .ShouldBeTrue();
    }

    [Fact]
    public void Domain_ShouldNotDependOn_Api()
    {
        Types.InAssembly(DomainAssembly)
            .Should()
            .NotHaveDependencyOn(ApiAssembly.GetName().Name)
            .GetResult()
            .IsSuccessful
            .ShouldBeTrue();
    }

    // ─────────────────────────────── Application ────────────────────────────

    [Fact]
    public void Application_ShouldNotDependOn_Infrastructure()
    {
        Types.InAssembly(ApplicationAssembly)
            .Should()
            .NotHaveDependencyOn(InfrastructureAssembly.GetName().Name)
            .GetResult()
            .IsSuccessful
            .ShouldBeTrue();
    }

    [Fact]
    public void Application_ShouldNotDependOn_Api()
    {
        Types.InAssembly(ApplicationAssembly)
            .Should()
            .NotHaveDependencyOn(ApiAssembly.GetName().Name)
            .GetResult()
            .IsSuccessful
            .ShouldBeTrue();
    }

    // ─────────────────────────────── Infrastructure ─────────────────────────

    [Fact]
    public void Infrastructure_ShouldNotDependOn_Api()
    {
        Types.InAssembly(InfrastructureAssembly)
            .Should()
            .NotHaveDependencyOn(ApiAssembly.GetName().Name)
            .GetResult()
            .IsSuccessful
            .ShouldBeTrue();
    }
}
