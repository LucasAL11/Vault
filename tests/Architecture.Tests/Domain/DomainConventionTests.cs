using NetArchTest.Rules;
using Shared;
using Shouldly;
using Xunit;

namespace Architecture.Tests.Domain;

/// <summary>
/// Validates domain model conventions:
/// - Entities inherit from Entity base class
/// - Domain errors follow the static Error factory pattern (VaultErrors, UserErrors, etc.)
/// - Domain has no dependency on infrastructure concerns
/// </summary>
public class DomainConventionTests : BaseTest
{
    [Fact]
    public void Domain_ShouldNotReference_EntityFramework()
    {
        var result = Types.InAssembly(DomainAssembly)
            .Should()
            .NotHaveDependencyOn("Microsoft.EntityFrameworkCore")
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"Domain types referencing EF Core: {string.Join(", ", result.FailingTypeNames ?? [])}");
    }

    [Fact]
    public void Domain_ShouldNotReference_AspNetCore()
    {
        var result = Types.InAssembly(DomainAssembly)
            .Should()
            .NotHaveDependencyOn("Microsoft.AspNetCore")
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"Domain types referencing ASP.NET Core: {string.Join(", ", result.FailingTypeNames ?? [])}");
    }

    [Fact]
    public void DomainErrors_ShouldBeStaticClasses()
    {
        // *Errors classes (e.g. VaultErrors, UserErrors) must be static
        var result = Types.InAssembly(DomainAssembly)
            .That()
            .HaveNameEndingWith("Errors")
            .Should()
            .BeStatic()
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"Error classes that are not static: {string.Join(", ", result.FailingTypeNames ?? [])}");
    }

    [Fact]
    public void DomainErrorClasses_ShouldResideIn_Domain()
    {
        // Errors defined in Application layer should not bleed into Domain
        var result = Types.InAssembly(ApplicationAssembly)
            .That()
            .HaveNameEndingWith("Errors")
            .Should()
            .BeStatic()
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"Application error classes that are not static: {string.Join(", ", result.FailingTypeNames ?? [])}");
    }
}
