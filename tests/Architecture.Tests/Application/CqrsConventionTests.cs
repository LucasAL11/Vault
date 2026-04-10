using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using NetArchTest.Rules;
using Shouldly;
using Xunit;

namespace Architecture.Tests.Application;

/// <summary>
/// Validates CQRS conventions in the Application layer:
/// - Every ICommand must have a corresponding ICommandHandler
/// - Every IQuery must have a corresponding IQueryHandler
/// - Handlers live only in the Application layer
/// </summary>
public class CqrsConventionTests : BaseTest
{
    [Fact]
    public void Commands_ShouldImplement_ICommand()
    {
        var result = Types.InAssembly(ApplicationAssembly)
            .That()
            .HaveNameEndingWith("Command")
            .And()
            .AreNotAbstract()
            .Should()
            .ImplementInterface(typeof(ICommand<>))
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"Commands without ICommand<>: {string.Join(", ", result.FailingTypeNames ?? [])}");
    }

    [Fact]
    public void CommandHandlers_ShouldImplement_ICommandHandler()
    {
        var result = Types.InAssembly(ApplicationAssembly)
            .That()
            .HaveNameEndingWith("CommandHandler")
            .And()
            .AreNotAbstract()
            .Should()
            .ImplementInterface(typeof(ICommandHandler<,>))
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"CommandHandlers without ICommandHandler<,>: {string.Join(", ", result.FailingTypeNames ?? [])}");
    }

    [Fact]
    public void Queries_ShouldImplement_IQuery()
    {
        var result = Types.InAssembly(ApplicationAssembly)
            .That()
            .HaveNameEndingWith("Query")
            .And()
            .AreNotAbstract()
            .Should()
            .ImplementInterface(typeof(IQuery<>))
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"Queries without IQuery<>: {string.Join(", ", result.FailingTypeNames ?? [])}");
    }

    [Fact]
    public void QueryHandlers_ShouldImplement_IQueryHandler()
    {
        var result = Types.InAssembly(ApplicationAssembly)
            .That()
            .HaveNameEndingWith("QueryHandler")
            .And()
            .AreNotAbstract()
            .Should()
            .ImplementInterface(typeof(IQueryHandler<,>))
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"QueryHandlers without IQueryHandler<,>: {string.Join(", ", result.FailingTypeNames ?? [])}");
    }

    [Fact]
    public void CommandHandlers_ShouldNotBePublic()
    {
        // Handlers are implementation details — they should be internal
        var result = Types.InAssembly(ApplicationAssembly)
            .That()
            .HaveNameEndingWith("CommandHandler")
            .Should()
            .NotBePublic()
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"Public handlers (should be internal): {string.Join(", ", result.FailingTypeNames ?? [])}");
    }

    [Fact]
    public void QueryHandlers_ShouldNotBePublic()
    {
        var result = Types.InAssembly(ApplicationAssembly)
            .That()
            .HaveNameEndingWith("QueryHandler")
            .Should()
            .NotBePublic()
            .GetResult();

        result.IsSuccessful.ShouldBeTrue(
            $"Public handlers (should be internal): {string.Join(", ", result.FailingTypeNames ?? [])}");
    }
}
