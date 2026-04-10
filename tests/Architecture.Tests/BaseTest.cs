using System.Reflection;
using Api.Endpoints;
using Application.Abstractions.Messaging.Handlers;
using Domain.vault;
using Infrastructure;
using Shared;

namespace Architecture.Tests;

public abstract class BaseTest
{
    // Anchor types — one per assembly to get the correct Assembly reference
    protected static readonly Assembly DomainAssembly       = typeof(Secret).Assembly;
    protected static readonly Assembly ApplicationAssembly  = typeof(ICommandHandler<,>).Assembly;
    protected static readonly Assembly InfrastructureAssembly = typeof(DependencyInjection).Assembly;
    protected static readonly Assembly ApiAssembly          = typeof(IEndpoint).Assembly;
    protected static readonly Assembly SharedAssembly       = typeof(Error).Assembly;
}
