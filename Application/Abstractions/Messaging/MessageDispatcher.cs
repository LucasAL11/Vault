using System.Collections.Concurrent;
using System.Diagnostics;
using Application.Abstractions.Messaging.Handlers;
using Application.Abstractions.Messaging.Message;
using Application.Observability;
using Microsoft.Extensions.DependencyInjection;
using Shared;

namespace Application.Abstractions.Messaging;

public class MessageDispatcher : IMessageDispatcher
{
    private readonly ConcurrentDictionary<Type, Func<object, CancellationToken, Task<Result>>> _handlers;
    private readonly ConcurrentDictionary<Type, Func<object, CancellationToken, Task<Result>>> _handlersWithResponse;
    private readonly IServiceProvider _serviceProvider;
    private readonly ConcurrentDictionary<Type, Func<object, CancellationToken, Task>> _eventDispatchers = new();
    private readonly MessageTelemetry _telemetry;

    public MessageDispatcher(IServiceProvider serviceProvider, MessageTelemetry telemetry)
    {
        _serviceProvider = serviceProvider;
        _telemetry = telemetry;
        _handlers = new ConcurrentDictionary<Type, Func<object, CancellationToken, Task<Result>>>();
        _handlersWithResponse = new ConcurrentDictionary<Type, Func<object, CancellationToken, Task<Result>>>();
    }

    public void RegisterHandler<TMessage>(Func<TMessage, Task<Result>> handler)
        where TMessage : IMessage
    {
        _handlers.TryAdd(typeof(TMessage), (message, _) => handler((TMessage)message));
    }

    public void RegisterHandler<TMessage, TResponse>(Func<TMessage, Task<Result<TResponse>>> handler)
        where TMessage : IMessage<TResponse>
    {
        _handlersWithResponse.TryAdd(
            typeof(TMessage),
            async (message, _) => await handler((TMessage)message));
    }

    public async Task<Result<TResponse>> Send<TResponse>(
        IMessage<TResponse> message,
        CancellationToken cancellationToken = default)
    {
        var messageType = message.GetType();
        var messageName = messageType.Name;
        var messageKind = message is IQuery<TResponse> ? "query" : "command";

        var handler = _handlersWithResponse.GetOrAdd(messageType, _ =>
        {
            Type handlerType = message is IQuery<TResponse>
                ? typeof(IQueryHandler<,>).MakeGenericType(messageType, typeof(TResponse))
                : typeof(ICommandHandler<,>).MakeGenericType(messageType, typeof(TResponse));

            var handlerInstance = _serviceProvider.GetRequiredService(handlerType);
            var handleMethod = handlerType.GetMethod("Handle")
                               ?? throw new InvalidOperationException($"Handle method not found on {handlerType.Name}");

            return async (obj, ct) => await (Task<Result<TResponse>>)handleMethod.Invoke(handlerInstance, [obj, ct])!;
        });

        using var activity = _telemetry.StartHandlerActivity(messageKind, messageName);
        var startedAt = Stopwatch.GetTimestamp();

        try
        {
            var result = await handler(message, cancellationToken);
            var typedResult = (Result<TResponse>)result;

            _telemetry.TrackResult(
                messageKind,
                messageName,
                typedResult.IsSuccess,
                typedResult.IsFailure ? typedResult.Error.Code : null,
                Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds);

            if (typedResult.IsFailure)
            {
                activity?.SetStatus(ActivityStatusCode.Error, typedResult.Error.Code);
            }

            return typedResult;
        }
        catch (Exception ex)
        {
            _telemetry.TrackException(
                messageKind,
                messageName,
                ex.GetType().Name,
                Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds);
            activity?.SetStatus(ActivityStatusCode.Error, ex.GetType().Name);
            throw;
        }
    }

    public async Task<Result> Send(IMessage message, CancellationToken cancellationToken = default)
    {
        var messageType = message.GetType();
        var messageName = messageType.Name;
        const string messageKind = "command";

        var handler = _handlers.GetOrAdd(messageType, _ =>
        {
            var handlerType = typeof(ICommandHandler<>).MakeGenericType(messageType);
            var handlerInstance = _serviceProvider.GetRequiredService(handlerType);
            var handleMethod = handlerType.GetMethod("Handle")
                               ?? throw new InvalidOperationException($"Handle method not found on {handlerType.Name}");

            return async (obj, ct) => await (Task<Result>)handleMethod.Invoke(handlerInstance, [obj, ct])!;
        });

        using var activity = _telemetry.StartHandlerActivity(messageKind, messageName);
        var startedAt = Stopwatch.GetTimestamp();

        try
        {
            var result = await handler(message, cancellationToken);

            _telemetry.TrackResult(
                messageKind,
                messageName,
                result.IsSuccess,
                result.IsFailure ? result.Error.Code : null,
                Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds);

            if (result.IsFailure)
            {
                activity?.SetStatus(ActivityStatusCode.Error, result.Error.Code);
            }

            return result;
        }
        catch (Exception ex)
        {
            _telemetry.TrackException(
                messageKind,
                messageName,
                ex.GetType().Name,
                Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds);
            activity?.SetStatus(ActivityStatusCode.Error, ex.GetType().Name);
            throw;
        }
    }

    public async Task Publish(
        IDomainEvent domainEvent,
        CancellationToken cancellationToken = default)
    {
        var eventType = domainEvent.GetType();
        var messageName = eventType.Name;
        const string messageKind = "domain_event";

        var dispatcher = _eventDispatchers.GetOrAdd(eventType, type =>
        {
            var handlersType = typeof(INotificationHandler<>).MakeGenericType(type);
            var handleMethod = handlersType.GetMethod("Handle")
                               ?? throw new InvalidOperationException($"Handle method not found on {handlersType.Name}");

            return async (evt, ct) =>
            {
                var handlers = _serviceProvider.GetServices(handlersType);

                foreach (var handler in handlers)
                {
                    await (Task)handleMethod.Invoke(handler, [evt, ct])!;
                }
            };
        });

        using var activity = _telemetry.StartHandlerActivity(messageKind, messageName);
        var startedAt = Stopwatch.GetTimestamp();

        try
        {
            await dispatcher(domainEvent, cancellationToken);
            _telemetry.TrackResult(
                messageKind,
                messageName,
                success: true,
                errorCode: null,
                Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds);
        }
        catch (Exception ex)
        {
            _telemetry.TrackException(
                messageKind,
                messageName,
                ex.GetType().Name,
                Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds);
            activity?.SetStatus(ActivityStatusCode.Error, ex.GetType().Name);
            throw;
        }
    }
}
