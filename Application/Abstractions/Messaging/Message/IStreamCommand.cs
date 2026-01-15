namespace Application.Abstractions.Messaging.Message;

public interface IBaseStreamCommand : IStreamMessage;

public interface IStreamCommand<out TResponse> : IBaseStreamCommand;
