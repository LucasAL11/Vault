namespace Application.Abstractions.Messaging.Message;

public interface ICommand : IMessage;

public interface ICommand<TResponse> : IMessage<TResponse>;