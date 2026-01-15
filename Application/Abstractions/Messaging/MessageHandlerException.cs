namespace Application.Abstractions.Messaging;

public class MessageHandlerException : Exception
{
    public MessageHandlerException(string message) : base(message)
    {
        throw new NotImplementedException();
    }
}