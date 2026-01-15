namespace Application.Abstractions.Messaging.Handlers;

public interface INotificationHandler<in TNotification> where TNotification : Shared.INotification
{
    Task Handle(TNotification notification, CancellationToken cancellationToken = default);
}