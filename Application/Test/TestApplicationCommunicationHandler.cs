using Application.Abstractions.Messaging;
using Application.Abstractions.Messaging.Handlers;
using Shared;

namespace Application.Test;

public class TestApplicationCommunicationHandler : ICommandHandler<TestApplicationCommunication, string>
{
    public async Task<Result<string>> Handle(TestApplicationCommunication command,
        CancellationToken cancellationToken = default)
    {
        return "teste";
    }
}