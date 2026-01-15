using Application.Abstractions.Messaging;
using Application.Abstractions.Messaging.Message;

namespace Application.Test;

public record TestApplicationCommunication : ICommand<string>;