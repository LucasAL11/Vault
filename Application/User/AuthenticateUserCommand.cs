using Application.Abstractions.Messaging.Message;

namespace Application.User;

public record AuthenticateUserCommand(
    string Username, string Domain)
    : ICommand<string>;