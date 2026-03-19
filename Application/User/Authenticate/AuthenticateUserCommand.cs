using Application.Abstractions.Messaging.Message;

namespace Application.User.Authenticate;

public record AuthenticateUserCommand(
    string Username, string Domain)
    : ICommand<string>;