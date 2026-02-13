using Application.Abstractions.Messaging.Message;

namespace Application.User;

public record ValidateUserCommand(
    string Username, string Password)
    : ICommand<string>;