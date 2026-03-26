using Application.Abstractions.Messaging.Message;

namespace Application.User.Register;

public record RegisterUserCommand(
    string Username,
    string Password,
    string FirstName,
    string LastName) : ICommand<int>;
