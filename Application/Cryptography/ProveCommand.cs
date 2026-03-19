using Application.Abstractions.Messaging.Message;
using Application.Contracts.Zk;

namespace Application.Cryptography;

public sealed record ProveCommand(PreimageRequest Request) : ICommand<string>;