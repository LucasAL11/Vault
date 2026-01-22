using Application.Abstractions.Messaging.Message;

namespace Application.Computers;

public sealed record RegisterComputerCommand(
    string Name,
    string CpuId,
    string BiosSerialNumber,
    string DiskSerialNumber,
    string OperatingSystem,
    string MachineGuid
) : ICommand<string>;
