using Application.Abstractions.Data;
using Application.Abstractions.Messaging.Handlers;
using Domain.Computers;
using Domain.Computers.Events;
using Shared;

namespace Application.Computers;

public class RegisterComputerCommandHandler(IApplicationDbContext context, IDateTimeProvider dateTimeProvider) 
    : ICommandHandler<RegisterComputerCommand, string>
{
    public async Task<Result<string>> Handle(
        RegisterComputerCommand command,
        CancellationToken cancellationToken = default)
    {
        var biosSerial = Bios.Create(command.BiosSerialNumber);
        var diskSerial = Disk.Create(command.DiskSerialNumber);

        var combined = Result.Combine(biosSerial, diskSerial);

        if (combined.IsFailure)
            return Result.Failure<string>(combined.Error);
        
        var computer = new Computer(
            command.Name,
            new CpuId(command.CpuId),
            biosSerial.Value,
            diskSerial.Value,
            new InternalOperatingSystem(command.OperatingSystem),
            new MachineGuid(command.MachineGuid),
            dateTimeProvider
            );
        
        context.Computers.Add(computer);

        await context.SaveChangesAsync(cancellationToken);
        computer.RaiseEvents(new ComputerRegisteredDomainEvent(computer.Id, computer.Name));

        return "Registro comunicado com sucesso";
    }
}
