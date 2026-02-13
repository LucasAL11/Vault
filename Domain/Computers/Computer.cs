using Shared;

namespace Domain.Computers;

public class Computer : Entity
{
    //construtor vazio para efcore criar tabela
    private Computer(){ }
    
    public Computer(
        string name, 
        CpuId cpuId, 
        Bios biosSerial, 
        Disk disk, 
        InternalOperatingSystem operatingSystem,
        MachineGuid machineGuid,
        IDateTimeProvider dateTimeProvider)
    {
        Name = name;
        CpuId = cpuId;
        Bios = biosSerial;
        Disk = disk;
        OperatingSystem = operatingSystem;
        MachineGuid = machineGuid;
        
        FirstSeen = dateTimeProvider.UtcNow;
        LastSeen = dateTimeProvider.UtcNow;
        IsActive = true;
    }

    public int Id { get; set; }
    public string Name { get; private set; }
    public string Hwid => GenerateHashedHwid();
    public CpuId CpuId { get; private set; }
    public Bios Bios { get; private set; }
    public Disk Disk { get; private set; }
    public InternalOperatingSystem OperatingSystem { get; private set; }
    public MachineGuid MachineGuid { get; private set; }
    public DateTime FirstSeen { get; private set; }
    public DateTime LastSeen { get; private set; }
    public bool IsActive { get; private set; }

    public void Deactivate()
    {
        IsActive = false;
    }

    public void Activate()
    {
        IsActive = true;
    }
    
    public string GenerateHashedHwid()
    {
        var raw = $"{Name}:{CpuId.Value}:{Bios.Serial}:{Disk.Serial}:{OperatingSystem}:{MachineGuid}";
        return Hash(raw);
    }
    
    public void Touch(IDateTimeProvider dateTimeProvider)
    {
        LastSeen = dateTimeProvider.UtcNow;
    }

    private string Hash(string raw)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(raw);
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }
}
