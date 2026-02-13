namespace Domain.KillSwitch;

public class KillSwitch
{
    public bool IsEnabled { get; init; }
    
    public string AllowedGroup  { get; set; }
    
    public KillSwitch()
    {
        IsEnabled = true;
    }
}