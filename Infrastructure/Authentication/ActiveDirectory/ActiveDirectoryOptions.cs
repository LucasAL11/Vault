namespace Infrastructure.Authentication.ActiveDirectory;

public sealed class ActiveDirectoryOptions
{
    public bool Enabled { get; set; } = true;
    public string? Domain { get; set; }
    public string? Container { get; set; }
}
