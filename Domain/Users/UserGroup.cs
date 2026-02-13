namespace Domain.Users;

public record UserGroup(string Name)
{
    public static readonly UserGroup Administrators = new("Admins");
    public static readonly UserGroup IT = new("TI");
};