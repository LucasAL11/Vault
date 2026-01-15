namespace Shared;

public record Error
{
    public static readonly Error None = new(string.Empty, string.Empty, ErrorType.Failure);

    public static readonly Error NullValue = new(
        "General.Null",
        "Null value was provide",
        ErrorType.Failure
    );
    
    public Error(string Code, string Description, ErrorType Type)
    {
        this.Code = Code;
        this.Description = Description;
        this.Type = Type;
    }

    public string Code { get; set; }
    public string Description { get; set; }
    public ErrorType Type { get; set; }
    
    public static Error Problem(string code, string description) => 
        new(code, description, ErrorType.Problem);
    
    public static Error NotFound(string code, string description) => 
        new(code, description, ErrorType.NotFound);
    
    public static Error Conflict(string code, string description) =>
        new(code, description, ErrorType.Conflict);
    
    public static Error Failure(string code, string description) =>
        new(code, description, ErrorType.Failure);

    public static Error Forbidden(string code, string description) =>
        new(code, description, ErrorType.Forbidden);

    public static Error BadRequest(string code, string description) => 
        new(code, description, ErrorType.BadRequest);

    public static Error Unauthorized(string code, string description) =>
        new(code, description, ErrorType.Unauthorized);
}