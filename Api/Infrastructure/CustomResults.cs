using Shared;

namespace Api.Infrastructure;

public static class CustomResults
{
    public static IResult Problem(Result result)
    {
        if (result.IsSuccess)
        {
            throw new InvalidOperationException("Problem occured");
        }
        
        return Results.Problem(
            title: GetTitle(result.Error), 
            detail: GetDetail(result.Error), 
            type: GetType(result.Error.Type), 
            statusCode: GetStatusCode(result.Error.Type), 
            extensions: GetErrors(result));
        
        static string GetTitle(Error resultError) =>
            resultError.Type switch
            {
                ErrorType.Validation => resultError.Code,
                ErrorType.Problem => resultError.Code,
                ErrorType.NotFound => resultError.Code,
                ErrorType.Conflict => resultError.Code,
                ErrorType.Unauthorized => resultError.Code,
                ErrorType.Forbidden => resultError.Code,
                ErrorType.BadRequest => resultError.Code,
                _ => "Server failure"
            };
        
        static string GetDetail(Error resultError) =>
            resultError.Type switch
            {
                ErrorType.Validation => resultError.Description,
                ErrorType.Problem => resultError.Description,
                ErrorType.NotFound => resultError.Description,
                ErrorType.Conflict => resultError.Description,
                ErrorType.Unauthorized => resultError.Description,
                ErrorType.Forbidden => resultError.Description,
                ErrorType.BadRequest => resultError.Description,
                _ => "An unexpected error occurred"
            };
        
        static string GetType(ErrorType errorType) =>
            errorType switch
            {
                ErrorType.Validation => "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                ErrorType.Problem => "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                ErrorType.NotFound => "https://tools.ietf.org/html/rfc7231#section-6.5.4",
                ErrorType.Conflict => "https://tools.ietf.org/html/rfc7231#section-6.5.8",
                ErrorType.Unauthorized => "https://tools.ietf.org/html/rfc7231#section-6.5.4",
                ErrorType.Forbidden => "https://tools.ietf.org/html/rfc7231#section-6.5.3",
                ErrorType.BadRequest => "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                _ => "https://tools.ietf.org/html/rfc7231#section-6.6.1"
            };
        
        static int GetStatusCode(ErrorType errorType) =>
            errorType switch
            {
                ErrorType.Validation => StatusCodes.Status400BadRequest,
                ErrorType.NotFound => StatusCodes.Status404NotFound,
                ErrorType.Conflict => StatusCodes.Status409Conflict,
                ErrorType.Unauthorized => StatusCodes.Status401Unauthorized,
                ErrorType.Forbidden => StatusCodes.Status403Forbidden,
                ErrorType.BadRequest => StatusCodes.Status400BadRequest,
                _ => StatusCodes.Status500InternalServerError
            };
        
        static Dictionary<string, object?>? GetErrors(Result result)
        {
            if (result.Error is not ValidationError validationError)
            {
                return null;
            }

            return new Dictionary<string, object?>
            {
                { "errors", validationError.Errors }
            };
        }
    }
}