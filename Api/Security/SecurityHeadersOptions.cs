namespace Api.Security;

public sealed class SecurityHeadersOptions
{
    public string XFrameOptions { get; set; } = "DENY";
    public string ContentSecurityPolicy { get; set; } =
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    public string ReferrerPolicy { get; set; } = "no-referrer";
    public string PermissionsPolicy { get; set; } =
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";
    public string CrossOriginOpenerPolicy { get; set; } = "same-origin";
    public string CrossOriginResourcePolicy { get; set; } = "same-origin";
    public string XPermittedCrossDomainPolicies { get; set; } = "none";
}
