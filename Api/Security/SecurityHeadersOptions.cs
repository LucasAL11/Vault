namespace Api.Security;

public sealed class SecurityHeadersOptions
{
    public string ContentSecurityPolicy { get; set; } =
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    public string ReferrerPolicy { get; set; } = "no-referrer";
    public string PermissionsPolicy { get; set; } =
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";
}