using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace Egov.Integrations.MPass.Saml;

/// <summary>
/// Options for MPass SAML endpoints.
/// </summary>
public class MPassSamlEndpointsOptions
{
    /// <summary>
    /// The default returnUrl parameter for /login and /logout endpoints. By default, this is set to "/".
    /// </summary>
    public string DefaultReturnUrl { get; set; } = "/";

    /// <summary>
    /// Authentication scheme used for remote authentication.
    /// </summary>
    public string RemoteAuthenticationScheme { get; set; } = MPassSamlDefaults.AuthenticationScheme;

    /// <summary>
    /// Authentication scheme used for local authentication.
    /// </summary>
    public string LocalAuthenticationScheme { get; set; } = CookieAuthenticationDefaults.AuthenticationScheme;

    /// <summary>
    /// A delegate assigned to this property will be invoked to build an instance of <see cref="AuthenticationProperties"/> in /login endpoint.
    /// </summary>
    public Func<HttpContext, MPassSamlAuthenticationProperties> AuthenticationPropertiesFactory { get; set; } = context => new MPassSamlAuthenticationProperties();
}
