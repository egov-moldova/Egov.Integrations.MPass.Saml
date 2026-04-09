using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Egov.Integrations.MPass.Saml;

/// <summary>
/// State for remote sign-out context.
/// </summary>
public class RemoteSignOutContext : RemoteAuthenticationContext<MPassSamlOptions>
{
    /// <summary>
    /// Creates a new instance of <see cref="RemoteSignOutContext"/>.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> this context applies to.</param>
    /// <param name="scheme">The scheme used when the client authentication handler was registered.</param>
    /// <param name="options">Used <see cref="MPassSamlOptions"/>.</param>
    public RemoteSignOutContext(
        HttpContext context,
        AuthenticationScheme scheme,
        MPassSamlOptions options)
        : base(context, scheme, options, new AuthenticationProperties())
    {
    }
}
