using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Egov.Integrations.MPass.Saml;

/// <summary>
/// Default values related to MPass authentication handler
/// </summary>
public static class MPassSamlDefaults
{
    /// <summary>
    /// The default value used for authenticationScheme parameter.
    /// </summary>
    public const string AuthenticationScheme = "MPassSaml";

    /// <summary>
    /// The default value for the display name.
    /// </summary>
    public static readonly string DisplayName = "MPass";

    /// <summary>
    /// The default value for SAML Request.
    /// </summary>
    public static readonly string SAMLRequest = "SAMLRequest";

    /// <summary>
    /// The default value for SAML Response.
    /// </summary>
    public static readonly string SAMLResponse = "SAMLResponse";

    /// <summary>
    /// The default value for Session Index.
    /// </summary>
    public static readonly string SessionIndex = "SessionIndex";

    /// <summary>
    /// The default value for Relay State.
    /// </summary>
    public static readonly string RelayState = "RelayState";

    /// <summary>
    /// The default value used for <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
    /// </summary>
    public static readonly PathString CallbackPath = "/mpass-login";

    /// <summary>
    /// The default value used for <see cref="MPassSamlOptions.LogoutRequestPath"/>.
    /// </summary>
    public static readonly PathString LogoutRequestPath = "/mpass-slo";

    /// <summary>
    /// The default value used for <see cref="MPassSamlOptions.LogoutResponsePath"/>.
    /// </summary>
    public static readonly PathString LogoutResponsePath = "/mpass-logout";

    /// <summary>
    /// The default value used for <see cref="MPassSamlOptions.SamlMessageTimeout"/>.
    /// </summary>
    public static readonly TimeSpan SamlMessageTimeout = TimeSpan.FromMinutes(10d);

    /// <summary>
    /// The default path prefix used for account related endpoints.
    /// </summary>
    public static readonly string EndpointPath = "account";
}
