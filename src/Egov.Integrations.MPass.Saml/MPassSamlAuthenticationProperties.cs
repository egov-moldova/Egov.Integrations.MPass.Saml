using Microsoft.AspNetCore.Authentication;

namespace Egov.Integrations.MPass.Saml;

/// <summary>
/// Represents additional MPass SAML authentication properties.
/// </summary>
public class MPassSamlAuthenticationProperties : AuthenticationProperties
{
    internal const string AuthnRequestIDKey = "authnRequestID";
    internal const string LogoutRequestIDKey = "logoutRequestID";
    internal const string FailedRedirectUriKey = "failedUri";
    private const string ForceAuthnKey = "force";
    private const string IsPassiveKey = "passive";
    internal const string LanguageKey = "lang";

    /// <summary>
    /// Uri to redirect to when authentication failed, including on passive request.
    /// </summary>
    public string? FailedRedirectUri
    {
        get => GetString(FailedRedirectUriKey);
        set => SetString(FailedRedirectUriKey, value);
    }

    /// <summary>
    /// Force authentication, even if user is already authenticated.
    /// </summary>
    public bool? ForceAuthn
    {
        get => GetBool(ForceAuthnKey);
        set => SetBool(ForceAuthnKey, value);
    }

    /// <summary>
    /// Use passive SAML authentication.
    /// </summary>
    public bool? IsPassive
    {
        get => GetBool(IsPassiveKey);
        set => SetBool(IsPassiveKey, value);
    }

    /// <summary>
    /// Indicates language to be used by MPass. Currently valid values are: ro, ru, en.
    /// </summary>
    public string? Language
    {
        get => GetString(LanguageKey);
        set => SetString(LanguageKey, value);
    }
}
