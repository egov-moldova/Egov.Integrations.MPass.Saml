using Microsoft.AspNetCore.Authentication;

namespace Egov.Integrations.MPass.Saml;

/// <summary>
/// Base events class that allows the application to override needed methods.
/// </summary>
public class MPassSamlEvents : RemoteAuthenticationEvents
{
    /// <summary>
    /// A delegate assigned to this property will be invoked before remote authentication sign-out.
    /// </summary>
    public Func<RemoteSignOutContext, Task> OnRemoteSignOut { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// A delegate assigned to this property will be invoked after remote authentication sign-out.
    /// </summary>
    public Func<RemoteSignOutContext, Task> OnSignedOutCallbackRedirect { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Invoked before remote authentication sign-out.
    /// </summary>
    /// <param name="context">State for remote sign-out context.</param>
    public virtual Task RemoteSignOut(RemoteSignOutContext context) => OnRemoteSignOut(context);

    /// <summary>
    /// Invoked after remote authentication sign-out
    /// </summary>
    /// <param name="context">State for remote sign-out context.</param>
    public virtual Task SignedOutCallbackRedirect(RemoteSignOutContext context) => OnSignedOutCallbackRedirect(context);
}
