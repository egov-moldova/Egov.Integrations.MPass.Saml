using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Egov.Integrations.MPass.Saml;
using Microsoft.Extensions.Configuration;
using Egov.Extensions.Configuration;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for <see cref="AuthenticationBuilder"/>.
/// </summary>
public static class AuthenticationBuilderExtensions
{
    /// <summary>
    /// Adds MPass SAML-based user authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddMPassSaml(this AuthenticationBuilder builder)
        => builder.AddMPassSaml(MPassSamlDefaults.AuthenticationScheme, _ => { });

    /// <summary>
    /// Adds MPass SAML-based user authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="config">The configuration being bound to.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddMPassSaml(this AuthenticationBuilder builder, IConfiguration config)
        => builder.AddMPassSaml(MPassSamlDefaults.AuthenticationScheme, config);

    /// <summary>
    /// Adds MPass SAML-based user authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="MPassSamlOptions"/>.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddMPassSaml(this AuthenticationBuilder builder, Action<MPassSamlOptions> configureOptions)
        => builder.AddMPassSaml(MPassSamlDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Adds MPass SAML-based user authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="config">The configuration being bound to.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="MPassSamlOptions"/>.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddMPassSaml(this AuthenticationBuilder builder, IConfiguration config, Action<MPassSamlOptions> configureOptions)
        => builder.AddMPassSaml(MPassSamlDefaults.AuthenticationScheme, config, configureOptions);

    /// <summary>
    /// Adds MPass SAML-based user authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="config">The configuration being bound to.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddMPassSaml(this AuthenticationBuilder builder, string authenticationScheme, IConfiguration config)
        => builder.AddMPassSaml(authenticationScheme, config, _ => { });

    /// <summary>
    /// Adds MPass SAML-based user authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="MPassSamlOptions"/>.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddMPassSaml(this AuthenticationBuilder builder, string authenticationScheme, Action<MPassSamlOptions> configureOptions)
        => builder.AddMPassSaml(authenticationScheme, MPassSamlDefaults.DisplayName, configureOptions);

    /// <summary>
    /// Adds MPass SAML-based user authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="config">The configuration being bound to.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="MPassSamlOptions"/>.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddMPassSaml(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        IConfiguration config,
        Action<MPassSamlOptions> configureOptions)
        => builder.AddMPassSaml(authenticationScheme, MPassSamlDefaults.DisplayName, config, configureOptions);

    /// <summary>
    /// Adds MPass SAML-based user authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="displayName">A display name for this scheme.</param>
    /// <param name="config">The configuration being bound to.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddMPassSaml(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        string displayName,
        IConfiguration config)
        => builder.AddMPassSaml(authenticationScheme, displayName, config, _ => { });

    /// <summary>
    /// Adds MPass SAML-based user authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="displayName">A display name for this scheme.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="MPassSamlOptions"/>.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddMPassSaml(
        this AuthenticationBuilder builder, 
        string authenticationScheme, 
        string displayName, 
        Action<MPassSamlOptions> configureOptions)
    {
        builder.Services.AddOptions<MPassSamlOptions>(authenticationScheme)
            .Configure<IOptions<SystemCertificateOptions>>((mpassSamlOptions, systemCertificateOptions) =>
            {
                mpassSamlOptions.SystemCertificate ??= systemCertificateOptions.Value.Certificate;
            });

        builder.Services.TryAddSingleton<IPostConfigureOptions<MPassSamlOptions>, MPassSamlPostConfigureOptions>();

        return builder.AddRemoteScheme<MPassSamlOptions, MPassSamlHandler>(authenticationScheme, displayName, configureOptions);
    }

    /// <summary>
    /// Adds MPass SAML-based user authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="displayName">A display name for this scheme.</param>
    /// <param name="config">The configuration being bound to.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="MPassSamlOptions"/>.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddMPassSaml(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        string displayName,
        IConfiguration config,
        Action<MPassSamlOptions> configureOptions)
    {
        builder.Services.Configure<MPassSamlOptions>(authenticationScheme, config);
        return builder.AddMPassSaml(authenticationScheme, displayName, configureOptions);
    }
}
