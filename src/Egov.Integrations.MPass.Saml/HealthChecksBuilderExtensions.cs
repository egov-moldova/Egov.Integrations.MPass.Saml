using Egov.Integrations.MPass.Saml;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for <see cref="IHealthChecksBuilder"/>.
/// </summary>
public static class HealthChecksBuilderExtensions
{
    /// <summary>
    /// Adds a new health check for client authentication. In particular it checks for IdP and system certificates validity.
    /// </summary>
    /// <param name="builder">An instance of <see cref="IHealthChecksBuilder"/> to add the health check to.</param>
    /// <param name="failureStatus">The <see cref="HealthStatus"/> that should be reported when the health check reports a failure, or <see cref="HealthStatus.Unhealthy"/> if null.</param>
    /// <param name="tags">A list of tags that can be used to filter health checks.</param>
    /// <returns>The <see cref="IHealthChecksBuilder"/> so that additional calls can be chained.</returns>
    public static IHealthChecksBuilder AddMPassSamlHealthCheck(this IHealthChecksBuilder builder, HealthStatus? failureStatus = default, IEnumerable<string>? tags = null)
    {
        return builder.AddMPassSamlHealthCheck(MPassSamlDefaults.AuthenticationScheme, failureStatus, tags);
    }

    /// <summary>
    /// Adds a new health check for client authentication. In particular it checks for IdP and system certificates validity.
    /// </summary>
    /// <param name="builder">An instance of <see cref="IHealthChecksBuilder"/> to add the health check to.</param>
    /// <param name="name">The name of the health check.</param>
    /// <param name="failureStatus">The <see cref="HealthStatus"/> that should be reported when the health check reports a failure, or <see cref="HealthStatus.Unhealthy"/> if null.</param>
    /// <param name="tags">A list of tags that can be used to filter health checks.</param>
    /// <returns>The <see cref="IHealthChecksBuilder"/> so that additional calls can be chained.</returns>
    public static IHealthChecksBuilder AddMPassSamlHealthCheck(this IHealthChecksBuilder builder, string name, HealthStatus? failureStatus = default, IEnumerable<string>? tags = null)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Please provide a configuration name, such as MPassSamlDefaults.AuthenticationScheme", nameof(name));
        }

        builder.Services.TryAddSingleton<MPassSamlHealthCheck>();
        return builder.AddCheck<MPassSamlHealthCheck>(name, failureStatus, tags, null);
    }
}
