using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Egov.Integrations.MPass.Saml;

internal class MPassSamlHealthCheck : IHealthCheck
{
    private readonly IOptionsMonitor<MPassSamlOptions> optionsMonitor;

    public MPassSamlHealthCheck(IOptionsMonitor<MPassSamlOptions> optionsMonitor)
    {
        this.optionsMonitor = optionsMonitor;
    }

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var options = optionsMonitor.Get(context.Registration.Name);

        if (options.IdpCertificate == null)
            return Task.FromResult(HealthCheckResult.Unhealthy("No identity provider certificate specified"));

        if (options.IdpCertificate.NotAfter < DateTime.Now)
            return Task.FromResult(new HealthCheckResult(context.Registration.FailureStatus, "Identity provider certificate is expired"));

        if (options.IdpCertificate.NotAfter < DateTime.Now.AddDays(30))
            return Task.FromResult(HealthCheckResult.Degraded("Identity provider certificate expires in less than 30 days"));

        if (options.SystemCertificate == null)
            return Task.FromResult(HealthCheckResult.Unhealthy("No service certificate specified"));

        if (!options.SystemCertificate.HasPrivateKey)
            return Task.FromResult(HealthCheckResult.Unhealthy("Service certificate does not contain private key"));

        if (options.SystemCertificate.NotAfter < DateTime.Now)
            return Task.FromResult(new HealthCheckResult(context.Registration.FailureStatus, "Service certificate is expired"));

        if (options.SystemCertificate.NotAfter < DateTime.Now.AddDays(30))
            return Task.FromResult(HealthCheckResult.Degraded("Service certificate expires in less than 30 days"));


        return Task.FromResult(HealthCheckResult.Healthy());
    }
}
