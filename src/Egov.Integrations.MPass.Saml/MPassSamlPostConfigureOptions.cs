using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Egov.Extensions.Configuration;

namespace Egov.Integrations.MPass.Saml;

internal class MPassSamlPostConfigureOptions : IPostConfigureOptions<MPassSamlOptions>
{
    private readonly IDataProtectionProvider _dataProtectionProvider;

    public MPassSamlPostConfigureOptions(IDataProtectionProvider dataProtectionProvider)
    {
        _dataProtectionProvider = dataProtectionProvider;
    }

    public void PostConfigure(string? name, MPassSamlOptions options)
    {
        options.DataProtectionProvider ??= _dataProtectionProvider;

        if (string.IsNullOrEmpty(options.SignOutScheme))
        {
            options.SignOutScheme = options.SignInScheme;
        }

        if (options.StateDataFormat == null)
        {
            var dataProtector = options.DataProtectionProvider.CreateProtector(nameof(MPassSamlHandler));
            options.StateDataFormat = new PropertiesDataFormat(dataProtector);
        }

        if (options.SystemCertificate == null)
        {
            throw new ApplicationException("No system certificate configured");
        }

        if (options.IdpCertificate == null)
        {
            if (options.IdentityProviderCertificatePath == null)
            {
                throw new ApplicationException("No identity provider certificate path");
            }

            options.IdpCertificate = CertificateLoader.Public(options.IdentityProviderCertificatePath) ??
                                     throw new ApplicationException("Invalid identity provider certificate path");
        }
    }
}
