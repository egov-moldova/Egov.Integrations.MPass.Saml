using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Moq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Egov.Integrations.MPass.Saml.Tests;

public class MPassSamlPostConfigureOptionsTests
{
    private readonly Mock<IDataProtectionProvider> _mockDataProtectionProvider;
    private readonly MPassSamlPostConfigureOptions _postConfigure;

    public MPassSamlPostConfigureOptionsTests()
    {
        _mockDataProtectionProvider = new Mock<IDataProtectionProvider>();
        var mockDataProtector = new Mock<IDataProtector>();
        _mockDataProtectionProvider.Setup(p => p.CreateProtector(It.IsAny<string>())).Returns(mockDataProtector.Object);
        _postConfigure = new MPassSamlPostConfigureOptions(_mockDataProtectionProvider.Object);
    }

    [Fact]
    public void PostConfigure_Throws_WhenSystemCertificateIsMissing()
    {
        // Arrange
        var options = new MPassSamlOptions();

        // Act & Assert
        Assert.Throws<ApplicationException>(() => _postConfigure.PostConfigure("scheme", options));
    }

    private static X509Certificate2 CreateMockCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Mock", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
    }

    [Fact]
    public void PostConfigure_SetsDefaultValues_WhenValid()
    {
        // Arrange
        var options = new MPassSamlOptions
        {
            SystemCertificate = CreateMockCert(),
            IdpCertificate = CreateMockCert(),
            SignInScheme = "Cookies"
        };

        // Act
        _postConfigure.PostConfigure("scheme", options);

        // Assert
        Assert.Equal("Cookies", options.SignOutScheme);
        Assert.NotNull(options.DataProtectionProvider);
        Assert.NotNull(options.StateDataFormat);
    }

    [Fact]
    public void PostConfigure_Throws_WhenIdpCertificateAndPathAreMissing()
    {
        // Arrange
        var options = new MPassSamlOptions
        {
            SystemCertificate = CreateMockCert()
        };

        // Act & Assert
        var ex = Assert.Throws<ApplicationException>(() => _postConfigure.PostConfigure("scheme", options));
        Assert.Equal("No identity provider certificate path", ex.Message);
    }
}
