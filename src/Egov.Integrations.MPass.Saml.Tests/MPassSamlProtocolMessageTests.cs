using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Xml;

namespace Egov.Integrations.MPass.Saml.Tests;

public class MPassSamlProtocolMessageTests
{
    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utcNow;
        public FixedTimeProvider(DateTimeOffset utcNow) => _utcNow = utcNow;
        public override DateTimeOffset GetUtcNow() => _utcNow;
    }

    private static X509Certificate2 CreateSelfSignedCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        // Export and import to ensure private key is persisted
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
    }

    private static string ExtractHiddenField(string html, string name)
    {
        var match = Regex.Match(html, $"name=\"{Regex.Escape(name)}\" value=\"(?<v>[^\"]+)\"");
        Assert.True(match.Success, $"Hidden field '{name}' not found");
        return match.Groups["v"].Value;
    }

    [Fact]
    public void BuildAuthnRequest_ProducesSignedForm_WithExpectedAttributes()
    {
        // Arrange
        var fixedNow = new DateTimeOffset(2024, 12, 31, 11, 22, 33, TimeSpan.Zero);
        var tp = new FixedTimeProvider(fixedNow);
        var cert = CreateSelfSignedCert();

        var msg = new Egov.Integrations.MPass.Saml.MPassSamlProtocolMessage(tp)
        {
            RequestIssuer = "https://sp.example.test",
            RequestID = "_id-123",
            IssuerAddress = "https://idp.example.test/sso",
            ServiceCertificate = cert,
            IdentityProviderCertificate = cert, // not used for request
            SamlMessageTimeout = TimeSpan.FromMinutes(5)
        };

        // Act
        var form = msg.BuildAuthnRequest("https://sp.example.test/acs", forceAuthn: true, isPassive: false);

        // Assert - basic HTML form structure and presence of SAMLRequest
        var samlRequest = ExtractHiddenField(form, "SAMLRequest");
        Assert.False(string.IsNullOrWhiteSpace(samlRequest));

        // Decode and validate XML shape
        var xml = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(samlRequest));
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
        ns.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

        var root = doc.DocumentElement!;
        Assert.Equal("AuthnRequest", root.LocalName);
        Assert.Equal("2.0", root.GetAttribute("Version"));
        Assert.Equal("_id-123", root.GetAttribute("ID"));
        Assert.Equal("https://idp.example.test/sso", root.GetAttribute("Destination"));
        Assert.Equal("https://sp.example.test/acs", root.GetAttribute("AssertionConsumerServiceURL"));
        Assert.Equal("true", root.GetAttribute("ForceAuthn"));

        // IssueInstant comes from fixed time
        var issueInstant = root.GetAttribute("IssueInstant");
        Assert.False(string.IsNullOrEmpty(issueInstant));
        Assert.Equal(fixedNow, XmlConvert.ToDateTimeOffset(issueInstant));

        // Issuer element
        var issuer = root.SelectSingleNode("saml2:Issuer", ns);
        Assert.NotNull(issuer);
        Assert.Equal("https://sp.example.test", issuer!.InnerText);

        // Signature element exists (enveloped)
        var signature = root["Signature", "http://www.w3.org/2000/09/xmldsig#"];
        Assert.NotNull(signature);
    }

    [Fact]
    public void BuildLogoutRequest_ProducesSignedForm_WithExpectedAttributes()
    {
        // Arrange
        var tp = new FixedTimeProvider(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var cert = CreateSelfSignedCert();

        var msg = new Egov.Integrations.MPass.Saml.MPassSamlProtocolMessage(tp)
        {
            RequestIssuer = "https://sp.example.test",
            RequestID = "_logout-1",
            IssuerAddress = "https://idp.example.test/logout",
            ServiceCertificate = cert,
            IdentityProviderCertificate = cert,
            SamlMessageTimeout = TimeSpan.FromMinutes(5)
        };

        // Act
        var form = msg.BuildLogoutRequest("user@example.test", "sess-1");

        // Assert
        var samlRequest = ExtractHiddenField(form, "SAMLRequest");
        var xml = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(samlRequest));
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
        ns.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

        var root = doc.DocumentElement!;
        Assert.Equal("LogoutRequest", root.LocalName);
        Assert.Equal("_logout-1", root.GetAttribute("ID"));
        Assert.Equal("https://idp.example.test/logout", root.GetAttribute("Destination"));
        Assert.Equal("user@example.test", root.SelectSingleNode("saml2:NameID", ns)!.InnerText);
        Assert.Equal("sess-1", root.SelectSingleNode("saml2p:SessionIndex", ns)!.InnerText);
        Assert.NotNull(root["Signature", "http://www.w3.org/2000/09/xmldsig#"]);
    }
}
