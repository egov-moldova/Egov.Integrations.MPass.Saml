using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Egov.Integrations.MPass.Saml;

internal class MPassSamlProtocolMessage : AuthenticationProtocolMessage
{
    public MPassSamlProtocolMessage(TimeProvider timeProvider)
    {
        TimeProvider = timeProvider;
    }

    public string? RequestIssuer { get; init; }
    public string? RequestID { get; init; }
    public TimeProvider TimeProvider { get; }
    public X509Certificate2 ServiceCertificate { get; init; } = default!;
    public X509Certificate2 IdentityProviderCertificate { get; init; } = default!;
    public TimeSpan SamlMessageTimeout { get; init; }

    public string RelayState
    {
        get => GetParameter(nameof(RelayState));
        init => SetParameter(nameof(RelayState), value);
    }

    public string BuildAuthnRequest(string assertionConsumerUrl, bool forceAuthn, bool isPassive)
    {
        return SignAndEncode("SAMLRequest",
            $@"<saml2p:AuthnRequest ID=""{RequestID}"" Version=""2.0"" IssueInstant=""{XmlConvert.ToString(TimeProvider.GetUtcNow())}"" " +
               $@"Destination=""{IssuerAddress}"" AssertionConsumerServiceURL=""{assertionConsumerUrl}"" " +
               (forceAuthn ? @"ForceAuthn=""true"" " : null) +
               (isPassive ? @"IsPassive=""true"" " : null) +
               $@"xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"">" +
                 $@"<saml2:Issuer>{RequestIssuer}</saml2:Issuer>" +
                  @"<saml2p:NameIDPolicy AllowCreate=""true""/>" +
            @"</saml2p:AuthnRequest>");
    }

    public string BuildLogoutRequest(string? nameID, string? sessionIndex)
    {
        return SignAndEncode("SAMLRequest",
            $@"<saml2p:LogoutRequest ID=""{RequestID}"" Version=""2.0"" IssueInstant=""{XmlConvert.ToString(TimeProvider.GetUtcNow())}"" Destination=""{IssuerAddress}"" xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"">" +
                $@"<saml2:Issuer>{RequestIssuer}</saml2:Issuer>" +
                $@"<saml2:NameID>{nameID}</saml2:NameID>" +
                $@"<saml2p:SessionIndex>{sessionIndex}</saml2p:SessionIndex>" +
            @"</saml2p:LogoutRequest>");
    }

    public string BuildLogoutResponse(string responseID)
    {
        return SignAndEncode("SAMLResponse",
            $@"<saml2p:LogoutResponse ID=""{responseID}"" Version=""2.0"" IssueInstant=""{XmlConvert.ToString(TimeProvider.GetUtcNow())}"" Destination=""{IssuerAddress}"" InResponseTo=""{RequestID}"" xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"">" +
                $@"<saml2:Issuer>{RequestIssuer}</saml2:Issuer>" +
                @"<saml2p:Status>" +
                    @"<saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>" +
                @"</saml2p:Status>" +
            @"</saml2p:LogoutResponse>");
    }

    #region Parsing and Verification
    public HandleRequestResult LoadAndVerifyLoginResponse(string samlResponse, string expectedDestination, string? redirectUri, string schemeName)
    {
        var (samlDocument, error) = LoadAndVerifyResponse(samlResponse, expectedDestination, new[] { "urn:oasis:names:tc:SAML:2.0:status:Success" }, out var ns);
        if (error != null) return HandleRequestResult.Fail(error);

        // get to Assertion
        var assertionNode = samlDocument!.SelectSingleNode("/saml2p:Response/saml2:Assertion", ns);
        if (assertionNode == null)
        {
            return HandleRequestResult.Fail("SAML Response does not contain an Assertion");
        }

        // verify Audience
        var audienceNode = assertionNode.SelectSingleNode("saml2:Conditions/saml2:AudienceRestriction/saml2:Audience", ns);
        if ((audienceNode == null) || (audienceNode.InnerText != RequestIssuer))
        {
            return HandleRequestResult.Fail("The SAML Assertion is not for this Service");
        }

        // get SessionIndex
        var sessionIndexAttribute = assertionNode.SelectSingleNode("saml2:AuthnStatement/@SessionIndex", ns);
        if (sessionIndexAttribute == null)
        {
            return HandleRequestResult.Fail("The SAML Assertion AuthnStatement does not contain a SessionIndex");
        }

        // get to Subject
        var subjectNode = assertionNode.SelectSingleNode("saml2:Subject", ns);
        if (subjectNode == null)
        {
            return HandleRequestResult.Fail("No Subject found in SAML Assertion");
        }

        // verify SubjectConfirmationData, according to [SAMLProf, 4.1.4.3]
        if (subjectNode.SelectSingleNode("saml2:SubjectConfirmation/saml2:SubjectConfirmationData", ns) is not XmlElement subjectConfirmationDataNode)
        {
            return HandleRequestResult.Fail("No Subject/SubjectConfirmation/SubjectConfirmationData found in SAML Assertion");
        }
        if (!subjectConfirmationDataNode.GetAttribute("Recipient").Equals(expectedDestination, StringComparison.CurrentCultureIgnoreCase))
        {
            return HandleRequestResult.Fail("The SAML Response is not for this Service");
        }
        if (!subjectConfirmationDataNode.HasAttribute("NotOnOrAfter") || XmlConvert.ToDateTimeOffset(subjectConfirmationDataNode.GetAttribute("NotOnOrAfter")) < TimeProvider.GetUtcNow())
        {
            return HandleRequestResult.Fail("Expired SAML Assertion");
        }

        // get NameID, which is normally an IDNP
        var nameIDNode = subjectNode.SelectSingleNode("saml2:NameID", ns);
        if (nameIDNode == null)
        {
            return HandleRequestResult.Fail("No Subject/NameID found in SAML Assertion");
        }

        // transform subject attributes to claims identity
        var identity = new ClaimsIdentity(MPassSamlDefaults.AuthenticationScheme, "Username", "Role");
        identity.AddClaim(new Claim("Username", nameIDNode.InnerText));
        if (sessionIndexAttribute.Value != null) identity.AddClaim(new Claim(MPassSamlDefaults.SessionIndex, sessionIndexAttribute.Value));

        foreach (XmlElement attributeElement in assertionNode.SelectNodes("saml2:AttributeStatement/saml2:Attribute", ns))
        {
            var attributeName = attributeElement.GetAttribute("Name");
            identity.AddClaims(attributeElement.SelectNodes("saml2:AttributeValue", ns)?.Cast<XmlElement>().Select(e => e.InnerXml).Select(value => new Claim(attributeName, value)));
        }
        return HandleRequestResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), new AuthenticationProperties { RedirectUri = redirectUri }, schemeName));
    }

    public (string? LogoutRequestID, string? Error) LoadAndVerifyLogoutRequest(string samlRequest, string expectedDestination, string? expectedNameID, string? expectedSessionIndex)
    {
        var result = new XmlDocument { PreserveWhitespace = true };
        result.LoadXml(Decode(samlRequest));

        // verify Signature
        if (!Verify(result, IdentityProviderCertificate))
        {
            return (null, "LogoutRequest signature invalid");
        }

        var ns = new XmlNamespaceManager(result.NameTable);
        ns.AddNamespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
        ns.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

        // verify IssueInstant
        var issueInstantAttribute = result.SelectSingleNode("/saml2p:LogoutRequest/@IssueInstant", ns);
        if ((issueInstantAttribute?.Value == null) ||
            ((DateTime.UtcNow - XmlConvert.ToDateTime(issueInstantAttribute.Value, XmlDateTimeSerializationMode.Utc)).Duration() > SamlMessageTimeout))
        {
            return (null, "The LogoutRequest is expired");
        }

        // verify Destination, according to [SAMLBind, 3.5.5.2]
        var requestDestination = result.SelectSingleNode("/saml2p:LogoutRequest/@Destination", ns);
        if ((requestDestination == null) || !string.Equals(requestDestination.Value, expectedDestination, StringComparison.CurrentCultureIgnoreCase))
        {
            return (null, "The LogoutRequest is not for this Service");
        }

        // verify NameID
        var nameIDElement = result.SelectSingleNode("/saml2p:LogoutRequest/saml2:NameID", ns);
        if ((nameIDElement == null) || ((expectedNameID != null) && !nameIDElement.InnerText.Equals(expectedNameID, StringComparison.CurrentCultureIgnoreCase)))
        {
            return (null, "The LogoutRequest received is for a different user");
        }

        // verify SessionIndex
        var sessionIndexElement = result.SelectSingleNode("/saml2p:LogoutRequest/saml2p:SessionIndex", ns);
        if ((sessionIndexElement == null) || ((expectedSessionIndex != null) && !sessionIndexElement.InnerText.Equals(expectedSessionIndex, StringComparison.CurrentCultureIgnoreCase)))
        {
            return (null, "The LogoutRequest is not expected in this user session");
        }

        // get LogoutRequest ID
        var logoutRequestIDAttribute = result.SelectSingleNode("/saml2p:LogoutRequest/@ID", ns);
        if (logoutRequestIDAttribute == null)
        {
            return (null, "LogoutRequest does not have an ID");
        }
        return (logoutRequestIDAttribute.Value, null);
    }

    public bool LoadAndVerifyLogoutResponse(string samlResponse, string expectedDestination)
    {
        var (_, error) = LoadAndVerifyResponse(samlResponse, expectedDestination,
            new[] { "urn:oasis:names:tc:SAML:2.0:status:Success", "urn:oasis:names:tc:SAML:2.0:status:PartialLogout" }, out _);
        return error == null;
    }

    private (XmlDocument? SamlDocument, string? Error) LoadAndVerifyResponse(string samlResponse, string expectedDestination, IEnumerable<string> validStatusCodes, out XmlNamespaceManager ns)
    {
        var result = new XmlDocument { PreserveWhitespace = true };
        ns = new XmlNamespaceManager(result.NameTable);
        ns.AddNamespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
        ns.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

        result.LoadXml(Decode(samlResponse));
        var responseElement = result.DocumentElement;
        if (responseElement == null) return (null, "SAML Response invalid");

        // verify Signature
        if (!Verify(result, IdentityProviderCertificate))
        {
            return (null, "SAML Response signature invalid");
        }

        // verify IssueInstant
        var issueInstant = responseElement.GetAttribute("IssueInstant");
        if ((issueInstant == null) || ((TimeProvider.GetUtcNow() - XmlConvert.ToDateTimeOffset(issueInstant)).Duration() > SamlMessageTimeout))
        {
            return (null, "SAML Response expired");
        }

        // verify Destination, according to [SAMLBind, 3.5.5.2]
        var responseDestination = responseElement.GetAttribute("Destination");
        if ((responseDestination == null) || !responseDestination.Equals(expectedDestination, StringComparison.CurrentCultureIgnoreCase))
        {
            return (null, "SAML Response is not for this Service");
        }

        // verify InResponseTo
        if (responseElement.GetAttribute("InResponseTo") != RequestID)
        {
            return (null, "SAML Response not expected");
        }

        // verify StatusCode
        var statusCodeValueAttribute = responseElement.SelectSingleNode("saml2p:Status/saml2p:StatusCode/@Value", ns);
        if (statusCodeValueAttribute == null)
        {
            return (null, "SAML Response does not contain a StatusCode Value");
        }
        if (!validStatusCodes.Contains(statusCodeValueAttribute.Value, StringComparer.OrdinalIgnoreCase))
        {
            var statusMessageNode = responseElement.SelectSingleNode("saml2p:Status/saml2p:StatusMessage", ns);
            return (null, $"Received failed SAML Response, status code: '{statusCodeValueAttribute.Value}', status message: '{statusMessageNode?.InnerText}'");
        }
        return (result, null);
    }
    #endregion

    #region Signature
    private string SignAndEncode(string samlParameter, string xml)
    {
        var doc = new XmlDocument();
        doc.LoadXml(xml);

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(ServiceCertificate));

        var signedXml = new SignedXml(doc)
        {
            SigningKey = ServiceCertificate.GetKeyAlgorithm() switch
            {
                "1.2.840.113549.1.1.1" => ServiceCertificate.GetRSAPrivateKey(),
                "1.2.840.10040.4.1" => ServiceCertificate.GetDSAPrivateKey(),
                _ => throw new NotSupportedException("Certificate key algorithm not supported")
            },
            KeyInfo = keyInfo
        };
        if (signedXml.SignedInfo == null)
        {
            throw new InvalidOperationException("SignedInfo is null");
        }
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

        if (doc.DocumentElement == null)
        {
            throw new InvalidOperationException("DocumentElement is null");
        }
        var messageID = doc.DocumentElement.GetAttribute("ID");
        if (string.IsNullOrEmpty(messageID))
        {
             throw new InvalidOperationException("ID attribute is missing");
        }
        var reference = new Reference("#" + messageID)
        {
            DigestMethod = SignedXml.XmlDsigSHA256Url
        };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());

        signedXml.AddReference(reference);

        signedXml.ComputeSignature();
        // insert after Issuer
        doc.DocumentElement.InsertAfter(signedXml.GetXml(), doc.DocumentElement.FirstChild);

        SetParameter(samlParameter, Encode(doc.OuterXml));
        return BuildFormPost();
    }

    private static bool Verify(XmlDocument document, X509Certificate2 publicCertificate)
    {
        var signedXml = new SignedXml(document);
        var signatureNode = document.DocumentElement?["Signature", "http://www.w3.org/2000/09/xmldsig#"];
        if (signatureNode == null) return false;
        signedXml.LoadXml(signatureNode);

        return signedXml.CheckSignature(publicCertificate, true);
    }
    #endregion

    #region Encoding
    private static string Encode(string message)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(message));
    }

    private static string Decode(string message)
    {
        return Encoding.UTF8.GetString(Convert.FromBase64String(message));
    }
    #endregion
}
