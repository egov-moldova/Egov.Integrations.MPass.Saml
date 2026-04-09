# MPass SAML Authentication

This package is intended for Service Provider integration built on ASP.NET Core 8.0+ with MPass using SAML v2.0 protocol for authentication.

### Getting Started

Please go through the following instructions to integrate your project with MPass.

### Prerequisites

Before being able to integrate with MPass, a Service Provider, including its certificate, must be registered accordingly in MPass.
MPass accepts certificates issued by [STISC](https://stisc.gov.md/).

### Installing

Install the following package from [NuGet](https://www.nuget.org/packages/Egov.Integrations.MPass.Saml)

```
Install-Package Egov.Integrations.MPass.Saml
```

**Note:** This package is dependent on [`Egov.Extensions.Configuration`](https://www.nuget.org/packages/Egov.Extensions.Configuration/).

Then follow the instructions from Configuration and Usage sections below.

### Configuration

Add the following configuration section to your **appsettings.json**:

```json
{
   ...
    "Certificate": {
      "Path": "Files\\Certificates\\yourcertificate.pfx",
      "Password": "yourcertificatepassword"
   }
   ...
   "MPassSaml": {
      "SamlRequestIssuer": "https://sampleservice.md",
      "IdentityProviderCertificatePath": "Files\\Certificates\\idp.cer",
      "SamlMessageTimeout": "00:10:00",
      "SamlLoginDestination": "https://mpass.staging.egov.md/login/saml",
      "SamlLogoutDestination": "https://mpass.staging.egov.md/logout/saml",
      "ServiceRootUrl": "https://localhost:44379"
   }
   ...
}
```

where **ServiceRootUrl** is the base path of your published service.

Please note that your Service must be published using **https** protocol.

### Usage

Add the following code snippet to your **Startup.ConfigureServices** method:

```csharp
builder.Services.AddSystemCertificate(builder.Configuration.GetSection("Certificate"));

services.AddAuthentication(sharedOptions =>
{
    sharedOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    sharedOptions.DefaultChallengeScheme = MPassSamlDefaults.AuthenticationScheme;
})
.AddCookie()
.AddMPassSaml(builder.Configuration.GetSection("MPassSaml"));
```

In your **Startup.Configure** add the Authentication Middleware.

```csharp
app.UseAuthentication();
```
This package allows you to enable default endpoints mapper, so you don't have to implement login, logout, and user-details endpoints manually.
```csharp
app.MapMPassSaml();
```

**MapMPassSaml** - registers 3 endpoints in your application under the `/account` path:

- **`/account/login`** - Initiates SAML authentication with MPass. Accepts optional query parameters:
  - `returnUrl` - URL to redirect after successful authentication (defaults to `/`)
  - `passive` - Set to `true` for passive authentication (defaults to `false`)
  - `lang` - Language preference (`ro`, `ru`, or `en`)
- **`/account/logout`** - Handles logout from both local and remote sessions. Accepts optional query parameter:
  - `returnUrl` - URL to redirect after logout (defaults to `/`)
- **`/account/me`** - Returns the current user's claims as JSON. Returns `204 No Content` if the user is not authenticated.

