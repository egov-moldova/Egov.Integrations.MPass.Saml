# Egov.Integrations.MPass.Saml

MPass SAML 2.0 Authentication Handler for ASP.NET Core.

## Installation

You can install the package via NuGet:

```bash
dotnet add package Egov.Integrations.MPass.Saml
```

## Usage

### 1. Configure Services

In your `Program.cs`, add the MPass SAML authentication handler:

```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = MPassSamlDefaults.AuthenticationScheme;
})
.AddCookie()
.AddMPassSaml(builder.Configuration.GetSection("MPassSaml"));
```

### 2. Configure Endpoints

Map the MPass SAML endpoints:

```csharp
app.UseAuthentication();
app.MapMPassSaml();
```

### 3. Configuration

Add the following configuration to your `appsettings.json`:

```json
{
  "MPassSaml": {
    "MetadataAddress": "https://mpass.gov.md/saml/metadata",
    "ServiceProviderEntityId": "https://your-app.md",
    "CallbackPath": "/signin-mpass",
    "SignedOutCallbackPath": "/signout-callback-mpass"
  }
}
```

## Health Checks

You can also add a health check for MPass SAML:

```csharp
builder.Services.AddHealthChecks()
    .AddMPassSamlHealthCheck();

app.MapHealthChecks("/health");
```

## License

This project is licensed under the MIT License.
