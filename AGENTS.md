# AI Coding Agent Guide - Egov.Integrations.MPass.Saml

This guide is intended for AI coding agents (like Junie, GitHub Copilot, Cursor, etc.) to understand the architecture, patterns, and development workflow of the `Egov.Integrations.MPass.Saml` library.

## Project Purpose
The library provides an ASP.NET Core authentication handler for **MPass** (the Moldovan Government Authentication and Access Control Service) using the **SAML 2.0** protocol. It simplifies SP (Service Provider) integration by handling SAML requests, responses, and artifact exchanges.

## Architecture Overview

### Core Components
- **`MPassSamlHandler`**: The central `RemoteAuthenticationHandler`. It manages the authentication lifecycle: Challenge (Login), HandleRemoteAuthenticate (Callback), and SignOut (Single Log Out).
- **`MPassSamlProtocolMessage`**: Responsible for constructing and parsing SAML XML messages (AuthnRequest, LogoutRequest, LogoutResponse). It handles XML digital signatures (signing with SP certificate, verifying with IdP certificate).
- **`MPassSamlOptions`**: Configuration settings including certificates, issuer URIs, and destination endpoints.
- **`EndpointRouteBuilderExtensions`**: Provides `MapMPassSaml()` to automatically register `/account/login`, `/account/logout`, and `/account/me` endpoints.

### Authentication Flow
1. **Challenge**: `MPassSamlHandler.HandleChallengeAsync` creates a `SAMLRequest` (AuthnRequest) and returns an HTML form that auto-posts to MPass.
2. **Callback**: MPass posts a `SAMLResponse` to the `CallbackPath` (default `/mpass-login`). `HandleRemoteAuthenticateAsync` verifies the signature and IssueInstant, extracts claims, and creates an `AuthenticationTicket`.
3. **Sign Out**: `SignOutAsync` initiates Single Log Out (SLO) by sending a `LogoutRequest` to MPass.

## Coding Patterns & Guidelines

### XML Handling
- Use `XmlDocument` with `PreserveWhitespace = true` for signature verification.
- Always verify signatures using the `IdentityProviderCertificate`.
- When generating XML, use `XmlConvert` for date/time formatting to ensure SAML compliance.

### Security
- **Open Redirect**: Always validate `returnUrl` using `IsLocalUrl` before redirecting.
- **XXE**: Although .NET Core's `XmlDocument` has safe defaults, be cautious when adding `XmlReaderSettings`.
- **Certificates**: System certificate (with private key) is required for signing; IdP certificate (public key) is required for verification.

### Dependency Injection
- Extension methods in `AuthenticationBuilderExtensions` and `HealthChecksBuilderExtensions` are the primary entry points for consumers.
- Use `IPostConfigureOptions<MPassSamlOptions>` for default value assignment and certificate loading.

## Common Development Tasks

### Adding New Claims
If MPass starts providing new attributes, they are automatically mapped in `MPassSamlProtocolMessage.LoadAndVerifyLoginResponse`. To add typed accessors, update `ClaimsPrincipalExtensions.cs`.

### Modifying Endpoints
Default endpoints are defined in `EndpointRouteBuilderExtensions.cs`. If changing the path structure, ensure `MPassSamlDefaults.EndpointPath` is updated or made configurable.

### Testing
- Use the `Test` project for integration testing.
- For unit tests, mock `TimeProvider` to test SAML message expiration logic.
- Ensure any changes to XML generation are verified against the SAML 2.0 schema.

## Troubleshooting for Agents
- **Signature Failure**: Ensure the correct `Reference` URI (usually `#ID`) and `CanonicalizationMethod` are used in `MPassSamlProtocolMessage`.
- **Clock Skew**: SAML is sensitive to time. Use `SamlMessageTimeout` to handle slight differences between SP and IdP clocks.
- **Certificate Loading**: Certificates are often loaded from files. Check `MPassSamlPostConfigureOptions` for loading logic.
