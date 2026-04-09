using Egov.Integrations.MPass.Saml;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Nodes;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Extensions methods for <see cref="IEndpointRouteBuilder"/>.
/// </summary>
public static class EndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps /login, /logout and /me endpoints under /account path.
    /// Optionally, /login endpoint forwards returnUrl, passive (true/false) and lang (ro/ru/en) query parameters
    /// and /logout endpoint forwards returnUrl query parameter.
    /// </summary>
    /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to map the routes to.</param>
    public static void MapMPassSaml(this IEndpointRouteBuilder endpoints)
        => endpoints.MapMPassSaml(MPassSamlDefaults.EndpointPath);

    /// <summary>
    /// Maps /login, /logout and /me endpoints under /account path.
    /// Optionally, /login endpoint forwards returnUrl, passive (true/false) and lang (ro/ru/en) query parameters
    /// and /logout endpoint forwards returnUrl query parameter.
    /// </summary>
    /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to map the routes to.</param>
    /// <param name="path">The prefix to use for account endpoints.</param>
    public static void MapMPassSaml(this IEndpointRouteBuilder endpoints, string path)
        => endpoints.MapMPassSaml(path, _ => { });

    /// <summary>
    /// Maps /login, /logout and /me endpoints under /account path according to options.
    /// Optionally, /login endpoint forwards returnUrl, passive (true/false) and lang (ro/ru/en) query parameters
    /// and /logout endpoint forwards returnUrl query parameter.
    /// </summary>
    /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to map the routes to.</param>
    /// <param name="configureOptions">A callback to configure endpoints options.</param>
    public static void MapMPassSaml(this IEndpointRouteBuilder endpoints, Action<MPassSamlEndpointsOptions> configureOptions)
        => endpoints.MapMPassSaml(MPassSamlDefaults.EndpointPath, configureOptions);

    /// <summary>
    /// Maps /login, /logout and /me endpoints according to path and options.
    /// Optionally, /login endpoint forwards returnUrl, passive (true/false) and lang (ro/ru/en) query parameters
    /// and /logout endpoint forwards returnUrl query parameter.
    /// </summary>
    /// <param name="endpoints">The <see cref="IEndpointRouteBuilder"/> to map the routes to.</param>
    /// <param name="path">The path to use for endpoints.</param>
    /// <param name="configureOptions">A callback to configure endpoints options.</param>
    public static void MapMPassSaml(this IEndpointRouteBuilder endpoints, string path, Action<MPassSamlEndpointsOptions> configureOptions)
    {
        var options = new MPassSamlEndpointsOptions();
        configureOptions?.Invoke(options);

        endpoints.MapGet(path + "/login", async context =>
        {
            var returnUrl = options.DefaultReturnUrl;
            if (context.Request.Query.TryGetValue("returnUrl", out var returnUrlValues))
            {
                returnUrl = returnUrlValues.ToString();
            }
            if (!IsLocalUrl(returnUrl))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            var isPassive = false;
            if (context.Request.Query.TryGetValue("passive", out var passiveValues))
            {
                isPassive = Convert.ToBoolean(passiveValues.ToString());
            }

            string? lang = null;
            if (context.Request.Query.TryGetValue("lang", out var langValues))
            {
                lang = langValues.ToString();
            }

            if (!context.User.Identity?.IsAuthenticated ?? true)
            {
                var authenticationProperties = options.AuthenticationPropertiesFactory(context);
                authenticationProperties.RedirectUri = returnUrl;
                if (isPassive) authenticationProperties.IsPassive = isPassive;
                if (lang != null) authenticationProperties.Language = lang;
                await context.ChallengeAsync(authenticationProperties);
            }
            else
            {
                context.Response.Redirect(returnUrl, false, true);
            }
        });

        endpoints.MapGet(path + "/logout", async context =>
        {
            var returnUrl = options.DefaultReturnUrl;
            if (context.Request.Query.TryGetValue("returnUrl", out var returnUrlValues))
            {
                returnUrl = returnUrlValues.ToString();
            }

            if (!IsLocalUrl(returnUrl))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            if (context.User.Identity?.IsAuthenticated ?? false)
            {
                await context.SignOutAsync(options.LocalAuthenticationScheme);
                await context.SignOutAsync(options.RemoteAuthenticationScheme, new AuthenticationProperties
                {
                    RedirectUri = returnUrl
                });
            }
            else
            {
                context.Response.Redirect(returnUrl, false, true);
            }
        });

        endpoints.MapGet(path + "/me", async context =>
        {
            if (!context.User.Identity?.IsAuthenticated ?? true)
            {
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }

            var claimsJson = new JsonObject();
            foreach (var claim in context.User.Claims)
            {
                if (string.IsNullOrWhiteSpace(claim.Value)) continue;
                if (claimsJson.TryGetPropertyValue(claim.Type, out var claimValues))
                {
                    if (claimValues is JsonArray claimValuesArray)
                    {
                        claimValuesArray.Add(claim.Value);
                    }
                    else
                    {
                        claimsJson[claim.Type] = new JsonArray
                        {
                            claimValues!.GetValue<string>(),
                            claim.Value
                        };
                    }
                }
                else
                {
                    claimsJson[claim.Type] = claim.Value;
                }
            }
            
            await context.Response.WriteAsJsonAsync(claimsJson, context.RequestAborted);
        });
    }

    // from https://github.com/dotnet/aspnetcore/blob/main/src/Mvc/Mvc.Core/src/Routing/UrlHelperBase.cs
    private static bool IsLocalUrl([NotNullWhen(true)] string? url)
    {
        if (string.IsNullOrEmpty(url))
        {
            return false;
        }

        // Allows "/" or "/foo" but not "//" or "/\".
        if (url[0] == '/')
        {
            // url is exactly "/"
            if (url.Length == 1)
            {
                return true;
            }

            // url doesn't start with "//" or "/\"
            if (url[1] != '/' && url[1] != '\\')
            {
                return !HasControlCharacter(url.AsSpan(1));
            }

            return false;
        }

        // Allows "~/" or "~/foo" but not "~//" or "~/\".
        if (url[0] == '~' && url.Length > 1 && url[1] == '/')
        {
            // url is exactly "~/"
            if (url.Length == 2)
            {
                return true;
            }

            // url doesn't start with "~//" or "~/\"
            if (url[2] != '/' && url[2] != '\\')
            {
                return !HasControlCharacter(url.AsSpan(2));
            }

            return false;
        }

        return false;

        static bool HasControlCharacter(ReadOnlySpan<char> readOnlySpan)
        {
            // URLs may not contain ASCII control characters.
            for (var i = 0; i < readOnlySpan.Length; i++)
            {
                if (char.IsControl(readOnlySpan[i]))
                {
                    return true;
                }
            }

            return false;
        }
    }
}