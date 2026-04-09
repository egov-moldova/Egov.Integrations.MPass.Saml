using Egov.Integrations.MPass.Saml;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSystemCertificate(builder.Configuration.GetSection("Certificate"));

builder.Services.AddAuthentication(sharedOptions =>
{
    sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    sharedOptions.DefaultChallengeScheme = MPassSamlDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.Name = "auth";
    options.Cookie.SameSite = SameSiteMode.None;
})
.AddMPassSaml(builder.Configuration.GetSection("MPassSaml"));

builder.Services.AddHealthChecks()
    .AddMPassSamlHealthCheck();

var app = builder.Build();

app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();

app.MapHealthChecks("/health");
app.MapMPassSaml();

app.MapGet("/signedout", async context =>
{
    await WriteHtmlAsync(context.Response, async res =>
    {
        await res.WriteAsync($"<h1>You have been signed out.</h1>");
        await res.WriteAsync("<a class=\"btn btn-link\" href=\"/\">Sign In</a>");
    });
});

app.MapGet("/signout-local", async context =>
{
    if (context.User.Identity?.IsAuthenticated ?? false)
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await WriteHtmlAsync(context.Response, async res =>
    {
        await context.Response.WriteAsync($"<h1>Signed out {HtmlEncode(context.User.Identity?.Name ?? "anonymous")}</h1>");
        await context.Response.WriteAsync("<a class=\"btn btn-link\" href=\"/\">Sign In</a>");
    });
});

app.MapFallback(async context =>
{
    // DefaultAuthenticateScheme causes User to be set
    var user = context.User;

    // Not authenticated
    if (!user.Identity?.IsAuthenticated ?? true)
    {
        await WriteHtmlAsync(context.Response, async response =>
        {
            await response.WriteAsync($"<h1>Hello Anonymous User</h1>");
            await response.WriteAsync("<a class=\"btn btn-default\" href=\"/account/login\">Sign In</a>");
        });
        return;
    }

    await WriteHtmlAsync(context.Response, async response =>
    {
        await response.WriteAsync($"<h1>Hello Authenticated User {HtmlEncode(user.Identity?.Name ?? "anonymous")}</h1>");
        await response.WriteAsync("<a class=\"btn btn-default\" href=\"/signout-local\">Sign Out Local</a>");
        await response.WriteAsync("<a class=\"btn btn-default\" href=\"/account/logout\">Sign Out Remote</a>");

        await response.WriteAsync("<h2>Claims:</h2>");
        await WriteTableHeader(response, [ "Claim Type", "Value" ], context.User.Claims.Select(c => new[] { c.Type, c.Value }));
    });
});

app.Run();

static async Task WriteHtmlAsync(HttpResponse response, Func<HttpResponse, Task> writeContent)
{
    var bootstrap = "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css\" integrity=\"sha384-HSMxcRTRxnN+Bdg0JdbxYKrThecOKuH5zCYotlSAcp1+c8xmyTe9GYg1l9a69psu\" crossorigin=\"anonymous\">";

    response.ContentType = "text/html";
    await response.WriteAsync($"<html><head>{bootstrap}</head><body><div class=\"container\">");
    await writeContent(response);
    await response.WriteAsync("</div></body></html>");
}

static async Task WriteTableHeader(HttpResponse response, IEnumerable<string> columns, IEnumerable<IEnumerable<string>> data)
{
    await response.WriteAsync("<table class=\"table table-condensed\">");
    await response.WriteAsync("<tr>");
    foreach (var column in columns)
    {
        await response.WriteAsync($"<th>{HtmlEncode(column)}</th>");
    }
    await response.WriteAsync("</tr>");
    foreach (var row in data)
    {
        await response.WriteAsync("<tr>");
        foreach (var column in row)
        {
            await response.WriteAsync($"<td>{HtmlEncode(column)}</td>");
        }
        await response.WriteAsync("</tr>");
    }
    await response.WriteAsync("</table>");
}

static string HtmlEncode(string content) =>
    string.IsNullOrEmpty(content) ? string.Empty : HtmlEncoder.Default.Encode(content);