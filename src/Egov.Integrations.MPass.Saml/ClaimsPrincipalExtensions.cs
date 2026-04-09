namespace System.Security.Claims;

/// <summary>
/// Extension methods for <see cref="ClaimsIdentity"/>.
/// </summary>
public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// Returns the value of FirstName claim.
    /// </summary>
    /// <param name="principal">The <see cref="ClaimsPrincipal"/> to search through.</param>
    /// <returns>Requested claim value, if any.</returns>
    public static string? GetFirstName(this ClaimsPrincipal principal)
    {
        return principal.FindFirst("FirstName")?.Value;
    }

    /// <summary>
    /// Returns the value of LastName claim.
    /// </summary>
    /// <param name="principal">The <see cref="ClaimsPrincipal"/> to search through.</param>
    /// <returns>Requested claim value, if any.</returns>
    public static string? GetLastName(this ClaimsPrincipal principal)
    {
        return principal.FindFirst("LastName")?.Value;
    }

    /// <summary>
    /// Returns full name built from "FirstName LastName" claim values.
    /// </summary>
    /// <param name="principal">The <see cref="ClaimsPrincipal"/> to search through.</param>
    /// <returns>Requested value, if any.</returns>
    public static string? GetFullName(this ClaimsPrincipal principal)
    {
        var firstName = principal.GetFirstName();
        var lastName = principal.GetLastName();

        if (!string.IsNullOrEmpty(firstName) && !string.IsNullOrEmpty(lastName))
        {
            return firstName + " " + lastName;
        }
        return null;
    }
}
