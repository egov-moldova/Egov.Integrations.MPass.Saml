using System.Security.Claims;

namespace Egov.Integrations.MPass.Saml.Tests;

public class ClaimsPrincipalExtensionsTests
{
    [Fact]
    public void GetFirstName_ReturnsValue_WhenClaimExists()
    {
        // Arrange
        var claims = new List<Claim> { new Claim("FirstName", "John") };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        // Act
        var result = principal.GetFirstName();

        // Assert
        Assert.Equal("John", result);
    }

    [Fact]
    public void GetFirstName_ReturnsNull_WhenClaimDoesNotExist()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        var result = principal.GetFirstName();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void GetLastName_ReturnsValue_WhenClaimExists()
    {
        // Arrange
        var claims = new List<Claim> { new Claim("LastName", "Doe") };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        // Act
        var result = principal.GetLastName();

        // Assert
        Assert.Equal("Doe", result);
    }

    [Fact]
    public void GetFullName_ReturnsCombinedValue_WhenBothClaimsExist()
    {
        // Arrange
        var claims = new List<Claim> 
        { 
            new Claim("FirstName", "John"),
            new Claim("LastName", "Doe")
        };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        // Act
        var result = principal.GetFullName();

        // Assert
        Assert.Equal("John Doe", result);
    }

    [Fact]
    public void GetFullName_ReturnsNull_WhenOneClaimIsMissing()
    {
        // Arrange
        var claims = new List<Claim> { new Claim("FirstName", "John") };
        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);

        // Act
        var result = principal.GetFullName();

        // Assert
        Assert.Null(result);
    }
}
