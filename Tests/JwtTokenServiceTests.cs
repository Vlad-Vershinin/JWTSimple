using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthService.Interfaces;
using AuthService.Models;
using AuthService.Services;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;

namespace Tests;

public class JwtTokenServiceTests
{
    private readonly IJwtTokenService<Guid> _tokenService;
    private const string TestSecret = "super-secret-key-that-is-at-least-32-characters-long!";
    private const string TestIssuer = "MyAuthService";
    private const string TestAudience = "MyApps";

    public JwtTokenServiceTests()
    {
        _tokenService = new JwtTokenService<Guid>();
    }

    private class TestUser : IAuthUser<Guid>
    {
        public Guid Id { get; set; }
        public string Identity { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public IEnumerable<Claim> CustomClaims { get; set; } = Enumerable.Empty<Claim>();
    }

    [Fact]
    public void GenerateToken_WithValidUser_ShouldReturnValidJwt()
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            Identity = "test_user"
        };

        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = 60
        };

        var token = _tokenService.GenerateToken(user, options);

        token.Should().NotBeNullOrWhiteSpace();

        var handler = new JwtSecurityTokenHandler();
        handler.CanReadToken(token).Should().BeTrue();
    }

    [Fact]
    public void GenerateToken_ShouldIncludeCorrectClaims()
    {
        var userId = Guid.NewGuid();
        var userIdentity = "john_doe";

        var user = new TestUser
        {
            Id = userId,
            Identity = userIdentity
        };

        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = 30
        };

        var token = _tokenService.GenerateToken(user, options);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        var nameIdClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
        nameIdClaim.Should().NotBeNull();
        nameIdClaim!.Value.Should().Be(userId.ToString());

        var nameClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
        nameClaim.Should().NotBeNull();
        nameClaim!.Value.Should().Be(userIdentity);
    }

    [Fact]
    public void GenerateToken_ShouldIncludeJtiClaim()
    {
        var user = new TestUser { Id = Guid.NewGuid(), Identity = "test" };
        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience
        };

        var token = _tokenService.GenerateToken(user, options);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        var jtiClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti);
        jtiClaim.Should().NotBeNull();
        Guid.TryParse(jtiClaim!.Value, out _).Should().BeTrue();
    }

    [Fact]
    public void GenerateToken_ShouldHaveCorrectIssuerAndAudience()
    {
        var user = new TestUser { Id = Guid.NewGuid(), Identity = "test" };
        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience
        };

        var token = _tokenService.GenerateToken(user, options);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        jwtToken.Issuer.Should().Be(TestIssuer);
        jwtToken.Audiences.Should().Contain(TestAudience);
    }

    [Fact]
    public void GenerateToken_ShouldSetCorrectExpiration()
    {
        var expiryMinutes = 120;
        var user = new TestUser { Id = Guid.NewGuid(), Identity = "test" };
        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = expiryMinutes
        };

        var beforeGeneration = DateTime.UtcNow;
        var token = _tokenService.GenerateToken(user, options);
        var afterGeneration = DateTime.UtcNow;

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        jwtToken.ValidTo.Should().BeAfter(beforeGeneration.AddMinutes(expiryMinutes - 1))
            .And.BeBefore(afterGeneration.AddMinutes(expiryMinutes + 1));
    }

    [Fact]
    public void GenerateToken_ShouldIncludeCustomClaims()
    {
        var customClaims = new[]
        {
            new Claim("role", "admin"),
            new Claim("department", "backend")
        };

        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            Identity = "admin_user",
            CustomClaims = customClaims
        };

        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience
        };

        var token = _tokenService.GenerateToken(user, options);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        var roleClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "role");
        roleClaim.Should().NotBeNull();
        roleClaim!.Value.Should().Be("admin");

        var departmentClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "department");
        departmentClaim.Should().NotBeNull();
        departmentClaim!.Value.Should().Be("backend");
    }

    [Fact]
    public void GenerateToken_WithNullUser_ShouldThrowArgumentNullException()
    {
        var options = new JwtOptions { SecretKey = TestSecret };

        var action = () => _tokenService.GenerateToken(null!, options);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("user");
    }

    [Fact]
    public void GenerateToken_WithNullOptions_ShouldThrowArgumentNullException()
    {
        var user = new TestUser { Id = Guid.NewGuid() };

        var action = () => _tokenService.GenerateToken(user, null!);

        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("options");
    }

    [Fact]
    public void GenerateToken_WithShortSecretKey_ShouldThrowArgumentException()
    {
        var user = new TestUser { Id = Guid.NewGuid() };
        var options = new JwtOptions { SecretKey = "short" };

        var action = () => _tokenService.GenerateToken(user, options);

        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GenerateToken_WithEmptySecretKey_ShouldThrowArgumentException()
    {
        var user = new TestUser { Id = Guid.NewGuid() };
        var options = new JwtOptions { SecretKey = string.Empty };

        var action = () => _tokenService.GenerateToken(user, options);

        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GenerateToken_ShouldUseHmacSha256Algorithm()
    {
        var user = new TestUser { Id = Guid.NewGuid(), Identity = "test" };
        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience
        };

        var token = _tokenService.GenerateToken(user, options);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        jwtToken.Header.Alg.Should().Be(SecurityAlgorithms.HmacSha256);
    }

    [Fact]
    public void GenerateRefreshToken_ShouldReturnNonEmptyString()
    {
        var refreshToken = _tokenService.GenerateRefreshToken();

        refreshToken.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void GenerateRefreshToken_ShouldReturnBase64String()
    {
        var refreshToken = _tokenService.GenerateRefreshToken();

        var action = () => Convert.FromBase64String(refreshToken);

        action.Should().NotThrow();
    }

    [Fact]
    public void GenerateRefreshToken_ShouldGenerateUniqueTokens()
    {
        var tokens = new HashSet<string>();

        for (int i = 0; i < 10; i++)
        {
            var token = _tokenService.GenerateRefreshToken();
            tokens.Add(token);
        }

        tokens.Count.Should().Be(10, "All generated tokens should be unique");
    }

    [Fact]
    public void GenerateRefreshToken_ShouldHaveSufficientLength()
    {
        var refreshToken = _tokenService.GenerateRefreshToken();
        var decodedBytes = Convert.FromBase64String(refreshToken);

        decodedBytes.Length.Should().Be(64, "Refresh token should be 64 bytes");
    }

    [Fact]
    public void GetPrincipalFromExpiredToken_WithValidExpiredToken_ShouldReturnClaimsPrincipal()
    {
        var user = new TestUser { Id = Guid.NewGuid(), Identity = "test_user" };
        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = -10
        };

        var expiredToken = _tokenService.GenerateToken(user, options);

        var principal = _tokenService.GetPrincipalFromExpiredToken(expiredToken, TestSecret);

        principal.Should().NotBeNull();
    }

    [Fact]
    public void GetPrincipalFromExpiredToken_ShouldPreserveUserClaims()
    {
        var userId = Guid.NewGuid();
        var userIdentity = "test_user";

        var user = new TestUser
        {
            Id = userId,
            Identity = userIdentity
        };

        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = -10
        };

        var expiredToken = _tokenService.GenerateToken(user, options);
        var principal = _tokenService.GetPrincipalFromExpiredToken(expiredToken, TestSecret);

        var nameIdClaim = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
        nameIdClaim.Should().NotBeNull();
        nameIdClaim!.Value.Should().Be(userId.ToString());

        var nameClaim = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
        nameClaim.Should().NotBeNull();
        nameClaim!.Value.Should().Be(userIdentity);
    }

    [Fact]
    public void GetPrincipalFromExpiredToken_WithInvalidSecret_ShouldThrowSecurityTokenException()
    {
        var user = new TestUser { Id = Guid.NewGuid(), Identity = "test" };
        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = -10
        };

        var expiredToken = _tokenService.GenerateToken(user, options);
        var wrongSecret = "wrong-secret-key-that-is-at-least-32-chars-long!!";

        var action = () => _tokenService.GetPrincipalFromExpiredToken(expiredToken, wrongSecret);

        action.Should().Throw<SecurityTokenException>();
    }

    [Fact]
    public void GetPrincipalFromExpiredToken_WithWrongAlgorithmToken_ShouldThrowSecurityTokenException()
    {
        var token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.something";

        var action = () => _tokenService.GetPrincipalFromExpiredToken(token, TestSecret);

        action.Should().Throw<Exception>();
    }

    [Fact]
    public void GetPrincipalFromExpiredToken_WithInvalidTokenFormat_ShouldThrowException()
    {
        var invalidToken = "invalid.token.format";

        var action = () => _tokenService.GetPrincipalFromExpiredToken(invalidToken, TestSecret);

        action.Should().Throw<Exception>();
    }

    [Fact]
    public void GetPrincipalFromExpiredToken_ShouldPreserveCustomClaims()
    {
        var customClaims = new[]
        {
            new Claim("role", "moderator"),
            new Claim("level", "5")
        };

        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            Identity = "moderator_user",
            CustomClaims = customClaims
        };

        var options = new JwtOptions
        {
            SecretKey = TestSecret,
            Issuer = TestIssuer,
            Audience = TestAudience,
            ExpiryInMinutes = 60
        };

        var expiredToken = _tokenService.GenerateToken(user, options);
        var principal = _tokenService.GetPrincipalFromExpiredToken(expiredToken, TestSecret);

        var roleClaim = principal.Claims.FirstOrDefault(c => c.Type == "role");
        if (roleClaim != null)
        {
            roleClaim.Value.Should().Be("moderator");
        }

        var levelClaim = principal.Claims.FirstOrDefault(c => c.Type == "level");
        if (levelClaim != null)
        {
            levelClaim.Value.Should().Be("5");
        }

        var nameIdClaim = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
        nameIdClaim.Should().NotBeNull();
    }
}
