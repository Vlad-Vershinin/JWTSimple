using AuthService.Models;
using System.Security.Claims;

namespace AuthService.Interfaces;

public interface IJwtTokenService<TId> where TId : IEquatable<TId>
{
    string GenerateToken(IAuthUser<TId> user, JwtOptions options);
    string GenerateRefreshToken();

    ClaimsPrincipal GetPrincipalFromExpiredToken(string token, string secretKey);
}
