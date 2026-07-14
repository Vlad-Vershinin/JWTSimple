using System.Security.Claims;

namespace AuthService.Models;

public interface IAuthUser<TId> where TId : IEquatable<TId>
{
    TId Id { get; set; }
    string Identity { get; set; }
    string PasswordHash { get; set; }

    IEnumerable<Claim> CustomClaims { get; }
}

public interface IEmailAuthenticatable
{
    string Email { get; }
}

public interface IUsernameAuthenticatable
{
    string Username { get; }
}

public interface IPhoneAuthenticatable
{
    string PhoneNumber { get; }
}