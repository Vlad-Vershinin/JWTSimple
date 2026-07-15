using System.Security.Claims;

namespace JWTSimple.Models;

public interface IAuthUser<TId> where TId : IEquatable<TId>
{
    public TId Id { get; set; }
    public string Identity { get; set; }
    public string PasswordHash { get; set; }

    public virtual IEnumerable<Claim> CustomClaims => Enumerable.Empty<Claim>();
}

public interface IEmailAuthenticatable
{
    public string Email { get; }
}

public interface IUsernameAuthenticatable
{
    public string Username { get; }
}

public interface IPhoneAuthenticatable
{
    public string PhoneNumber { get; }
}