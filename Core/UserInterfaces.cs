namespace Core;

public interface IAuthUser<TId> where TId : IEquatable<TId>
{
    TId Id { get; set; }
    string Identity { get; set; }
    string PasswordHash { get; set; }
}
