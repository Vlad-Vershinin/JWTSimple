namespace JWTSimple.Models;

public class RefreshToken
{
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public string AssociatedAccessTokenId { get; set; } = string.Empty;
}
