using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Data.Entities
{
    public enum EmailTokenType
    {
        VerifyEmail,
        ResetPassword,
        ChangeEmail,
        DeleteAccount,
    }

    public sealed class EmailVerificationToken
    {
        [Key]
        public Guid UUID { get; set; } = Guid.CreateVersion7();
        public required Guid UserUUID { get; set; }
        public User User { get; set; } = null!;
        public required string TokenHash { get; set; }
        public string? TargetEmail { get; set; }
        public long CreatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public long ExpiresAt { get; set; }
        public required EmailTokenType Type { get; set; }
        public bool Used { get; set; } = false;
    }
}
