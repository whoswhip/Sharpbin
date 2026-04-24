using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data.Enums;
using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Data.Entities
{

    [Flags]
    public enum Role
    {
        User = 1,
        Moderator = 2,
        Admin = 4
    }

    [Index(nameof(UID))]
    [Index(nameof(UUID), IsUnique = true)]
    public sealed class User
    {
        public long? UID { get; set; }
        [Key]
        public required Guid UUID { get; set; } = Guid.CreateVersion7();
        public long CreatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public required string Username { get; set; }
        public required string PasswordHash { get; set; }

        public string? Email { get; set; }
        public bool EmailVerified { get; set; } = false;

        public string? DisplayName { get; set; }
        public long? LastLogin { get; set; }

        public Role Roles { get; set; } = Role.User;
        public bool IsBanned { get; set; } = false;

        public Visibility Visibility { get; set; } = Visibility.Public;
        public List<Paste> Pastes { get; set; } = [];
        public List<RefreshToken> RefreshTokens { get; set; } = [];
        public List<Report> Reports { get; set; } = [];
        public List<ApiKey> ApiKeys { get; set; } = [];
        public List<EmailVerificationToken> EmailVerificationTokens { get; set; } = [];
        public List<Comment> Comments { get; set; } = [];
        public UserTotp? Totp { get; set; }
    }
}
