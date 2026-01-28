using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Data.Entities
{
    [Index(nameof(UID))]
    [Index(nameof(UUID), IsUnique = true)]
    public sealed class User
    {
        public int? UID { get; set; }
        [Key]
        public required Guid UUID { get; set; } = Guid.CreateVersion7();
        public long CreatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public required string Username { get; set; }
        public required string PasswordHash { get; set; }

        public string? Email { get; set; }
        public string? DisplayName { get; set; }
        public long? LastLogin { get; set; }

        public int[] Roles { get; set; } = [0]; // 0 = regular user, 1 = moderator, 255 = admin
        public int Visibility { get; set; } = 0; // 0 = public, 1 = unlisted, 2 = private
        public List<Paste> Pastes { get; set; } = [];
        public List<RefreshToken> RefreshTokens { get; set; } = [];
        public List<Report> Reports { get; set; } = [];
        public UserTotp? Totp { get; set; }
    }
}
