using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SharpbinV3.Server.Data.Entities
{
    public sealed class RefreshToken
    {
        [Key]
        public Guid Id { get; set; }

        [Required]
        public Guid UserUUID { get; set; }

        [Required]
        public string TokenHash { get; set; } = null!;

        [Required]
        public string JwtId { get; set; } = null!;

        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }

        public bool Used { get; set; }
        public bool Revoked { get; set; }

        public string? ReplacedByToken { get; set; }

        public byte[] RowVersion { get; set; } = Array.Empty<byte>();

        [ForeignKey(nameof(UserUUID))]
        public User User { get; set; } = null!;
    }
}
