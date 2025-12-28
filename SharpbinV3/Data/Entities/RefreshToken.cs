using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Data.Entities
{
    public sealed class RefreshToken
    {
        [Key]
        public Guid UserUUID { get; set; }
        public required string Token { get; set; }
        public required string JwtId { get; set; }
        public required long CreatedAt { get; set; }
        public required long ExpiresAt { get; set; }
        public bool Used { get; set; } = false;
        public User? User { get; set; }
    }
}
