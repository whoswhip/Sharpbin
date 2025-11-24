using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ValueGeneration.Internal;
using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Data.Entities
{
    [Index(nameof(UID), IsUnique = true)]
    [Index(nameof(UUID), IsUnique = true)]
    public sealed class User
    {
        [Key]
        public int UID { get; set; }
        public required Guid UUID { get; set; } = Guid.CreateVersion7(); // uuid v7 includes timestamp
        public required string Username { get; set; }
        public required string PasswordHash { get; set; }
        public string? Email { get; set; }
        public string? DisplayName { get; set; }
        public long? LastLogin { get; set; }
        public int Type { get; set; } = 0; // 0 = regular user, 1 = moderator, 255 = admin
        public int Visiblity { get; set; } = 0; // 0 = public, 1 = unlisted, 2 = private
        public List<Paste> Pastes { get; set; } = [];
    }
}
