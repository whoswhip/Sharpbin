using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using SharpbinV3.Server.Data.Enums;

namespace SharpbinV3.Server.Data.Entities
{
    [Index(nameof(PasteID), nameof(UserUUID), IsUnique = true)]
    [Index(nameof(PasteID), nameof(Type))]
    public class PasteInteraction
    {
        [Key]
        public long Id { get; set; }
        public long PasteID { get; set; }
        public Guid UserUUID { get; set; }
        public long CreatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        public Interaction Type { get; set; }

        public Paste Paste { get; set; } = null!;
    }
}
