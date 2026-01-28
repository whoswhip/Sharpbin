using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Data.Entities
{
    [Index(nameof(PID), IsUnique = true)]
    [Index(nameof(UUID), IsUnique = true)]
    [Index(nameof(ID), IsUnique = true)]
    [Index(nameof(AuthorUUID))]
    [Index(nameof(ExpiresAt))]
    [Index(nameof(Visibility))]
    [Index(nameof(Syntax))]
    [Index(nameof(Views))]
    [Index(nameof(Size))]
    public sealed class Paste
    {
        [Key]
        public int PID { get; set; }
        public required Guid UUID { get; set; }
        public long CreatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public required string ID { get; set; }
        public string? Title { get; set; }

        public Guid? AuthorUUID { get; set; } // uuid of the user who created the paste, or null for anonymous pastes
        public User? User { get; set; }

        public long? EditedAt { get; set; }

        public required byte[] Content { get; set; }
        public long Size { get; set; } // stored size (may be compressed)
        public long TrueSize { get; set; } // uncompressed size
        public bool IsCompressed { get; set; } = false;

        public int Views { get; set; }
        public string? Syntax { get; set; }
        public int Visibility { get; set; } = 0; // 0 = public, 1 = unlisted, 2 = private (encrypted pastes handled on frontend)

        public long ExpiresAt { get; set; } // timestamp of when the paste expires, or 0 for never

        public List<PasteView> PasteViews { get; set; } = [];
        public List<Report> Reports { get; set; } = [];
    }
}
