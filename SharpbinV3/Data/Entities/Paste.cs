using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Data.Entities
{
    [Index(nameof(PID), IsUnique = true)]
    [Index(nameof(UUID), IsUnique = true)]
    [Index(nameof(ID), IsUnique = true)]
    [Index(nameof(AuthorUUID))]
    [Index(nameof(ExpiresAt))]
    [Index(nameof(Views))]
    [Index(nameof(Visibility))]
    public sealed class Paste
    {
        [Key]
        public int PID { get; set; }
        public required Guid UUID { get; set; } // uuid v7 includes timestamp, this counts as created at
        public required string ID { get; set; }
        public string? Title { get; set; }

        public required Guid AuthorUUID { get; set; } = Guid.Empty; // uuid of the user who created the paste, or Guid.Empty for anonymous pastes
        public User? User { get; set; }

        public long? EditedAt { get; set; }

        public required byte[] Content { get; set; }
        public int Size { get; set; } // stored size (may be compressed)
        public int TrueSize { get; set; } // uncompressed size
        public bool IsCompressed { get; set; } = false;

        public int Views { get; set; }
        public string? Syntax { get; set; }
        public int Visibility { get; set; } = 0; // 0 = public, 1 = unlisted, 2 = private (encrypted pastes handled on frontend)

        public long ExpiresAt { get; set; } // timestamp of when the paste expires, or 0 for never
    }
}
