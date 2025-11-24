using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

namespace SharpbinV3.Data.Entities
{
    [Index(nameof(PID), IsUnique = true)]
    [Index(nameof(UUID), IsUnique = true)]
    [Index(nameof(ID), IsUnique = true)]
    [Index(nameof(AuthorUUID))]
    [Index(nameof(ExpiresAt))]
    [Index(nameof(Views))]
    [Index(nameof(Visiblity))]
    public sealed class Paste
    {
        [Key]
        public int PID { get; set; }
        public required string UUID { get; set; } // uuid v7 includes timestamp, this counts as created at
        public required string ID { get; set; }
        public string? Title { get; set; }
        public required string AuthorUUID { get; set; } // uuid of the user who created the paste, or "ANON" for anonymous pastes
        public User? User { get; set; }
        public required string FilePath { get; set; }
        public long? EditedAt { get; set; }
        public int Size { get; set; } // stored size (may be compressed)
        public int TrueSize { get; set; } // uncompressed size
        public int Views { get; set; }
        public string? Syntax { get; set; }
        public int Visiblity { get; set; } = 0; // 0 = public, 1 = unlisted, 2 = private
        public long ExpiresAt { get; set; } // timestamp of when the paste expires, or 0 for never
    }
}
