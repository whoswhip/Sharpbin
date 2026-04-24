using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data.Enums;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SharpbinV3.Server.Data.Entities
{
    [Index(nameof(UUID))]
    [Index(nameof(ID), IsUnique = true)]
    [Index(nameof(AuthorUUID))]
    [Index(nameof(ExpiresAt))]
    [Index(nameof(Syntax))]
    [Index(nameof(Views))]
    [Index(nameof(StoredSize))]
    public sealed class Paste
    {
        [Key]
        public long PID { get; set; }
        public required Guid UUID { get; set; }
        public long CreatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public required string ID { get; set; }
        public string? Title { get; set; }

        public Guid? AuthorUUID { get; set; } // uuid of the user who created the paste, or null for anonymous pastes
        public User? User { get; set; }

        public long? EditedAt { get; set; }

        public required byte[] Content { get; set; }
        public long StoredSize { get; set; }
        public long OriginalSize { get; set; }
        public bool IsCompressed { get; set; } = false;

        public int Views { get; set; }
        public string? Syntax { get; set; }
        public Visibility Visibility { get; set; } = Visibility.Public;

        public long ExpiresAt { get; set; } // timestamp of when the paste expires, or 0 for never

        public List<PasteView> PasteViews { get; set; } = [];
        public List<Report> Reports { get; set; } = [];
        public List<Comment> Comments { get; set; } = [];
        public List<PasteInteraction> Interactions { get; set; } = [];

        [NotMapped]
        public int PositiveInteractionCount { get; set; }
        [NotMapped]
        public int NegativeInteractionCount { get; set; }
    }
}
