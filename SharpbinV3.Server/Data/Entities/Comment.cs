using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SharpbinV3.Server.Data.Entities
{
    public class Comment
    {
        [Key]
        public long Id { get; set; }
        public long PastePID { get; set; }
        public long? ParentCommentID { get; set; }

        [MaxLength(5000)]
        public byte[]? Content { get; set; } = null!; // compressed & decompressed server side, if deleted then null
        public long StoredSize { get; set; }
        public long OriginalSize { get; set; }
        public bool IsCompressed { get; set; } = false;

        public Guid UserUUID { get; set; }
        public long CreatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        public long? UpdatedAt { get; set; }

        public Paste Paste { get; set; } = null!;
        public User User { get; set; } = null!;
        public Comment? ParentComment { get; set; }
        public List<CommentInteraction> Interactions { get; set; } = [];
        public List<Comment> Replies { get; set; } = [];
        public List<Report> Reports { get; set; } = [];

        [NotMapped]
        public int PositiveInteractionCount { get; set; }

        [NotMapped]
        public int NegativeInteractionCount { get; set; }
    }
}
