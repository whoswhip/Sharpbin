using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using SharpbinV3.Server.Data.Enums;

namespace SharpbinV3.Server.Data.Entities
{
    [Index(nameof(CommentID), nameof(UserUUID), IsUnique = true)]
    [Index(nameof(CommentID), nameof(Type))]
    public class CommentInteraction
    {
        [Key]
        public long Id { get; set; }
        public long CommentID { get; set; }
        public Guid UserUUID { get; set; }
        public long CreatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        public Interaction Type { get; set; }

        public Comment Comment { get; set; } = null!;
    }
}
