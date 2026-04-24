using SharpbinV3.Server.Data.Enums;
using SharpbinV3.Server.DTOs.User;

namespace SharpbinV3.Server.DTOs.Paste
{
    public class CreateCommentDto
    {
        public string Content { get; set; } = string.Empty;
        public long? ParentCommentID { get; set; }
    }

    public class ReactToCommentDto
    {
        public Interaction? Reaction { get; set; }
    }

    public class ReactToPasteDto
    {
        public Interaction? Reaction { get; set; }
    }

    public class CommentResponseDto
    {
        public long Id { get; set; }
        public long? ParentCommentID { get; set; }
        public string? Content { get; set; }
        public long StoredSize { get; set; }
        public long OriginalSize { get; set; }
        public bool IsCompressed { get; set; }
        public long CreatedAt { get; set; }
        public long? UpdatedAt { get; set; }
        public int Likes { get; set; }
        public int Dislikes { get; set; }
        public Interaction? UserReaction { get; set; }
        public UserSimpleDto? Author { get; set; }
    }

    public class CommentReactionResponseDto
    {
        public long CommentID { get; set; }
        public int Likes { get; set; }
        public int Dislikes { get; set; }
        public Interaction? UserReaction { get; set; }
    }

    public class PasteReactionResponseDto
    {
        public string PasteID { get; set; } = string.Empty;
        public int Likes { get; set; }
        public int Dislikes { get; set; }
        public Interaction? UserReaction { get; set; }
    }
}
