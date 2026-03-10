using SharpbinV3.Server.Data.Enums;
using SharpbinV3.Server.DTOs.User;

namespace SharpbinV3.Server.DTOs.Paste
{
    public class PasteResponseDto
    {
        public string ID { get; set; } = string.Empty;
        public Guid UUID { get; set; }
        public long CreatedAt { get; set; }
        public string? Title { get; set; }
        public string? Syntax { get; set; }
        public long Size { get; set; }
        public long TrueSize { get; set; }
        public bool IsCompressed { get; set; }
        public int Views { get; set; }
        public Visibility Visibility { get; set; }
        public long? EditedAt { get; set; }
        public long ExpiresAt { get; set; }
        public int? ReportCount { get; set; }
        public UserSimpleDto? Author { get; set; }
    }

    public class PasteCreatedResponseDto
    {
        public string ID { get; set; } = string.Empty;
        public Guid UUID { get; set; }
        public long CreatedAt { get; set; }
        public bool IsCompressed { get; set; }
        public long Size { get; set; }
        public long TrueSize { get; set; }
        public long ExpiresAt { get; set; }
        public Visibility Visibility { get; set;}
    }

    public class PasteOptionsDto
    {
        public string[] Syntaxes { get; set; } = [];
        public List<PasteVisibilityOptionDto> Visibilities { get; set; } = [];
        public int MaxTitleLength { get; set; }
        public long MaxPasteSize { get; set; }
        public bool RequiresVerification { get; set; }
    }

    public class PasteVisibilityOptionDto
    {
        public int Value { get; set; }
        public string DisplayName { get; set; } = string.Empty;
    }
}
