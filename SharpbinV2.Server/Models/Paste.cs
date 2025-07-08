namespace SharpbinV2.Server.Models
{
    public class Paste
    {
        public int UID { get; set; }
        public string? UUID { get; set; }
        public string? ID { get; set; }
        public int? Visibility { get; set; }
        public string? Title { get; set; }
        public string? AuthorUUID { get; set; }
        public string? FilePath { get; set; }
        public long? Created { get; set; }
        public long? Edited { get; set; }
        public int? Size { get; set; }
        public int? TrueSize { get; set; }
        public int? Views { get; set; }
        public string? Syntax { get; set; }
    }
}
