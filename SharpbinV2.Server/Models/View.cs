namespace SharpbinV2.Server.Models
{
    public class View
    {
        public string? UUID { get; set; }
        public string? PasteUUID { get; set; }
        public string? UserUUID { get; set; }
        public string? Fingerprint { get; set; }
        public string? UserAgent { get; set; }
        public long? Created { get; set; }
    }
}
