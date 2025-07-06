namespace SharpbinV2.Server.Models
{
    public class Session
    {
        public string? UUID { get; set; }
        public string? UserUUID { get; set; }
        public string? Token { get; set; }
        public long? Created { get; set; }
        public long? Expirary { get; set; }
        public string? Ip { get; set; }
        public string? UserAgent { get; set; }
    }
}
