namespace SharpbinV2.Server.Models
{
    public class PasswordReset
    {
        public string? UID { get; set; }
        public string? UUID { get; set; }
        public string? USERUUID { get; set; }
        public string? URL { get; set; }
        public string? Token { get; set; }
        public long? Created { get; set; }
        public long? Expirary { get; set; }
    }
}
