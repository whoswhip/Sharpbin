namespace SharpbinV2.Server.Models
{
    public class User
    {
        public int? UID { get; set; }
        public string? UUID { get; set; }
        public int? Type { get; set; }
        public string? Email { get; set; }
        public string? Username { get; set; }
        public string? DisplayName { get; set; }
        public string? Password { get; set; }
        public long? Created { get; set; }
        public long? LastLogin { get; set; }
    }
}
