namespace SharpbinV2.Server
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
    public class Paste
    {
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
    public class RequestDetails
    {
        public string? Ip { get; set; }
        public string? UserAgent { get; set; }
        public string? Token { get; set; }
    }
    public class View
    {
        public string? UUID { get; set; }
        public string? PasteUUID { get; set; }
        public string? UserUUID { get; set; }
        public string? IP { get; set; }
        public string? UserAgent { get; set; }
        public long? Created { get; set; }
    }
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
