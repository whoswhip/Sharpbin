namespace SharpbinV3.Server.DTOs.User
{
    public class DeleteUserDto
    {
        public string? Token { get; set; }
        public string? TotpCode { get; set; }
    }
}
