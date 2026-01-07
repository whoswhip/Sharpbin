using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.DTOs.User
{
    public class LoginUserDto
    {
        [StringLength(50, MinimumLength = 3)]
        public string? Username { get; set; }
        public string? Email { get; set; }
        [StringLength(128, MinimumLength = 6)]
        public string? Password { get; set; }
        public string? Token { get; set; }
        public string? TotpCode { get; set; }
    }
}
