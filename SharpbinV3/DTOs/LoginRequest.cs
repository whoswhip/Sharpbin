using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.DTOs
{
    public class LoginRequest
    {
        [StringLength(50, MinimumLength = 3)]
        public string? Username { get; set; }
        [EmailAddress]
        public string? Email { get; set; }
        [StringLength(128, MinimumLength = 6)]
        public string? Password { get; set; }
    }
}
