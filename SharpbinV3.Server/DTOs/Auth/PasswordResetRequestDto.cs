using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.DTOs.Auth
{
    public sealed class PasswordResetRequestDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        public string? Token { get; set; }
    }
}
