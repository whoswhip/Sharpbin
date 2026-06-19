using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.DTOs.Auth
{
    public sealed class PasswordResetDto
    {
        [Required]
        public string Token { get; set; } = string.Empty;

        [Required]
        [StringLength(128, MinimumLength = 8)]
        public string NewPassword { get; set; } = string.Empty;

        public string? TotpCode { get; set; }
    }
}
