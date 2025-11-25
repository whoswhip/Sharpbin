using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.DTOs
{
    public class RegisterRequest
    {
        [Required]
        [StringLength(50, MinimumLength = 3)]
        public required string Username { get; set; }

        [Required]
        [StringLength(128, MinimumLength = 6)]
        public required string Password { get; set; }

        [EmailAddress]
        public string? Email { get; set; }

        public string? DisplayName { get; set; }
    }
}
