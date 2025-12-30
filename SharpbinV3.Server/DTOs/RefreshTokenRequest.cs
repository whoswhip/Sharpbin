using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.DTOs
{
    public class RefreshTokenRequest
    {
        [Required]
        public required string Token { get; set; }
        [Required]
        public required string RefreshToken { get; set; }
    }
}
