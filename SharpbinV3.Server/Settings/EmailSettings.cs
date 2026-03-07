using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Settings
{
    public class EmailSettings
    {
        [MaxLength(256)]
        public string Host { get; set; } = string.Empty;

        [Range(1, 65535)]
        public int Port { get; set; } = 587;

        [MaxLength(256)]
        public string User { get; set; } = string.Empty;

        [MaxLength(256)]
        public string Password { get; set; } = string.Empty;

        [EmailAddress]
        public string? From { get; set; }
        public string Verification_HMAC_Secret { get; set; } = string.Empty;
    }
}
