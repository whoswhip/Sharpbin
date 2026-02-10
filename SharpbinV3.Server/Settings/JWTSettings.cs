using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Settings
{
    public class JWTSettings
    {
        [Required, MinLength(32), MaxLength(128)]
        public string Secret { get; set; } = string.Empty;

        [Required, MaxLength(128)]
        public string Issuer { get; set; } = "SharpbinApi";

        [Required, MaxLength(128)]
        public string Audience { get; set; } = "SharpbinClient";
    }
}
