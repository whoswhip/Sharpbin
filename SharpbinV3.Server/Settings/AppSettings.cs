using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Settings
{
    public class AppSettings
    {
        [Required, MaxLength(256)]
        public string Domain { get; set; } = string.Empty;
        public bool Https { get; set; } = true;
    }
}
