using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.Settings
{
    public class PasteSettings
    {
        public HashSet<string> ValidSyntaxLanguages { get; set; } = [];
        public int MaxTitleLength { get; set; } = 500;
        public int MaxPasteSizeInBytes { get; set; } = 1_048_576; // 1 MB
        public bool EnablePasteCompression { get; set; } = true;
        public bool RequiresVerification { get; set; } = true;
        [Required, MinLength(32), MaxLength(128)]
        public string View_HMAC_Secret { get; set; } = string.Empty;
        [MinLength(32), MaxLength(128)]
        public string View_Internal_API_Key { get; set; } = string.Empty;
    }
}
