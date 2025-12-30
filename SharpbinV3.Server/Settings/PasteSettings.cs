namespace SharpbinV3.Server.Settings
{
    public class PasteSettings
    {
        public string[] ValidSyntaxLanguages { get; set; } = [];
        public int MaxTitleLength { get; set; } = 500;
        public int MaxPasteSizeInBytes { get; set; } = 1_048_576; // 1 MB
    }
}
