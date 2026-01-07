namespace SharpbinV3.Server.DTOs.Auth
{
    public sealed class EnableTotpDto
    {
        public string Secret { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
    }
}
