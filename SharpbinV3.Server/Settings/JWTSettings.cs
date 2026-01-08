namespace SharpbinV3.Server.Settings
{
    public class JWTSettings
    {
        public string Secret { get; set; } = string.Empty;
        public string Issuer { get; set; } = "SharpbinApi";
        public string Audience { get; set; } = "SharpbinClient";
    }
}
