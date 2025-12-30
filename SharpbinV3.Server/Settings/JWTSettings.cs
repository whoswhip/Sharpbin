namespace SharpbinV3.Server.Settings
{
    public class JWTSettings
    {
        public string Secret { get; set; } = Utilities.GenerateRandomString(64);
        public string Issuer { get; set; } = "SharpbinApi";
        public string Audience { get; set; } = "SharpbinClient";
    }
}
