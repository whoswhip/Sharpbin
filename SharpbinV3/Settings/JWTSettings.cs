namespace SharpbinV3.Server.Settings
{
    public class JWTSettings
    {
        public string SecretKey { get; set; } = Utilities.GenerateRandomString(64);
        public string Issuer { get; set; } = "SharpbinV3";
        public string Audience { get; set; } = "SharpbinV3.Client";
    }
}
