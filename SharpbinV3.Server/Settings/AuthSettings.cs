namespace SharpbinV3.Server.Settings
{
    public class AuthSettings
    {
        public string CF_Turnstile_SiteKey { get; set; } = string.Empty;
        public string CF_Turnstile_SecretKey { get; set; } = string.Empty;
        public bool Registration_Enabled { get; set; } = true;
    }
}
