namespace SharpbinV3.Server.Settings
{
    public class AuthSettings
    {
        public string CF_Turnstile_SiteKey { get; set; } = string.Empty;
        public string CF_Turnstile_SecretKey { get; set; } = string.Empty;
        public bool Registration_Enabled { get; set; } = true;
        public bool First_User_Admin { get; set; } = true;
        public bool Admins_Require_2FA { get; set; } = true;
        public string API_Key_HMAC_Secret { get; set; } = string.Empty;
        public string Email_Verification_HMAC_Secret { get; set; } = string.Empty;
    }
}
