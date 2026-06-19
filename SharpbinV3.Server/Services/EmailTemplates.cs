using System.Reflection;

namespace SharpbinV3.Server.Services
{
    public static class EmailTemplates
    {
        private static readonly Assembly Assembly = Assembly.GetExecutingAssembly();
        private static readonly string BaseTemplateName = "SharpbinV3.Server.EmailTemplates.Base.html";

        private static string LoadEmbeddedResource(string resourceName)
        {
            using var stream = Assembly.GetManifestResourceStream(resourceName);
            if (stream == null)
                throw new FileNotFoundException($"Embedded resource not found: {resourceName}");

            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }

        private static string RenderTemplate(string title, string contentTemplate, Dictionary<string, string> replacements)
        {
            var baseTemplate = LoadEmbeddedResource(BaseTemplateName);
            var content = contentTemplate;

            foreach (var (key, value) in replacements)
            {
                content = content.Replace($"{{{{{key}}}}}", value);
            }

            return baseTemplate.Replace("{{TITLE}}", title).Replace("{{CONTENT}}", content);
        }

        public static string VerifyEmail(string verificationUrl, string username)
        {
            var contentTemplate = LoadEmbeddedResource("SharpbinV3.Server.EmailTemplates.VerifyEmail.html");
            var replacements = new Dictionary<string, string> { { "USERNAME", username }, { "VERIFICATION_URL", verificationUrl } };

            return RenderTemplate("Verify Your Email", contentTemplate, replacements);
        }

        public static string VerifyChangedEmail(string verificationUrl, string username)
        {
            var contentTemplate = LoadEmbeddedResource("SharpbinV3.Server.EmailTemplates.VerifyChangedEmail.html");
            var replacements = new Dictionary<string, string> { { "USERNAME", username }, { "VERIFICATION_URL", verificationUrl } };

            return RenderTemplate("Verify Your New Email", contentTemplate, replacements);
        }

        public static string EmailChangeRequested(string username, string oldEmail, string newEmail)
        {
            var contentTemplate = LoadEmbeddedResource("SharpbinV3.Server.EmailTemplates.EmailChangeRequested.html");
            var replacements = new Dictionary<string, string>
            {
                { "USERNAME", username },
                { "OLD_EMAIL", oldEmail },
                { "NEW_EMAIL", newEmail },
            };

            return RenderTemplate("Email Change Requested", contentTemplate, replacements);
        }

        public static string EmailChanged(string username, string oldEmail, string newEmail)
        {
            var contentTemplate = LoadEmbeddedResource("SharpbinV3.Server.EmailTemplates.EmailChanged.html");
            var replacements = new Dictionary<string, string>
            {
                { "USERNAME", username },
                { "OLD_EMAIL", oldEmail },
                { "NEW_EMAIL", newEmail },
            };

            return RenderTemplate("Email Address Changed", contentTemplate, replacements);
        }

        public static string ResetPassword(string username, string resetUrl)
        {
            var contentTemplate = LoadEmbeddedResource("SharpbinV3.Server.EmailTemplates.ResetPassword.html");
            var replacements = new Dictionary<string, string> { { "USERNAME", username }, { "RESET_URL", resetUrl } };

            return RenderTemplate("Reset Your Password", contentTemplate, replacements);
        }

        public static string PasswordChanged(string username)
        {
            var contentTemplate = LoadEmbeddedResource("SharpbinV3.Server.EmailTemplates.PasswordChanged.html");
            var replacements = new Dictionary<string, string> { { "USERNAME", username } };

            return RenderTemplate("Password Changed", contentTemplate, replacements);
        }

        public static string DeleteAccountVerification(string username, string deleteToken)
        {
            var contentTemplate = LoadEmbeddedResource("SharpbinV3.Server.EmailTemplates.DeleteAccountVerification.html");
            var replacements = new Dictionary<string, string> { { "USERNAME", username }, { "DELETE_TOKEN", deleteToken } };

            return RenderTemplate("Confirm Account Deletion", contentTemplate, replacements);
        }

        public static string AccountDeleted(string username)
        {
            var contentTemplate = LoadEmbeddedResource("SharpbinV3.Server.EmailTemplates.AccountDeleted.html");
            var replacements = new Dictionary<string, string> { { "USERNAME", username } };

            return RenderTemplate("Account Deleted", contentTemplate, replacements);
        }
    }
}
