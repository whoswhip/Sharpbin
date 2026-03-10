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
    }
}
