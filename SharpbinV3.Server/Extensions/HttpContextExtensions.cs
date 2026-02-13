using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.Services;

namespace SharpbinV3.Server.Extensions
{
    public static class HttpContextExtensions
    {
        public static readonly string[] ipHeaders =
        [
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",
            "True-Client-IP",
            "X-Cluster-Client-IP",
            "X-ProxyUser-IP",
        ];

        private const string ApiKeyContextKey = "ApiKey";

        public static string? GetApiKey(this HttpContext context)
        {
            var apiKeyHeader = context.Request.Headers["X-API-Key"].FirstOrDefault();
            if (string.IsNullOrEmpty(apiKeyHeader))
                return null;

            if (apiKeyHeader.Length != ApiKeyService.KeyLength)
                return null;

            return apiKeyHeader;
        }

        public static ApiKey? GetApiKeyFromContext(this HttpContext context)
        {
            if (context.Items.TryGetValue(ApiKeyContextKey, out var apiKey))
                return apiKey as ApiKey;

            return null;
        }

        public static void SetApiKeyContext(this HttpContext context, ApiKey apiKey)
        {
            context.Items[ApiKeyContextKey] = apiKey;
        }

        public static bool IsApiKeyAuthenticated(this HttpContext context)
        {
            return context.GetApiKeyFromContext() != null;
        }

        public static JwtUser? GetJwtUser(this HttpContext context)
        {
            if (context.User == null || !context.User.Identity?.IsAuthenticated == true)
                return null;

            var claims = context.User.Claims;

            var uuidClaim = claims.FirstOrDefault(c => c.Type == "uuid")?.Value;
            if (string.IsNullOrEmpty(uuidClaim) || !Guid.TryParse(uuidClaim, out var uuid))
                return null;

            var username = claims.FirstOrDefault(c => c.Type == "username")?.Value ?? "";
            var displayName = claims.FirstOrDefault(c => c.Type == "displayname")?.Value ?? "";
            var totpEnabled = claims.FirstOrDefault(c => c.Type == "totp_enabled")?.Value == "True";

            var roles = claims.Where(c => c.Type == ClaimTypes.Role).Select(c => int.TryParse(c.Value, out var r) ? r : 0).ToArray();

            var expClaim = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp)?.Value;
            var expires =
                expClaim != null && long.TryParse(expClaim, out var expUnix)
                    ? DateTimeOffset.FromUnixTimeSeconds(expUnix).UtcDateTime
                    : DateTime.UtcNow.AddMinutes(15);

            return new JwtUser
            {
                UUID = uuid,
                Username = username,
                DisplayName = displayName,
                TotpEnabled = totpEnabled,
                Roles = roles.Length > 0 ? roles : [0],
                Expires = expires,
            };
        }

        public static string GetRequestIP(this HttpContext context)
        {
            foreach (var header in ipHeaders)
            {
                if (context.Request.Headers.TryGetValue(header, out Microsoft.Extensions.Primitives.StringValues value))
                {
                    var ip = value.FirstOrDefault();
                    if (!string.IsNullOrEmpty(ip))
                        return ip.Split(',')[0].Trim();
                }
            }
            return context.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }
    }
}
