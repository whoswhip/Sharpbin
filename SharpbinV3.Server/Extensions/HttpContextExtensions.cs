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

        public static readonly string[] BotUserAgents =
        [
            "bot",
            "crawl",
            "spider",
            "slurp",
            "mediapartners-google",
            "adsbot-google",
            "googlebot",
            "bingbot",
            "yandexbot",
            "duckduckbot",
            "baiduspider",
            "sogou",
            "exabot",
            "facebot",
            "ia_archiver",
        ];

        private const string ApiKeyContextKey = "ApiKey";

        private static string? GetClaimValue(IEnumerable<Claim> claims, params string[] claimTypes)
        {
            foreach (var claimType in claimTypes)
            {
                var value = claims.FirstOrDefault(c => c.Type == claimType)?.Value;
                if (!string.IsNullOrEmpty(value))
                    return value;
            }

            return null;
        }

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

            var claims = context.User.Claims.ToArray();

            var uuidClaim = GetClaimValue(claims, "uuid");
            if (string.IsNullOrEmpty(uuidClaim) || !Guid.TryParse(uuidClaim, out var uuid))
                return null;

            var username = GetClaimValue(claims, "username") ?? "";
            var displayName = GetClaimValue(claims, "displayname") ?? "";
            var totpEnabled = bool.TryParse(GetClaimValue(claims, "totp_enabled"), out var parsedTotpEnabled) && parsedTotpEnabled;
            var isBanned = bool.TryParse(GetClaimValue(claims, "is_banned"), out var parsedIsBanned) && parsedIsBanned;
            var rolesClaim = GetClaimValue(claims, "roles", "role", ClaimTypes.Role);
            var roles = int.TryParse(rolesClaim, out var roleInt) ? (Role)roleInt : Role.User;

            var expClaim = GetClaimValue(claims, JwtRegisteredClaimNames.Exp, ClaimTypes.Expiration, "exp");
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
                Roles = roles,
                IsBanned = isBanned,
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

        public static bool IsKnownBot(this HttpContext context)
        {
            var userAgent = context.Request.Headers.UserAgent.FirstOrDefault()?.ToLower() ?? "";
            return BotUserAgents.Any(userAgent.Contains);
        }
    }
}
