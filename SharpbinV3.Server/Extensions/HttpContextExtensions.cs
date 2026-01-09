using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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

        public static JwtUser? GetJwtUser(this HttpContext context)
        {
            if (context.User == null || !context.User.Identity?.IsAuthenticated == true)
                return null;

            var claims = context.User.Claims;

            var uuidClaim = claims.FirstOrDefault(c => c.Type == "UUID")?.Value;
            if (string.IsNullOrEmpty(uuidClaim) || !Guid.TryParse(uuidClaim, out var uuid))
                return null;

            var username = claims.FirstOrDefault(c => c.Type == "Username")?.Value ?? "";
            var displayName = claims.FirstOrDefault(c => c.Type == "DisplayName")?.Value ?? "";
            var totpEnabled = claims.FirstOrDefault(c => c.Type == "TOTP_Enabled")?.Value == "True";

            var roles = claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => int.TryParse(c.Value, out var r) ? r : 0)
                .ToArray();

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
                if (
                    context.Request.Headers.TryGetValue(
                        header,
                        out Microsoft.Extensions.Primitives.StringValues value
                    )
                )
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
