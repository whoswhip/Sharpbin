using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using SharpbinV3.Server.Extensions;

namespace SharpbinV3.Server.Authorization
{
    public sealed class NotBannedHandler(bool requireAuth = false) : AuthorizationHandler<NotBannedRequirement>
    {
        private readonly bool _requireAuth = requireAuth;

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, NotBannedRequirement requirement)
        {
            var httpContext = context.Resource as HttpContext;
            var isAuthenticated = context.User.Identity?.IsAuthenticated ?? false;

            if (!isAuthenticated && httpContext != null)
            {
                var apiKey = httpContext.GetApiKeyFromContext();
                if (apiKey != null)
                {
                    isAuthenticated = true;
                }
            }

            if (_requireAuth && !isAuthenticated)
                return Task.CompletedTask;

            var isBanned = context.User.Claims.Any(c => (c.Type == ClaimTypes.Role || c.Type == "role") && c.Value == "403");

            if (httpContext?.GetApiKeyFromContext()?.User?.Roles?.Contains(403) == true)
                isBanned = true;

            if (!isBanned)
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}
