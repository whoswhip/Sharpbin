using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace SharpbinV3.Server.Authorization
{
    public sealed class NotBannedHandler(bool requireAuth = false)
        : AuthorizationHandler<NotBannedRequirement>
    {
        private readonly bool _requireAuth = requireAuth;

        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            NotBannedRequirement requirement
        )
        {
            var isAuthenticated = context.User.Identity?.IsAuthenticated ?? false;

            if (_requireAuth && !isAuthenticated)
                return Task.CompletedTask;

            var isBanned = context.User.Claims.Any(c =>
                (c.Type == ClaimTypes.Role || c.Type == "role") && c.Value == "403"
            );

            if (!isBanned)
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}
