using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Services;

namespace SharpbinV3.Server.Middleware
{
    public sealed class ApiKeyAuthenticationMiddleware(RequestDelegate next)
    {
        private readonly RequestDelegate _next = next;

        public async Task InvokeAsync(HttpContext context, ApiKeyService apiKeyService)
        {
            var apiKeyString = context.GetApiKey();
            if (!string.IsNullOrEmpty(apiKeyString))
            {
                var apiKey = await apiKeyService.GetByKeyAsync(apiKeyString);
                if (apiKey != null)
                {
                    context.SetApiKeyContext(apiKey);
                    await apiKeyService.UpdateLastUsedAsync(apiKey.UUID);
                }
            }

            await _next(context);
        }
    }
}
