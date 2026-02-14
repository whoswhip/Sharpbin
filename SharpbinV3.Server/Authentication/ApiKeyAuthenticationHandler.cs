using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Services;

namespace SharpbinV3.Server.Authentication
{
    public sealed class ApiKeyAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ApiKeyService apiKeyService
    ) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        private readonly ApiKeyService _apiKeyService = apiKeyService;

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var apiKeyString = Context.GetApiKey();
            if (string.IsNullOrEmpty(apiKeyString))
                return AuthenticateResult.NoResult();

            var apiKey = await _apiKeyService.GetByKeyAsync(apiKeyString);
            if (apiKey == null || apiKey.User == null)
                return AuthenticateResult.Fail("Invalid API key.");

            var claims = new List<Claim>
            {
                new("uuid", apiKey.User.UUID.ToString()),
                new("username", apiKey.User.Username ?? ""),
                new("displayname", apiKey.User.DisplayName ?? ""),
                new("totp_enabled", (apiKey.User.Totp != null).ToString()),
            };

            if (apiKey.User.Roles != null)
                claims.AddRange(apiKey.User.Roles.Select(r => new Claim(ClaimTypes.Role, r.ToString())));

            var identity = new ClaimsIdentity(claims, AuthSchemes.ApiKey);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, AuthSchemes.ApiKey);

            Context.SetApiKeyContext(apiKey);
            await _apiKeyService.UpdateLastUsedAsync(apiKey.UUID);

            return AuthenticateResult.Success(ticket);
        }
    }
}
