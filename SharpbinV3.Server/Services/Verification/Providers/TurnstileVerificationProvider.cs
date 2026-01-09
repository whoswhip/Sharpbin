using System.Text.Json;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.DTOs.Auth;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server.Services.Verification.Providers
{
    public sealed class TurnstileVerificationProvider(
        IOptions<AuthSettings> options,
        HttpClient httpClient
    ) : IVerificationProvider
    {
        private readonly AuthSettings _authSettings = options.Value;
        private const string SiteverifyUrl =
            "https://challenges.cloudflare.com/turnstile/v0/siteverify";

        public int Priority => 1;
        public bool IsConfigured =>
            !string.IsNullOrEmpty(_authSettings.CF_Turnstile_SecretKey)
            && !string.IsNullOrEmpty(_authSettings.CF_Turnstile_SiteKey);

        public async Task<bool> VerifyAsync(VerificationContext ctx)
        {
            if (_authSettings.CF_Turnstile_SecretKey is null)
                throw new InvalidOperationException("Turnstile secret key is not configured.");
            if (string.IsNullOrEmpty(ctx.Token))
                return false;

            var parameters = new Dictionary<string, string>
            {
                { "secret", _authSettings.CF_Turnstile_SecretKey },
                { "response", ctx.Token },
            };

            if (!string.IsNullOrEmpty(ctx.Ip))
                parameters.Add("remoteip", ctx.Ip);

            var postContent = new FormUrlEncodedContent(parameters);

            var response = await httpClient.PostAsync(SiteverifyUrl, postContent);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<TurnstileResponseDto>(json);
            return result?.Success ?? false;
        }
    }
}
