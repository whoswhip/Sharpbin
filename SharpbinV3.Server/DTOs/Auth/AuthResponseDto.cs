namespace SharpbinV3.Server.DTOs.Auth
{
    public class LoginResponseDto
    {
        public bool Success { get; set; }
        public string Token { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
    }

    public class TokenRefreshResponseDto
    {
        public bool Success { get; set; }
        public string? Message { get; set; }
        public TokenData? Token { get; set; }
    }

    public class TokenData
    {
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
    }
}
