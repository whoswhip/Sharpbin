using System.Text.Json.Serialization;

namespace SharpbinV3.Server.DTOs.Auth
{
    public class TurnstileResponseDto
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }
        [JsonPropertyName("error-codes")]
        public string[]? ErrorCodes { get; set; }
    }
}
