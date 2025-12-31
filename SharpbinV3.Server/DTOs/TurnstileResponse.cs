using System.Text.Json.Serialization;

namespace SharpbinV3.Server.DTOs
{
    public class TurnstileResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }
        [JsonPropertyName("error-codes")]
        public string[]? ErrorCodes { get; set; }
    }
}
