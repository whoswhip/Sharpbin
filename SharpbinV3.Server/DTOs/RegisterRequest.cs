using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SharpbinV3.Server.DTOs
{
    public partial class RegisterRequest
    {
        [Required]
        [StringLength(50, MinimumLength = 3)]
        public required string Username { get; set; }

        [Required]
        [StringLength(128, MinimumLength = 6)]
        public required string Password { get; set; }

        public string? Email { get; set; }

        public string? DisplayName { get; set; }
        public string? Token { get; set; }

        public IEnumerable<ValidationResult> Validate()
        {
            var results = new List<ValidationResult>();
            if (!ValidateUsername().IsMatch(Username))
                results.Add(new ValidationResult("Username can only contain letters, numbers, underscores, and dots.", [nameof(Username)]));

            if (DisplayName != null)
            {
                if (DisplayName.Length < 3 || DisplayName.Length > 26)
                    results.Add(new ValidationResult("DisplayName must be between 3 and 26 characters.", [nameof(DisplayName)]));
                if (!ValidateUsername().IsMatch(DisplayName))
                    results.Add(new ValidationResult("DisplayName can only contain letters, numbers, underscores, and dots.", [nameof(DisplayName)]));
            }
            if (Email != null)
            {
                var emailAttribute = new EmailAddressAttribute();
                if (!emailAttribute.IsValid(Email))
                    results.Add(new ValidationResult("Invalid email format.", [nameof(Email)]));
            }
            return results;
        }

        [GeneratedRegex("^[A-Za-z0-9_.]+$")]
        private static partial Regex ValidateUsername();
    }
}
