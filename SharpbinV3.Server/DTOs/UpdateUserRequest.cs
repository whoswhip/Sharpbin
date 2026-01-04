using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SharpbinV3.Server.DTOs
{
    public partial class UpdateUserRequest
    {
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
        public int? Visibility { get; set; } = 0;

        public IEnumerable<ValidationResult> Validate()
        {
            var results = new List<ValidationResult>();
            if (DisplayName != null)
            {
                if (DisplayName.Length < 3 || DisplayName.Length > 26)
                    results.Add(new ValidationResult("DisplayName must be between 3 and 26 characters.", [nameof(DisplayName)]));
                if (!ValidateDisplayname().IsMatch(DisplayName))
                    results.Add(new ValidationResult("DisplayName can only contain letters, numbers, underscores, and dots.", [nameof(DisplayName)]));
            }
            if (Email != null)
            {
                var emailAttribute = new EmailAddressAttribute();
                if (!emailAttribute.IsValid(Email))
                    results.Add(new ValidationResult("Invalid email format.", [nameof(Email)]));
            }
            if (Visibility != null)
            {
                if (Visibility < 0 || Visibility > 2)
                    results.Add(new ValidationResult("Visibility must be between 0 and 2.", [nameof(Visibility)]));
            }
            return results;
        }

        [GeneratedRegex("^[A-Za-z0-9_.]+$")]
        private static partial Regex ValidateDisplayname();
    }
}
