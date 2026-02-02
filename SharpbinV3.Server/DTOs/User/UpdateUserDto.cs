using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SharpbinV3.Server.DTOs
{
    public partial class UpdateUserDto : IValidatableObject
    {
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
        public int? Visibility { get; set; } = 0;
        public int[]? Roles { get; set; }
        public string? TotpCode { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            var results = new List<ValidationResult>();
            if (DisplayName != null && DisplayName.Length > 0)
            {
                if (DisplayName.Length < 3 || DisplayName.Length > 26)
                    results.Add(new ValidationResult("DisplayName must be between 3 and 26 characters.", [nameof(DisplayName)]));
                if (!ValidateDisplayname().IsMatch(DisplayName))
                    results.Add(new ValidationResult("DisplayName can only contain alphanumeric characters, underscores, periods, and spaces (no leading or trailing spaces).", [nameof(DisplayName)]));
            }
            if (Email != null && Email.Length > 0)
            {
                var emailAttribute = new EmailAddressAttribute();
                if (!emailAttribute.IsValid(Email))
                    results.Add(new ValidationResult("Invalid email format.", [nameof(Email)]));
            }
            if (Visibility != null && Visibility.HasValue)
            {
                if (Visibility < 0 || Visibility > 2)
                    results.Add(new ValidationResult("Visibility must be between 0 and 2.", [nameof(Visibility)]));
            }
            if (Roles != null && Roles.Length > 0)
            {
                if (Roles.Length == 0)
                    results.Add(new ValidationResult("Roles cannot be an empty array.", [nameof(Roles)]));
                int[] validRoles = [0, 1, 255, 403];
                foreach (var role in Roles)
                {
                    if (!validRoles.Contains(role))
                        results.Add(new ValidationResult($"Invalid role: {role}.", [nameof(Roles)]));
                }

            }
            return results;
        }

        [GeneratedRegex("^[A-Za-z0-9_.]+(?: [A-Za-z0-9_.]+)*$")]
        private static partial Regex ValidateDisplayname();
    }
}
