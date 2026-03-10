using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.Data.Enums;

namespace SharpbinV3.Server.DTOs
{
    public partial class UpdateUserDto : IValidatableObject
    {
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
        public Visibility? Visibility { get; set; } = Data.Enums.Visibility.Public;
        public Role? Roles { get; set; }
        public bool? IsBanned { get; set; }
        public string? TotpCode { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            var results = new List<ValidationResult>();
            if (DisplayName != null && DisplayName.Length > 0)
            {
                if (DisplayName.Length < 3 || DisplayName.Length > 26)
                    results.Add(new ValidationResult("DisplayName must be between 3 and 26 characters.", [nameof(DisplayName)]));
                if (!ValidateDisplayname().IsMatch(DisplayName))
                    results.Add(
                        new ValidationResult(
                            "DisplayName can only contain alphanumeric characters, underscores, periods, and spaces (no leading or trailing spaces).",
                            [nameof(DisplayName)]
                        )
                    );
            }
            if (Email != null && Email.Length > 0)
            {
                var emailAttribute = new EmailAddressAttribute();
                if (!emailAttribute.IsValid(Email))
                    results.Add(new ValidationResult("Invalid email format.", [nameof(Email)]));
            }
            if (Visibility != null && Visibility.HasValue)
            {
                if (!Enum.IsDefined(typeof(Visibility), Visibility.Value))
                    results.Add(new ValidationResult($"Invalid visibility: {Visibility.Value}.", [nameof(Visibility)]));
            }
            if (Roles != null && Roles.HasValue)
            {
                int validBits = Enum.GetValues(typeof(Role)).Cast<Role>().Aggregate(0, (acc, role) => acc | (int)role);
                if ((((int)Roles.Value) & validBits) != (int)Roles.Value || Roles.Value == 0)
                    results.Add(new ValidationResult($"Invalid role: {Roles.Value}.", [nameof(Roles)]));
            }
            return results;
        }

        [GeneratedRegex("^[A-Za-z0-9_.]+(?: [A-Za-z0-9_.]+)*$")]
        private static partial Regex ValidateDisplayname();
    }
}
