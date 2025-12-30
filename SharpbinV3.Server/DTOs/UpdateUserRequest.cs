using System.ComponentModel.DataAnnotations;

namespace SharpbinV3.Server.DTOs
{
    public class UpdateUserRequest
    {
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
        public int? Visibility { get; set; } = 0;

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            var results = new List<ValidationResult>();
            if (DisplayName != null) {
                if (DisplayName.Length < 3 || DisplayName.Length > 26)
                {
                    results.Add(new ValidationResult("DisplayName must be between 3 and 50 characters.", [nameof(DisplayName)]));
                }
            }
            if (Email != null)
            {
                var emailAttribute = new EmailAddressAttribute();
                if (!emailAttribute.IsValid(Email))
                {
                    results.Add(new ValidationResult("Invalid email format.", [nameof(Email)]));
                }
            }
            if (Visibility != null)
            {
                if (Visibility < 0 || Visibility > 2)
                {
                    results.Add(new ValidationResult("Visibility must be between 0 and 2.", [nameof(Visibility)]));
                }
            }
            return results;
        }
    }
}
