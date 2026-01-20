using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs.Paste;
using SharpbinV3.Server.DTOs.Report;
using SharpbinV3.Server.DTOs.User;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Services;
using SharpbinV3.Server.Services.Verification;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PasteController(PasteService pasteService, VerificationService verificationService, AuthService authService,
        ReportService reportService, IOptions<PasteSettings> options, IOptions<AuthSettings> authSettings) : ControllerBase
    {
        private readonly PasteService _pasteService = pasteService;
        private readonly VerificationService _verificationService = verificationService;
        private readonly AuthService _authService = authService;
        private readonly ReportService _reportService = reportService;
        private readonly PasteSettings _pasteSettings = options.Value;
        private readonly AuthSettings _authSettings = authSettings.Value;

        [HttpPost]
        [Route("create")]
        [Authorize(Policy = "NotBanned")]
        [EnableRateLimiting("Strict")]
        public async Task<IActionResult> CreatePaste(string title = "", string syntax = "plaintext", int visibility = 0, long expiresAt = 0, string? token = null)
        {
            if (!await _pasteService.ValidateExpiresAt(expiresAt))
                return BadRequest(new { success = false, message = "Invalid expiration time." });
            if (!await _pasteService.ValidateVisibility(visibility))
                return BadRequest(new { success = false, message = "Invalid visibility level. Must be between 0 and 2." });
            if (!await _pasteService.ValidateSyntax(syntax))
                return BadRequest(new { success = false, message = "Invalid syntax." });
            if (!await _pasteService.ValidateTitle(title))
                return BadRequest(new { success = false, message = $"Invalid title. Must be less than {_pasteSettings.MaxTitleLength} characters." });

            string content = await new StreamReader(Request.Body).ReadToEndAsync();
            if (content.Length == 0)
                return BadRequest(new { success = false, message = "Paste content cannot be empty." });
            if (System.Text.Encoding.UTF8.GetByteCount(content) > _pasteSettings.MaxPasteSizeInBytes)
                return BadRequest(new { success = false, message = $"Paste size exceeds the maximum allowed size of {_pasteSettings.MaxPasteSizeInBytes} bytes." });

            if (_pasteSettings.RequiresVerfication && !await _verificationService.VerifyAsync(new VerificationContext
            {
                Token = token,
                Ip = HttpContext.GetRequestIP()
            }))
                return BadRequest(new { success = false, message = "Verification failed." });

            var user = await _authService.GetUserFromHttpContext(HttpContext);
            Paste paste = await _pasteService.Create(user, content, title, syntax, visibility, expiresAt, _pasteSettings.EnablePasteCompression);
            return Ok(new PasteCreatedResponseDto
            {
                ID = paste.ID,
                UUID = paste.UUID,
                IsCompressed = paste.IsCompressed,
                Size = paste.Size,
                TrueSize = paste.TrueSize,
                ExpiresAt = paste.ExpiresAt
            });
        }

        [HttpGet]
        [Route("{id}")]
        public async Task<IActionResult> GetPasteByID(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found" });
            var jwtUser = HttpContext.GetJwtUser();

            int? reportCount = null;
            if (jwtUser != null && jwtUser.Roles.Any(r => r == 1 || r == 255))
            {
                var query = new ReportQuery
                {
                    PastePID = paste.PID
                };
                reportCount = await _reportService.GetReportCount(query);
            }

            return Ok(new
            {
                success = true,
                paste = new PasteResponseDto
                {
                    ID = paste.ID,
                    UUID = paste.UUID,
                    Title = paste.Title,
                    Size = paste.Size,
                    TrueSize = paste.TrueSize,
                    IsCompressed = paste.IsCompressed,
                    Views = paste.Views,
                    Syntax = paste.Syntax,
                    Visibility = paste.Visibility,
                    ExpiresAt = paste.ExpiresAt,
                    EditedAt = paste.EditedAt,
                    ReportCount = reportCount,
                    Author = paste.User != null && paste.User.Visibility == 0 ? new UserSimpleDto
                    {
                        UID = paste.User.UID,
                        UUID = paste.User.UUID,
                        Username = paste.User.Username,
                        DisplayName = paste.User.DisplayName,
                        Visibility = paste.User.Visibility,
                        Roles = paste.User.Roles
                    } : null
                }
            });
        }

        [HttpGet]
        [Route("{id}/raw")]
        public async Task<IActionResult> GetRawPasteByID(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null) return NotFound();
            if (paste.IsCompressed)
                Response.Headers.Append("Content-Encoding", "gzip");

            return File(paste.Content, "text/plain; charset=utf-8");
        }

        [HttpPut]
        [Route("{id}")]
        [Authorize(Policy = "AuthAndNotBanned")]
        public async Task<IActionResult> EditPaste(string id)
        {
            string content = await new StreamReader(Request.Body).ReadToEndAsync();
            if (content == null || id == null)
                return StatusCode(400, new { success = false, message = "Invalid request." });

            var paste = await _pasteService.Get(id);
            if (paste == null)
                return StatusCode(404, new { success = false, message = "Paste not found." });

            var user = HttpContext.GetJwtUser();
            if (user == null)
                return Unauthorized(new { success = false, message = "Invalid token." });

            var hasPrivilegedRole = user.Roles.Any(r => r == 1 || r == 255);
            if (paste.AuthorUUID != user.UUID && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to edit this paste." });
            if (user.Roles.Contains(255) && !user.TotpEnabled && _authSettings.Admins_Require_2FA)
                return StatusCode(403, new { success = false, message = "2FA is required to perform this action." });

            bool result = await _pasteService.EditText(paste, content);
            if (!result) return StatusCode(500, new { success = false, message = "An error occurred while editing the paste." });
            return Ok(new { message = "Paste edited successfully." });
        }

        [HttpPatch]
        [Route("{id}")]
        [Authorize(Policy = "AuthAndNotBanned")]
        public async Task<IActionResult> ModifyPasteMetadata(string id, [FromBody] UpdatePasteDto request)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found." });

            var user = HttpContext.GetJwtUser();
            if (user == null)
                return Unauthorized(new { success = false, message = "Invalid token." });

            var hasPrivilegedRole = user.Roles.Any(r => r == 1 || r == 255);

            if (paste.AuthorUUID != user.UUID && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to modify this paste." });
            if (user.Roles.Contains(255) && !user.TotpEnabled && _authSettings.Admins_Require_2FA)
                return StatusCode(403, new { success = false, message = "2FA is required to perform this action." });
            if (request.Title != null)
                paste.Title = request.Title;
            if (request.Syntax != null)
                paste.Syntax = request.Syntax;
            if (request.Visibility.HasValue)
                paste.Visibility = request.Visibility.Value;
            if (request.ExpiresAt.HasValue)
                paste.ExpiresAt = request.ExpiresAt.Value;

            if (!await _pasteService.ValidateExpiresAt(paste.ExpiresAt))
                return BadRequest(new { success = false, message = "Invalid expiration time." });
            if (!await _pasteService.ValidateVisibility(paste.Visibility))
                return BadRequest(new { success = false, message = "Invalid visibility level. Must be between 0 and 2." });
            if (!await _pasteService.ValidateSyntax(paste.Syntax ?? "plaintext"))
                return BadRequest(new { success = false, message = "Invalid syntax." });
            if (!await _pasteService.ValidateTitle(paste.Title ?? ""))
                return BadRequest(new { success = false, message = $"Invalid title. Must be less than {_pasteSettings.MaxTitleLength} characters." });

            var newPaste = await _pasteService.Edit(paste);
            return Ok(new
            {
                success = true,
                message = "Paste metadata updated successfully.",
                paste = new PasteResponseDto
                {
                    ID = newPaste.ID,
                    UUID = newPaste.UUID,
                    Title = newPaste.Title,
                    Size = newPaste.Size,
                    TrueSize = newPaste.TrueSize,
                    IsCompressed = newPaste.IsCompressed,
                    Views = newPaste.Views,
                    Syntax = newPaste.Syntax,
                    Visibility = newPaste.Visibility,
                    ExpiresAt = newPaste.ExpiresAt
                }
            });
        }

        [HttpDelete]
        [Route("{id}")]
        [Authorize(Policy = "AuthAndNotBanned")]
        public async Task<IActionResult> DeletePaste(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null) return NotFound(new { success = false, message = "Paste not found." });

            var user = HttpContext.GetJwtUser();
            if (user == null)
                return Unauthorized(new { success = false, message = "Invalid token." });

            var hasPrivilegedRole = user.Roles.Any(r => r == 1 || r == 255);
            if (paste.AuthorUUID != user.UUID && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to delete this paste." });
            if (user.Roles.Contains(255) && !user.TotpEnabled && _authSettings.Admins_Require_2FA)
                return StatusCode(403, new { success = false, message = "2FA is required to perform this action." });

            bool result = await _pasteService.Delete(paste);
            if (!result) return StatusCode(500, new { success = false, message = "An error occurred while deleting the paste." });
            return Ok(new { success = true, message = "Paste deleted successfully." });
        }

        [HttpPost]
        [Route("{id}/view")]
        [Authorize(Policy = "NotBanned")]
        public async Task<IActionResult> RecordPasteView(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found." });

            if (_pasteSettings.View_HMAC_Secret == null)
                return StatusCode(500, new { success = false, message = "View recording is not configured properly." });
            if (!string.IsNullOrWhiteSpace(_pasteSettings.View_Internal_API_Key)
                && _pasteSettings.View_Internal_API_Key != Request.Headers["X-Internal-API-Key"])
                return Unauthorized(new { success = false, message = "Invalid API key." });

            var result = await _pasteService.RecordView(paste, HttpContext);

            if (result.paste is null && !result.alreadyExists)
                return StatusCode(500, new { success = false, message = "An error occurred while recording the paste view." });
            else if (result.alreadyExists)
                return Ok(new { success = true, message = "View already recorded." });

            return Ok(new { success = true, message = "Paste view recorded." });
        }

        [HttpPost]
        [Route("{id}/report")]
        [Authorize(Policy = "AuthAndNotBanned")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> ReportPaste(string id, [FromBody] ReportDto request)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found." });
            var user = HttpContext.GetJwtUser();
            if (user == null)
                return Unauthorized(new { success = false, message = "Invalid token." });

            Enum.TryParse<ReportType>(request.ReportType, true, out var reportType);
            if (!Enum.IsDefined(reportType))
                return BadRequest(new { success = false, message = "Invalid report type." });

            if (!await _verificationService.VerifyAsync(new VerificationContext
            {
                Token = request.VerificationToken,
                Ip = HttpContext.GetRequestIP()
            }))
                return BadRequest(new { success = false, message = "Verification failed." });


            Report report = await _reportService.CreateReport(user.UUID, ReportTargetType.Paste, paste.PID, reportType, request.Description);
            if (report == null)
                return StatusCode(500, new { success = false, message = "An error occurred while reporting the paste." });

            return Ok(new
            {
                success = true,
                message = "Paste reported successfully.",
                report = new ReportResponseDto
                {
                    ReportID = report.ReportID,
                    Type = report.Type,
                    Status = report.Status,
                    Description = report.Description,
                    CreatedAt = report.CreatedAt,
                    UpdatedAt = report.UpdatedAt,
                    ReporterUUID = report.ReporterUUID,
                    TargetType = report.TargetType,
                    UserUUID = report.UserUUID
                }
            });
        }

        [HttpPatch]
        [Route("{id}/report/{reportId}")]
        [Authorize(Policy = "AuthAndNotBanned")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> ModifyPasteReport(string id, int reportId, [FromBody] ReportDto request)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found." });

            var report = await _reportService.GetReportByID(reportId);
            if (report == null || report.TargetType != ReportTargetType.Paste || report.PastePID != paste.PID)
                return NotFound(new { success = false, message = "Report not found." });

            var user = HttpContext.GetJwtUser();
            if (user == null)
                return Unauthorized(new { success = false, message = "Invalid token." });

            var hasPrivilegedRole = user.Roles.Any(r => r == 1 || r == 255);
            if (report.ReporterUUID != user.UUID && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to modify this report." });

            Enum.TryParse<ReportType>(request.ReportType, true, out var reportType);
            if (!Enum.IsDefined(reportType))
                return BadRequest(new { success = false, message = "Invalid report type." });

            report.Type = reportType;
            report.Description = request.Description;

            var updatedReport = await _reportService.UpdateReport(report);
            if (updatedReport == null)
                return StatusCode(500, new { success = false, message = "An error occurred while updating the report." });

            return Ok(new { success = true, message = "Report updated successfully." });
        }

        [HttpDelete]
        [Route("{id}/report/{reportId}")]
        [Authorize(Policy = "AuthAndNotBanned")]
        [EnableRateLimiting("Sensitive")]
        public async Task<IActionResult> DeletePasteReport(string id, int reportId)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found." });

            var report = await _reportService.GetReportByID(reportId);
            if (report == null || report.TargetType != ReportTargetType.Paste || report.PastePID != paste.PID)
                return NotFound(new { success = false, message = "Report not found." });

            var user = HttpContext.GetJwtUser();
            if (user == null)
                return Unauthorized(new { success = false, message = "Invalid token." });

            var hasPrivilegedRole = user.Roles.Any(r => r == 1 || r == 255);
            if (report.ReporterUUID != user.UUID && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to delete this report." });

            if (user.Roles.Contains(255) && !user.TotpEnabled && _authSettings.Admins_Require_2FA)
                return StatusCode(403, new { success = false, message = "2FA is required to perform this action." });

            bool result = await _reportService.DeleteReport(report);
            if (!result)
                return StatusCode(500, new { success = false, message = "An error occurred while deleting the report." });

            return Ok(new { success = true, message = "Report deleted successfully." });
        }

        [HttpGet]
        [Route("recent")]
        public async Task<IActionResult> GetRecentPastes()
        {
            var results = await _pasteService.GetList(0, 50, true);
            return Ok(results.Select(p => new PasteResponseDto
            {
                ID = p.ID,
                UUID = p.UUID,
                Title = p.Title,
                Size = p.Size,
                TrueSize = p.TrueSize,
                IsCompressed = p.IsCompressed,
                Views = p.Views,
                Syntax = p.Syntax,
                Visibility = p.Visibility,
                ExpiresAt = p.ExpiresAt,
                EditedAt = p.EditedAt
            }));
        }

        [HttpGet]
        [EnableRateLimiting("NoLimit")]
        [Route("info")]
        public IActionResult GetCreatePasteOptions()
        {
            return Ok(new PasteOptionsDto
            {
                Syntaxes = _pasteSettings.ValidSyntaxLanguages,
                Visibilities =
                [
                    new() { Value = 0, DisplayName = "Public" },
                    new() { Value = 1, DisplayName = "Unlisted" },
                    new() { Value = 2, DisplayName = "Private" }
                ],
                MaxTitleLength = _pasteSettings.MaxTitleLength,
                MaxPasteSize = _pasteSettings.MaxPasteSizeInBytes,
                RequiresVerification = _pasteSettings.RequiresVerfication
            });
        }
    }
}
