using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs.Paste;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Services;
using SharpbinV3.Server.Services.Verification;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PasteController(PasteService pasteService, VerificationService verificationService, AuthService authService, IOptions<PasteSettings> options, IOptions<AuthSettings> authSettings) : ControllerBase
    {
        private readonly PasteService _pasteService = pasteService;
        private readonly VerificationService _verificationService = verificationService;
        private readonly AuthService _authService = authService;
        private readonly PasteSettings _pasteSettings = options.Value;
        private readonly AuthSettings _authSettings = authSettings.Value;

        [HttpPost]
        [Route("create")]
        [Authorize(Policy = "NotBanned")]
        public async Task<IActionResult> CreatePaste(string title = "", string syntax = "plaintext", int visibility = 0, long expiresAt = 0, string? token = null)
        {
            if (!await _pasteService.ValidateExpiresAt(expiresAt))
                return BadRequest(new { message = "Invalid expiration time." });
            if (!await _pasteService.ValidateVisibility(visibility))
                return BadRequest(new { message = "Invalid visibility level. Must be between 0 and 2." });
            if (!await _pasteService.ValidateSyntax(syntax))
                return BadRequest(new { message = "Invalid syntax." });
            if (!await _pasteService.ValidateTitle(title))
                return BadRequest(new { message = $"Invalid title. Must be less than {_pasteSettings.MaxTitleLength} characters." });

            string content = await new StreamReader(Request.Body).ReadToEndAsync();
            if (content.Length == 0)
                return BadRequest(new { message = "Paste content cannot be empty." });
            if (System.Text.Encoding.UTF8.GetByteCount(content) > _pasteSettings.MaxPasteSizeInBytes)
                return BadRequest(new { message = $"Paste size exceeds the maximum allowed size of {_pasteSettings.MaxPasteSizeInBytes} bytes." });

            if (_pasteSettings.RequiresVerfication && !await _verificationService.VerifyAsync(new VerificationContext
            {
                Token = token,
                Ip = HttpContext.GetRequestIP()
            }))
                return BadRequest(new { message = "Verification failed." });

            var user = await _authService.GetUserFromHttpContext(HttpContext);
            Paste paste = await _pasteService.Create(user, content, title, syntax, visibility, expiresAt, _pasteSettings.EnablePasteCompression);
            return Ok(new
            {
                paste.ID,
                paste.UUID,
                paste.IsCompressed,
                paste.Size,
                paste.TrueSize,
                paste.ExpiresAt
            });
        }
        [HttpGet]
        [Route("{id}")]
        public async Task<IActionResult> GetPasteByID(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null) return NotFound();
            return Ok(new
            {
                paste.ID,
                paste.UUID,
                paste.Title,
                paste.Size,
                paste.TrueSize,
                paste.IsCompressed,
                paste.Views,
                paste.Syntax,
                paste.Visibility,
                paste.ExpiresAt,
                paste.EditedAt,
                Author = paste.User != null && paste.User.Visibility == 0 ? new
                {
                    paste.User.UID,
                    paste.User.UUID,
                    paste.User.Username,
                    paste.User.DisplayName,
                    paste.User.Visibility
                } : null
            });
        }
        [HttpGet]
        [Route("{id}/raw")]
        public async Task<IActionResult> GetRawPasteByID(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null) return NotFound();
            if (paste.IsCompressed)
            {
                Response.Headers.Append("Content-Encoding", "gzip");
                return File(paste.Content, "application/octet-stream");
            }
            else
            {
                return File(paste.Content, "text/plain; charset=utf-8");
            }
        }

        [HttpPut]
        [Route("{id}/edit")]
        [Authorize(Policy = "AuthAndNotBanned")]
        public async Task<IActionResult> EditPaste(string id)
        {
            string content = await new StreamReader(Request.Body).ReadToEndAsync();
            if (content == null || id == null) return StatusCode(400, new { success = false, message = "Invalid request." });
            var paste = await _pasteService.Get(id);
            if (paste == null) return StatusCode(404, new { success = false, message = "Paste not found." });

            var user = HttpContext.GetJwtUser();
            if (user == null) return StatusCode(403, new { success = false, message = "You do not have permission to edit this paste." });

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
        [Route("{id}/modify")]
        [Authorize(Policy = "AuthAndNotBanned")]
        public async Task<IActionResult> ModifyPasteMetadata(string id, [FromBody] UpdatePasteDto request)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null) return NotFound();

            var user = HttpContext.GetJwtUser();
            if (user == null) return Forbid();

            var hasPrivilegedRole = user.Roles.Any(r => r == 1 || r == 255);

            if (paste.AuthorUUID != user.UUID && !hasPrivilegedRole)
                return Forbid();
            if (user.Roles.Contains(255) && !user.TotpEnabled && _authSettings.Admins_Require_2FA)
                return Forbid();
            if (request.Title != null)
                paste.Title = request.Title;
            if (request.Syntax != null)
                paste.Syntax = request.Syntax;
            if (request.Visibility.HasValue)
                paste.Visibility = request.Visibility.Value;
            if (request.ExpiresAt.HasValue)
                paste.ExpiresAt = request.ExpiresAt.Value;

            if (!await _pasteService.ValidateExpiresAt(paste.ExpiresAt))
                return BadRequest(new { message = "Invalid expiration time." });
            if (!await _pasteService.ValidateVisibility(paste.Visibility))
                return BadRequest(new { message = "Invalid visibility level. Must be between 0 and 2." });
            if (!await _pasteService.ValidateSyntax(paste.Syntax ?? "plaintext"))
                return BadRequest(new { message = "Invalid syntax." });
            if (!await _pasteService.ValidateTitle(paste.Title ?? ""))
                return BadRequest(new { message = $"Invalid title. Must be less than {_pasteSettings.MaxTitleLength} characters." });

            var newPaste = await _pasteService.Edit(paste);
            return Ok(new
            {
                message = "Paste metadata updated successfully.",
                paste = new
                {
                    newPaste.ID,
                    newPaste.UUID,
                    newPaste.Title,
                    newPaste.Size,
                    newPaste.TrueSize,
                    newPaste.IsCompressed,
                    newPaste.Views,
                    newPaste.Syntax,
                    newPaste.Visibility,
                    newPaste.ExpiresAt
                }
            });
        }
        [HttpDelete]
        [Route("{id}/delete")]
        [Authorize(Policy = "AuthAndNotBanned")]
        public async Task<IActionResult> DeletePaste(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null) return NotFound();

            var user = HttpContext.GetJwtUser();
            if (user == null) return Forbid();

            var hasPrivilegedRole = user.Roles.Any(r => r == 1 || r == 255);
            if (paste.AuthorUUID != user.UUID && !hasPrivilegedRole)
                return Forbid();
            if (user.Roles.Contains(255) && !user.TotpEnabled && _authSettings.Admins_Require_2FA)
                return Forbid();

            bool result = await _pasteService.Delete(paste);
            if (!result) return NotFound();
            return Ok(new { message = "Paste deleted successfully." });
        }

        [HttpGet]
        [Route("recent")]
        public async Task<IActionResult> GetRecentPastes()
        {
            var results = await _pasteService.GetList(0, 50, true);
            return Ok(results.Select(p => new
            {
                p.ID,
                p.UUID,
                p.Title,
                p.Size,
                p.TrueSize,
                p.IsCompressed,
                p.Views,
                p.Syntax,
                p.Visibility,
                p.ExpiresAt,
                p.EditedAt
            }));
        }

        [HttpGet]
        [Route("info")]
        public IActionResult GetCreatePasteOptions()
        {
            var options = new
            {
                syntaxes = _pasteSettings.ValidSyntaxLanguages,
                visibilities = new[]
                {
                    new { value = 0, displayName = "Public" },
                    new { value = 1, displayName = "Unlisted" },
                    new { value = 2, displayName = "Private" }
                },
                maxTitleLength = _pasteSettings.MaxTitleLength,
                maxPasteSize = _pasteSettings.MaxPasteSizeInBytes,
                requiresVerification = _pasteSettings.RequiresVerfication
            };
            return Ok(options);
        }
    }
}
