using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.DTOs;
using SharpbinV3.Server.Services;

namespace SharpbinV3.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PasteController(IPasteService pasteService, IUserService userService) : ControllerBase
    {
        private readonly IPasteService _pasteService = pasteService;
        private readonly IUserService _userService = userService;

        [HttpPost]
        [Route("create")]
        public async Task<IActionResult> CreatePaste(string title = "", string syntax = "plaintext", int visibility = 0, long expiresAt = 0)
        {
            if (!await _pasteService.ValidateExpiresAt(expiresAt))
                return BadRequest(new { message = "Invalid expiration time." });
            if (!await _pasteService.ValidateVisibility(visibility))
                return BadRequest(new { message = "Invalid visibility level. Must be between 0 and 2." });
            if (!await _pasteService.ValidateSyntax(syntax))
                return BadRequest(new { message = "Invalid syntax." });
            if (!await _pasteService.ValidateTitle(title))
                return BadRequest(new { message = "Invalid title. Must be less than 500 characters." });

            string content = await new StreamReader(Request.Body).ReadToEndAsync();
            var httpUser = HttpContext.User;
            var userUUID = httpUser?.FindFirst("UUID")?.Value;
            User? user = userUUID is not null ? await _userService.GetByUUID(Guid.Parse(userUUID)) : null;
            Paste paste = await _pasteService.Create(user, content, title, syntax, visibility, expiresAt);
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
            Console.WriteLine(paste.User);
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
                Author = paste.User != null && paste.User.Visiblity == 0 ? new
                {
                    paste.User.UID,
                    paste.User.UUID,
                    paste.User.Username,
                    paste.User.Visiblity
                } : null
            });
        }
        [HttpGet]
        [Route("raw/{id}")]
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
        [Authorize]
        public async Task<IActionResult> EditPaste(string id)
        {
            string content = await new StreamReader(Request.Body).ReadToEndAsync();
            if (content == null || id == null) return NotFound();
            var paste = await _pasteService.Get(id);
            if (paste == null) return NotFound();
            var httpUser = HttpContext.User;
            var userUUID = httpUser?.FindFirst("UUID")?.Value;
            if (userUUID == null || paste.AuthorUUID != Guid.Parse(userUUID))
                return Forbid();
            bool result = await _pasteService.EditText(paste, content);
            if (!result) return NotFound();
            return Ok(new { message = "Paste edited successfully." });
        }

        [HttpPatch]
        [Route("{id}/modify")]
        [Authorize]
        public async Task<IActionResult> ModifyPasteMetadata(string id, [FromBody] PasteMetadataUpdateRequest request)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null) return NotFound();
            var httpUser = HttpContext.User;
            var userUUID = httpUser?.FindFirst("UUID")?.Value;
            if (userUUID == null || paste.AuthorUUID != Guid.Parse(userUUID))
                return Forbid();
            if (request.Title != null)
                paste.Title = request.Title;
            if (request.Syntax != null)
                paste.Syntax = request.Syntax;
            if (request.Visibility.HasValue)
                paste.Visibility = request.Visibility.Value;
            if (request.ExpiresAt.HasValue)
                paste.ExpiresAt = request.ExpiresAt.Value;
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
    }
}
