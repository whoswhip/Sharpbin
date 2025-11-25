using Microsoft.AspNetCore.Mvc;
using SharpbinV3.Data.Entities;
using SharpbinV3.DTOs;
using SharpbinV3.Services;

namespace SharpbinV3.Controllers
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
    }
}
