using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SharpbinV2.Server.Services;
using SharpbinV2.Server.Models;
using System.Text;
using IOFile = System.IO.File;
using UAParser;

namespace SharpbinV2.Server.Controllers
{
    [ApiController]
    [Route("api/pastes")]
    public class PasteController : Controller
    {
        private readonly DatabaseService _databaseService;
        private readonly ILogger<PasteController> _logger;

        public PasteController(DatabaseService databaseService, ILogger<PasteController> logger)
        {
            _databaseService = databaseService;
            _logger = logger;
        }

        [HttpPost("create")]
        [EnableRateLimiting("uploads")]
        [Consumes("text/plain")]
        public async Task<IActionResult> CreatePaste(string title, string syntax, int visibility)
        {
            try
            {
                string content = await new StreamReader(HttpContext.Request.Body, Encoding.UTF8).ReadToEndAsync();
                var requestDetails = HelperService.GetRequestDetails(HttpContext);
                var queries = HttpContext.Request.Query;

                if (string.IsNullOrWhiteSpace(content))
                    return BadRequest(new { success = false, message = "Content cannot be empty." });

                if (content.Length > Program.MaxFileSize)
                    return BadRequest(new { success = false, message = $"Content exceeds maximum size of {Program.MaxFileSize} bytes." });

                title = !string.IsNullOrWhiteSpace(title) ? title : $"Untitled {await _databaseService.EnumeratePastes()}";
                syntax = syntax?.ToLower() ?? "none";
                visibility = visibility < 0 || visibility > 2 ? 0 : visibility;

                if (title.Length > 500)
                    return BadRequest(new { success = false, message = "Title cannot exceed 500 characters." });
                if (visibility < 0 || visibility > 2)
                    return BadRequest(new { success = false, message = "Invalid visibility option. Must be 0 (public), 1 (unlisted), or 2 (private)." });
                if (!Program.ValidSyntaxLanguages.Contains(syntax.ToLower()))
                    return BadRequest(new { success = false, message = "Invalid syntax language specified." });
                if (string.IsNullOrWhiteSpace(title))
                    title = $"Untitled {await _databaseService.EnumeratePastes()}";

                bool shouldCompress = await CompressionService.ShouldCompress(content);
                byte[] compressedContent = shouldCompress
                    ? await CompressionService.CompressString(content)
                    : Encoding.UTF8.GetBytes(content);
                User? user = await _databaseService.UserFromToken(requestDetails.Token ?? "");
                string pasteId = HelperService.GenerateRandomString(8);

                Paste paste = new Paste
                {
                    Created = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    Size = compressedContent.Length,
                    TrueSize = content.Length,
                    UUID = Guid.NewGuid().ToString(),
                    ID = pasteId,
                    AuthorUUID = user?.UUID ?? "0", // 0 means the user is anonymous
                    FilePath = shouldCompress ? $"pastes/{pasteId}.txt.gz" : $"pastes/{pasteId}.txt",
                    Visibility = visibility,
                    Title = title,
                    Edited = 0,
                    Views = 0,
                    Syntax = syntax.ToLower()
                };

                await IOFile.WriteAllBytesAsync(paste.FilePath, compressedContent);
                bool success = await _databaseService.CreatePaste(paste, _logger);

                if (!success)
                    return StatusCode(500, new { success, message = "An error occurred while creating the paste." });

                _logger.LogInformation($"Paste created successfully: {pasteId}");

                return Ok(new
                {
                    success = true,
                    paste = new
                    {
                        paste.ID,
                        paste.UUID,
                        paste.Title,
                        paste.Syntax,
                        paste.Visibility,
                        paste.Created,
                        paste.Size,
                        paste.TrueSize,
                        paste.AuthorUUID
                    },
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating paste");
                return StatusCode(500, new { error = "An error occurred while creating the paste." });
            }
        }

        [HttpGet("{id}")]
        [EnableRateLimiting("general")]
        public async Task<IActionResult> GetPaste(string id)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(id))
                    return BadRequest(new { success = false, message = "Invalid paste ID." });
                Paste? paste = await _databaseService.GetPasteFromID(id);

                if (paste == null || paste.FilePath == null || !IOFile.Exists(paste.FilePath))
                    return NotFound(new { success = false, message = "Paste not found." });

                if (paste.FilePath.EndsWith(".gz"))
                    Response.Headers.Append("Content-Encoding", "gzip");

                Response.Headers.Append("Content-Type", "text/plain; charset=utf-8");
                Response.Headers.Append("Cache-Control", "public, max-age=3600");

                return PhysicalFile(Path.GetFullPath(paste.FilePath), "text/plain");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving paste");
                return StatusCode(500, new { error = "An error occurred while retrieving the paste." });
            }
        }

        [HttpGet("{id}/info")]
        [EnableRateLimiting("general")]
        public async Task<IActionResult> GetPasteInfo(string id)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(id))
                    return BadRequest(new { success = false, message = "Invalid paste ID." });
                Paste? paste = await _databaseService.GetPasteFromID(id);
                if (paste == null || string.IsNullOrWhiteSpace(paste.UUID))
                    return NotFound(new { success = false, message = "Paste not found." });
                User? author = null;
                if (!string.IsNullOrWhiteSpace(paste.AuthorUUID))
                    author = await _databaseService.UserFromUUID(paste.AuthorUUID ?? "");
                return Ok(new
                {
                    success = true,
                    paste = new
                    {
                        paste.ID,
                        paste.UUID,
                        paste.Title,
                        paste.Syntax,
                        paste.Views,
                        paste.Visibility,
                        paste.Created,
                        paste.Size,
                        paste.TrueSize,
                        paste.AuthorUUID,
                        username = author?.Username ?? "Anonymous",
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving paste info");
                return StatusCode(500, new { error = "An error occurred while retrieving the paste info." });
            }
        }

        [HttpGet("{id}/views")]
        [EnableRateLimiting("general")]
        public async Task<IActionResult> GetPasteViews(string id)
        {
            try
            {
                var requestDetails = HelperService.GetRequestDetails(HttpContext);
                if (string.IsNullOrWhiteSpace(requestDetails.Token) || await _databaseService.GetSession(requestDetails.Token) == null)
                    return Unauthorized(new { success = false, message = "Invalid or missing authentication token." });
                if (string.IsNullOrWhiteSpace(id))
                    return BadRequest(new { success = false, message = "Invalid paste ID." });
                Paste? paste = await _databaseService.GetPasteFromID(id);
                User? user = await _databaseService.UserFromToken(requestDetails.Token ?? "");
                if (paste == null)
                    return NotFound(new { success = false, message = "Paste not found." });
                if (paste.AuthorUUID != user?.UUID)
                    return Unauthorized(new { success = false, message = "You do not have permission to view this paste's views." });

                List<View?>? views = await _databaseService.GetViewsFromPaste(paste.UUID ?? "", _logger);

                if (views == null || views.Count == 0)
                    return BadRequest(new { success = false, message = "No views found for this paste." });

                var details = new List<object>();

                foreach (var view in views)
                {
                    if (view == null)
                        continue;
                    var uaParser = Parser.GetDefault();
                    ClientInfo clientInfo = uaParser.Parse(view.UserAgent ?? "");
                    details.Add(new
                    {
                        view.PasteUUID,
                        view.Created,
                        UserAgent = new
                        {
                            Browser = clientInfo.UA.Family,
                            Platform = clientInfo.OS.Family,
                            Device = clientInfo.Device.Family
                        }
                    });
                }

                return Ok(new
                {
                    success = true,
                    pasteID = paste.ID,
                    pasteUUID = paste.UUID,
                    views = details
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving paste views");
                return StatusCode(500, new { error = "An error occurred while retrieving the paste views." });
            }
        }

        [HttpGet("archive")]
        [EnableRateLimiting("general")]
        public async Task<IActionResult> GetPastes(int page, int limit)
        {
            if (page < 1 || limit < 1 || limit > 25)
                return BadRequest(new { success = false, message = "Invalid page or limit parameters." });
            if (page == 1)
                page = 0;

            try
            {
                int pages = await _databaseService.EnumeratePastes() / limit;
                if (page > pages)
                    return BadRequest(new { success = false, message = "Page number exceeds available pages." });

                List<Paste?>? pastes = await _databaseService.GetPastes(limit, page, _logger);

                if (pastes == null || pastes.Count == 0)
                    return NotFound(new { success = false, message = "No pastes found." });

                var pasteList = new List<object>();
                foreach (var paste in pastes)
                {
                    if (paste == null)
                        continue;
                    pasteList.Add(new
                    {
                        paste.ID,
                        paste.UUID,
                        paste.Title,
                        paste.Syntax,
                        paste.Visibility,
                        paste.Created,
                        paste.Size,
                        paste.TrueSize,
                        paste.AuthorUUID
                    });
                }

                return Ok(new
                {
                    success = true,
                    pages,
                    pastes = pasteList
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving pastes archive");
                return StatusCode(500, new { error = "An error occurred while retrieving the pastes archive." });
            }
        }

        [HttpGet("my")]
        [EnableRateLimiting("general")]
        public async Task<IActionResult> GetMyPastes(int page, int limit)
        {
            var requestDetails = HelperService.GetRequestDetails(HttpContext);
            if (string.IsNullOrWhiteSpace(requestDetails.Token) || await _databaseService.GetSession(requestDetails.Token) == null)
                return Unauthorized(new { success = false, message = "Invalid or missing authentication token." });
            User? user = await _databaseService.UserFromToken(requestDetails.Token ?? "");
            if (user == null)
                return Unauthorized(new { success = false, message = "User not found." });
            if (page < 1 || limit < 1 || limit > 25)
                return BadRequest(new { success = false, message = "Invalid page or limit parameters." });
            if (page == 1)
                page = 0;

            try
            {
                int pages = await _databaseService.EnumerateUserPastes(user) / limit;
                if (page > pages)
                    return BadRequest(new { success = false, message = "Page number exceeds available pages." });
                List<Paste?>? pastes = await _databaseService.GetPastesFromUser(user, limit, page, _logger, true);
                if (pastes == null || pastes.Count == 0)
                    return NotFound(new { success = false, message = "No pastes found." });
                var pasteList = new List<object>();
                foreach (var paste in pastes)
                {
                    if (paste == null)
                        continue;
                    pasteList.Add(new
                    {
                        paste.ID,
                        paste.UUID,
                        paste.Title,
                        paste.Syntax,
                        paste.Visibility,
                        paste.Created,
                        paste.Size,
                        paste.TrueSize,
                        paste.AuthorUUID
                    });
                }
                return Ok(new
                {
                    success = true,
                    pages,
                    pastes = pasteList
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user's pastes");
                return StatusCode(500, new { error = "An error occurred while retrieving the user's pastes." });
            }
        }

        [HttpDelete("{id}")]
        [EnableRateLimiting("general")]
        public async Task<IActionResult> DeletePaste(string id)
        {
            var requestDetails = HelperService.GetRequestDetails(HttpContext);
            if (string.IsNullOrWhiteSpace(requestDetails.Token) || await _databaseService.GetSession(requestDetails.Token) == null)
                return Unauthorized(new { success = false, message = "Invalid or missing authentication token." });

            User? user = await _databaseService.UserFromToken(requestDetails.Token ?? "");
            if (user == null || user.UUID == "0")
                return Unauthorized(new { success = false, message = "User not found." });

            if (string.IsNullOrWhiteSpace(id))
                return BadRequest(new { success = false, message = "Invalid paste ID." });
            try
            {
                Paste? paste = await _databaseService.GetPasteFromID(id);
                if (paste == null)
                    return NotFound(new { success = false, message = "Paste not found." });

                if (paste.AuthorUUID != user.UUID && user.Type != 255)
                    return Unauthorized(new { success = false, message = "You do not have permission to delete this paste." });

                bool success = await _databaseService.DeletePaste(paste, _logger);
                if (!success)
                    return StatusCode(500, new { success, message = "An error occurred while deleting the paste." });

                if (IOFile.Exists(paste.FilePath))
                    IOFile.Delete(paste.FilePath);

                _logger.LogInformation($"Paste deleted successfully: {id}");
                return Ok(new { success = true, message = "Paste deleted successfully." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting paste");
                return StatusCode(500, new { error = "An error occurred while deleting the paste." });
            }
        }

        [HttpPost("{id}/change-id")]
        [EnableRateLimiting("general")]
        public async Task<IActionResult> ChangePasteID(string id, string newId)
        {
            var requestDetails = HelperService.GetRequestDetails(HttpContext);

            if (string.IsNullOrWhiteSpace(requestDetails.Token) || await _databaseService.GetSession(requestDetails.Token) == null)
                return Unauthorized(new { success = false, message = "Invalid or missing authentication token." });
            User? user = await _databaseService.UserFromToken(requestDetails.Token ?? "");
            if (user == null || user.UUID == "0")
                return Unauthorized(new { success = false, message = "User not found." });
            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(newId))
                return BadRequest(new { success = false, message = "Invalid paste ID." });
            if (user.Type != 255)
                return Unauthorized(new { success = false, message = "You do not have permission to change paste ID." });

            try
            {
                var paste = await _databaseService.GetPasteFromID(id);
                if (paste == null)
                    return NotFound(new { success = false, message = "Paste not found." });

                var newPaste = await _databaseService.UpdatePasteID(paste, newId, _logger);
                if (newPaste == null)
                    return StatusCode(500, new { success = false, message = "An error occurred while changing the paste ID." });

                if (IOFile.Exists(paste.FilePath) && paste.ID != null)
                {
                    string newFilePath = paste.FilePath.Replace(paste.ID, newId);
                    IOFile.Move(paste.FilePath, newFilePath);
                    paste.FilePath = newFilePath;
                }
                else
                {
                    return StatusCode(500, new { success = false, message = "Paste file not found or invalid." });
                }

                
                return Ok(new
                {
                    success = true,
                    message = "Paste ID changed successfully.",
                    paste = new
                    {
                        newPaste.ID,
                        newPaste.UUID,
                        newPaste.Title,
                        newPaste.Syntax,
                        newPaste.Visibility,
                        newPaste.Created,
                        newPaste.Size,
                        newPaste.TrueSize,
                        newPaste.AuthorUUID
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing paste ID");
                return StatusCode(500, new { error = "An error occurred while changing the paste ID." });
            }
        }
    }
}
