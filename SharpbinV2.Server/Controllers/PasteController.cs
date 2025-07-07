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
        public async Task<IActionResult> CreatePaste()
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

                string title = queries.ContainsKey("title") ? queries["title"].ToString() : $"Untitled {await _databaseService.EnumeratePastes()}";
                string syntax = queries.ContainsKey("syntax") ? queries["syntax"].ToString() : "none";
                int visibility = queries.ContainsKey("visibility") ? int.Parse(queries["visibility"]) : 0;

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
    }
}
